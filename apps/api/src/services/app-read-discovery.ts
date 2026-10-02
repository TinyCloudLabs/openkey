import { randomUUID } from 'node:crypto';
import { TCWSessionManager, prepareSession, completeSessionSetup, invoke, ensureEip55 } from '@tinycloud/node-sdk-wasm';
import { activateSessionWithHost } from '@tinycloud/sdk-core';
import { decodeApplicationRecord } from './app-read-records';
import { APP_READ_PROTOCOL_VERSION, appReadSelection, canonicalJson, canonicalPermissions, ownerSpace, policyError, publicClientKey, registryReadPermissions, sha256, type AppReadPermission } from './app-read-policy';

interface ManagedKey { id: string; userId: string | null; address: string; keyType: string; sealedBlob?: string | null }
interface DiscoveryRequest { discoveryProtocolVersion?: unknown; userId: string; keyId: string; host: string; jwk: unknown; reason?: unknown }
interface SelectionRequest extends DiscoveryRequest { discoveryToken?: unknown; appId?: unknown; selectionDigest?: unknown; permissions?: unknown }
interface RegistryResult { records: Array<{ key: string; value: unknown }>; truncated: boolean }
type Issue = { key: string; code: string; category: string; field: string };
const TTL = 10 * 60 * 1000;
const HOSTS = new Set(['https://node.tinycloud.xyz', 'https://tee.node.tinycloud.xyz']);

/** Same trust boundary as managed-key bootstrap, without running bootstrap. */
export function discoveryHost(value: string, production = process.env.NODE_ENV === 'production') {
  let url: URL;
  try { url = new URL(value); } catch { throw policyError('app_read_untrusted_host'); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || value.replace(/\/$/, '') !== url.origin) throw policyError('app_read_untrusted_host');
  if (HOSTS.has(url.origin)) return url.origin;
  if (!production && ['http:', 'https:'].includes(url.protocol) && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) return url.origin;
  throw policyError('app_read_untrusted_host');
}

async function boundedText(response: Response, limit: number) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (bytes > limit) throw policyError('app_read_registry_too_large');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks).toString('utf8');
}

/** One ephemeral account-read session stays inside the API. It never reaches
 * the agent and is never expanded into host, schema, registry-write or app access. */
export async function readManagedRegistry(key: ManagedKey, host: string, signMessage: (key: ManagedKey, message: string) => Promise<string>, {
  send = fetch, activate = activateSessionWithHost,
}: { send?: typeof fetch; activate?: typeof activateSessionWithHost } = {}): Promise<RegistryResult> {
  const ownerDid = `did:pkh:eip155:1:${ensureEip55(key.address)}`;
  const manager = new TCWSessionManager();
  const sessionKey = manager.createSessionKey(`app-read-discovery:${randomUUID()}`);
  const keyText = manager.jwk(sessionKey);
  if (!keyText) throw policyError('app_read_session_failed');
  const jwk = JSON.parse(keyText);
  const prepared = prepareSession({ address: ensureEip55(key.address), chainId: 1, domain: 'openkey.so', jwk,
    issuedAt: new Date().toISOString(), expirationTime: new Date(Date.now() + 5 * 60 * 1000).toISOString(), spaceId: ownerSpace(ownerDid, 'account'),
    abilities: { capabilities: { '': ['tinycloud.capabilities/read'] }, kv: { 'applications/': ['tinycloud.kv/get', 'tinycloud.kv/list'] } } });
  const signature = await signMessage(key, prepared.siwe);
  const session = completeSessionSetup({ ...prepared, jwk, signature });
  const activated = await activate(host, session.delegationHeader);
  if (!activated.success || activated.skipped?.includes(session.spaceId)) throw policyError('app_read_account_unavailable');
  async function read(path: string, action: string, limit: number, extra: Record<string, string> = {}) {
    const authorization = invoke(session, 'kv', path, action, undefined) as Record<string, string>;
    const response = await send(`${host}/invoke`, { method: 'POST', headers: { ...authorization, ...extra }, redirect: 'error', signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw policyError(response.status === 403 || response.status === 401 ? 'app_read_registry_denied' : 'app_read_registry_unavailable');
    return { response, text: await boundedText(response, limit) };
  }
  const listed = await read('applications/', 'tinycloud.kv/list', 128 * 1024, { 'x-tinycloud-limit': '1000' });
  let keys: unknown;
  try { keys = JSON.parse(listed.text); } catch { throw policyError('app_read_registry_invalid'); }
  if (!Array.isArray(keys) || keys.length > 1000 || keys.some(key => typeof key !== 'string' || !/^applications\/[^/*\u0000]+$/.test(key))) throw policyError('app_read_registry_invalid');
  const records: RegistryResult['records'] = [];
  let total = 0;
  for (const key of [...new Set(keys as string[])].sort()) {
    const loaded = await read(key, 'tinycloud.kv/get', 128 * 1024);
    total += Buffer.byteLength(loaded.text);
    if (total > 4 * 1024 * 1024) throw policyError('app_read_registry_too_large');
    records.push({ key, value: loaded.text });
  }
  return { records, truncated: listed.response.headers.get('x-tinycloud-truncated') === 'true' || Boolean(listed.response.headers.get('x-tinycloud-next-cursor')) };
}

export function createAppReadDiscovery({ getKey, signMessage, readRegistry = readManagedRegistry, now = Date.now }: {
  getKey(userId: string, keyId: string): Promise<ManagedKey | null>;
  signMessage(key: ManagedKey, message: string): Promise<string>;
  readRegistry?: typeof readManagedRegistry;
  now?: () => number;
}) {
  // Like prepared signing contexts, snapshots are process-local and short-lived.
  // Another worker or a restart must fail closed and require discovery again;
  // never rebuild authority from caller-supplied permissions or a stale token.
  const pending = new Map<string, { expires: number; userId: string; keyId: string; ownerDid: string; host: string; clientKeyDigest: string; applications: ReturnType<typeof appReadSelection>[] }>();
  return {
    async discover(input: DiscoveryRequest) {
      if (input.discoveryProtocolVersion !== APP_READ_PROTOCOL_VERSION) throw policyError('app_read_protocol_incompatible');
      const host = discoveryHost(input.host);
      const jwk = publicClientKey(input.jwk);
      if (typeof input.userId !== 'string' || !input.userId || typeof input.keyId !== 'string' || !input.keyId) throw policyError('app_read_invalid_request');
      const key = await getKey(input.userId, input.keyId);
      if (!key || key.userId !== input.userId || key.id !== input.keyId) throw policyError('app_read_key_not_found');
      if (key.keyType !== 'MANAGED' || !key.sealedBlob) throw policyError('app_read_managed_key_required');
      const ownerDid = `did:pkh:eip155:1:${ensureEip55(key.address)}`;
      const registry = await readRegistry(key, host, signMessage);
      const applications = [];
      const issues: Issue[] = [];
      if (registry.truncated) issues.push({ key: 'applications/', code: 'APPLICATION_REGISTRY_INCOMPLETE', category: 'truncated', field: '$' });
      for (const record of registry.records) {
        const decoded = decodeApplicationRecord(record.key, record.value);
        if (!decoded.ok) {
          issues.push({ key: record.key, code: decoded.error.code, category: String(decoded.error.meta?.category), field: String(decoded.error.meta?.field) });
          continue;
        }
        try {
          const selected = appReadSelection(decoded.data, { ownerDid, host, jwk });
          applications.push({ ...decoded.data, ...selected });
        } catch {
          issues.push({ key: record.key, code: 'APP_READ_SCOPE_UNSUPPORTED', category: 'unsupported_scope', field: 'manifests' });
        }
      }
      for (const [token, value] of pending) if (value.expires <= now()) pending.delete(token);
      if (pending.size >= 1000) throw policyError('app_read_discovery_busy');
      const discoveryToken = randomUUID();
      const expires = now() + TTL;
      const clientKeyDigest = sha256(jwk);
      pending.set(discoveryToken, { expires, userId: input.userId, keyId: key.id, ownerDid, host, clientKeyDigest, applications });
      return { schemaVersion: 1, protocolVersion: APP_READ_PROTOCOL_VERSION, discoveryToken, ownerDid, host, clientKeyDigest, expiresAt: new Date(expires).toISOString(), registryPermissions: registryReadPermissions(ownerDid), applications, issues, complete: issues.length === 0 };
    },
    select(input: SelectionRequest) {
      if (input.discoveryProtocolVersion !== APP_READ_PROTOCOL_VERSION) throw policyError('app_read_protocol_incompatible');
      if (typeof input.discoveryToken !== 'string') throw policyError('app_read_discovery_required');
      const bound = pending.get(input.discoveryToken);
      if (!bound || bound.expires <= now()) { pending.delete(input.discoveryToken); throw policyError('app_read_discovery_expired'); }
      if (input.userId !== bound.userId || input.keyId !== bound.keyId || discoveryHost(input.host) !== bound.host || sha256(publicClientKey(input.jwk)) !== bound.clientKeyDigest) throw policyError('app_read_context_changed');
      const selected = bound.applications.find(app => app.appId === input.appId && app.selectionDigest === input.selectionDigest);
      if (!selected) throw policyError('app_read_selection_changed');
      if (input.permissions !== undefined && (!Array.isArray(input.permissions) || canonicalJson(canonicalPermissions(input.permissions as AppReadPermission[])) !== canonicalJson(selected.permissions))) throw policyError('app_read_scope_changed');
      return { permissions: structuredClone(selected.permissions), appReadSelection: { schemaVersion: 1, protocolVersion: APP_READ_PROTOCOL_VERSION, appId: selected.appId, manifestHash: selected.manifestHash, selectionDigest: selected.selectionDigest, ownerDid: bound.ownerDid, host: bound.host, clientKeyDigest: bound.clientKeyDigest, permissions: structuredClone(selected.permissions) } };
    },
  };
}
