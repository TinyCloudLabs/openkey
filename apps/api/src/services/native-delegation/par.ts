import { createHash, randomBytes } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';
import { sessionDidForPublicJwk } from '../device-authorization';
import { enabledNativeDelegation, sqlIsolatedHosts, type NativeDelegationConfig } from './policy';
import { TINYCLOUD_DELEGATION_SCOPE } from '../../oauth-config';
import { TINYCLOUD_DELEGATED_PATH, TINYCLOUD_DELEGATED_PATH_MAX_LENGTH, hasDotSegment } from '../tinycloud-path-policy';

export const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:';
const FORM_KEYS = new Set(['client_id', 'response_type', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'scope', 'authorization_details']);
const DETAIL_KEYS = new Set(['type', 'session_key', 'permissions', 'ttl_seconds', 'siwe_nonce']);
const JWK_KEYS = new Set(['kty', 'crv', 'x', 'kid']);
const PERMISSION_KEYS = new Set(['service', 'space', 'path', 'actions']);
const OPTIONAL_SCOPES = new Set(['openid', 'email', 'keys']);
export type NativePermission = { service: string; space: 'applications'; path: string; actions: string[] };
export class ParError extends Error {
  constructor(readonly status: 400 | 401, readonly code: string, message: string) { super(message); }
}
function invalid(code: string, message: string): never { throw new ParError(400, code, message); }
function record(value: unknown, keys: Set<string>): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !keys.has(k))) invalid('invalid_authorization_details', 'unexpected authorization detail member');
  return value as Record<string, unknown>;
}
export function validatePermissions(value: unknown, ceiling: NativeDelegationConfig): NativePermission[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) invalid('invalid_authorization_details', 'permissions must be a non-empty array');
  const entries = (value as unknown[]).map((item) => {
    const p = record(item, PERMISSION_KEYS);
    if (p.space !== 'applications' || typeof p.path !== 'string' || typeof p.service !== 'string' || !Array.isArray(p.actions) || !p.actions.length || p.actions.some(a => typeof a !== 'string') || new Set(p.actions).size !== p.actions.length) invalid('invalid_authorization_details', 'invalid permission');
    const actions = p.actions as string[];
    const path = p.path as string;
    if (p.service === 'tinycloud.capabilities') {
      if (p.path !== '' || actions.length !== 1 || actions[0] !== 'tinycloud.capabilities/read') invalid('invalid_authorization_details', 'invalid capabilities permission');
    } else if (p.service === 'tinycloud.kv') {
      if (path.length > TINYCLOUD_DELEGATED_PATH_MAX_LENGTH || !TINYCLOUD_DELEGATED_PATH.test(path) || hasDotSegment(path) ||
        !ceiling.kv.paths.some(allowed => allowed.endsWith('/') ? path.startsWith(allowed) : path === allowed) ||
        actions.some(a => !a.startsWith('tinycloud.kv/') || !ceiling.kv.actions.includes(a.slice(13)))) invalid('invalid_authorization_details', 'KV permission exceeds ceiling');
    } else if (p.service === 'tinycloud.sql') {
      if (!ceiling.sql || !ceiling.sql.databases.includes(path) || actions.some(a => !a.startsWith('tinycloud.sql/') || !ceiling.sql!.actions.includes(a.slice(14)))) invalid('invalid_authorization_details', 'SQL permission exceeds ceiling');
    } else invalid('invalid_authorization_details', 'unsupported service');
    return { service: p.service as string, space: 'applications' as const, path, actions };
  });
  if (!entries.some(p => p.service === 'tinycloud.capabilities')) invalid('invalid_authorization_details', 'capabilities/read is required');
  for (let i = 0; i < entries.length; i++) for (let j = i + 1; j < entries.length; j++) {
    const a = entries[i]!, b = entries[j]!;
    if (a.service === b.service && (a.path === b.path || (a.path.endsWith('/') && b.path.startsWith(a.path)) || (b.path.endsWith('/') && a.path.startsWith(b.path)))) invalid('invalid_authorization_details', 'overlapping permissions');
  }
  return entries;
}
export function authoritativeQuery(row: { clientId: string; redirectUri: string; state: string; scopes: string[]; codeChallenge: string; id: string }): URLSearchParams {
  return new URLSearchParams([
    ['client_id', row.clientId], ['response_type', 'code'], ['redirect_uri', row.redirectUri], ['state', row.state],
    ['scope', row.scopes.join(' ')], ['code_challenge', row.codeChallenge], ['code_challenge_method', 'S256'],
    ['prompt', 'consent'], ['tinycloud_request', row.id],
  ]);
}
export function matchesAuthoritativeQuery(incoming: URLSearchParams, expected: URLSearchParams): boolean {
  const envelope = new Set(['exp', 'ba_iat', 'ba_pl', 'sig']);
  const keys = [...incoming.keys()];
  if (new Set(keys).size !== keys.length) return false;
  if (keys.some(k => !expected.has(k) && !envelope.has(k))) return false;
  for (const [k, v] of expected) if (incoming.getAll(k).length !== 1 || incoming.get(k) !== v) return false;
  return true;
}
export async function handlePar(request: Request, db: PrismaClient): Promise<Response> {
  const fail = (error: ParError) => Response.json({ error: error.code, error_description: error.message }, { status: error.status, headers: { 'Cache-Control': 'no-store' } });
  try {
    if ((request.headers.get('content-type') ?? '').split(';')[0]?.toLowerCase() !== 'application/x-www-form-urlencoded') invalid('invalid_request', 'form encoding required');
    const params = new URLSearchParams(await request.text());
    const keys = [...params.keys()];
    if (keys.length !== FORM_KEYS.size || new Set(keys).size !== keys.length || keys.some(k => !FORM_KEYS.has(k))) invalid('invalid_request', 'missing, duplicate, or unexpected field');
    const clientId = params.get('client_id')!;
    const client = await db.oauthClient.findUnique({ where: { clientId } });
    if (!client || client.disabled) throw new ParError(401, 'invalid_client', 'unknown or disabled client');
    const ceiling = enabledNativeDelegation(client);
    if (!ceiling) {
      const raw = client.tinycloudNativeDelegation as { tinycloudHost?: unknown; sql?: unknown } | null;
      let details: unknown;
      try { details = JSON.parse(params.get('authorization_details')!); } catch { /* invalid below */ }
      const asksSql = Array.isArray(details) && details.some(detail =>
        detail && typeof detail === 'object' && Array.isArray(detail.permissions) &&
        detail.permissions.some((permission: unknown) => permission && typeof permission === 'object' && (permission as { service?: unknown }).service === 'tinycloud.sql'));
      if (raw?.sql && typeof raw.tinycloudHost === 'string' && !sqlIsolatedHosts().has(raw.tinycloudHost) && asksSql) {
        invalid('invalid_authorization_details', 'SQL requires an isolated TinyCloud host');
      }
      invalid('unauthorized_client', 'native delegation is not enabled');
    }
    const challenge = params.get('code_challenge')!;
    const state = params.get('state')!;
    if (params.get('response_type') !== 'code' || !client.redirectUris.includes(params.get('redirect_uri')!) ||
      state.length < 16 || state.length > 512 || !/^[A-Za-z0-9_-]{43}$/.test(challenge) ||
      Buffer.from(challenge, 'base64url').length !== 32 || Buffer.from(challenge, 'base64url').toString('base64url') !== challenge ||
      params.get('code_challenge_method') !== 'S256') invalid('invalid_request', 'invalid authorization parameters');
    const scopes = params.get('scope')!.split(' ');
    if (scopes.includes('') || new Set(scopes).size !== scopes.length || !scopes.includes(TINYCLOUD_DELEGATION_SCOPE) || !scopes.includes('offline_access') || scopes.some(s => !client.scopes.includes(s) || (s !== TINYCLOUD_DELEGATION_SCOPE && s !== 'offline_access' && !OPTIONAL_SCOPES.has(s)))) invalid('invalid_scope', 'invalid native delegation scopes');
    let parsed: unknown;
    try { parsed = JSON.parse(params.get('authorization_details')!); } catch { invalid('invalid_authorization_details', 'invalid JSON'); }
    if (!Array.isArray(parsed) || parsed.length !== 1) invalid('invalid_authorization_details', 'one detail is required');
    const detail = record((parsed as unknown[])[0], DETAIL_KEYS);
    if (detail.type !== 'tinycloud_delegation') invalid('invalid_authorization_details', 'unsupported detail type');
    const jwk = record(detail.session_key, JWK_KEYS);
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || (jwk.kid !== undefined && (typeof jwk.kid !== 'string' || !jwk.kid))) invalid('invalid_authorization_details', 'invalid Ed25519 JWK');
    let did: string;
    try { did = sessionDidForPublicJwk(jwk); } catch { invalid('invalid_authorization_details', 'invalid Ed25519 JWK'); }
    const permissions = validatePermissions(detail.permissions, ceiling);
    const ttl = detail.ttl_seconds === undefined ? ceiling.maxDelegationTtlSeconds : detail.ttl_seconds;
    if (!Number.isInteger(ttl) || (ttl as number) < 300 || (ttl as number) > ceiling.maxDelegationTtlSeconds) invalid('invalid_authorization_details', 'invalid ttl_seconds');
    if (detail.siwe_nonce !== undefined && (typeof detail.siwe_nonce !== 'string' || !/^[A-Za-z0-9]{8,64}$/.test(detail.siwe_nonce))) invalid('invalid_authorization_details', 'invalid siwe_nonce');
    const id = randomBytes(24).toString('base64url');
    const now = Date.now();
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
    await db.tinyCloudNativeRequest.create({ data: {
      id, clientId, redirectUri: params.get('redirect_uri')!, state: params.get('state')!, codeChallenge: params.get('code_challenge')!, scopes,
      sessionDid: did, sessionJwk: JSON.parse(JSON.stringify(jwk)), sessionJkt: jkt, requestedPermissions: permissions, ttlSeconds: ttl as number,
      siweNonce: detail.siwe_nonce as string | undefined, requestUriExpiresAt: new Date(now + 90_000), expiresAt: new Date(now + 600_000),
    } });
    return Response.json({ request_uri: REQUEST_URI_PREFIX + id, expires_in: 90 }, { status: 201, headers: { 'Cache-Control': 'no-store' } });
  } catch (error) { if (error instanceof ParError) return fail(error); throw error; }
}
export async function resolveRequestUri(db: PrismaClient, requestUri: string, clientId: string): Promise<Record<string, string> | null> {
  if (!requestUri.startsWith(REQUEST_URI_PREFIX)) return null;
  const id = requestUri.slice(REQUEST_URI_PREFIX.length);
  const row = await db.tinyCloudNativeRequest.findUnique({ where: { id } });
  if (!row || row.clientId !== clientId || row.status !== 'PENDING' || row.requestUriExpiresAt <= new Date() || row.expiresAt <= new Date()) return null;
  const updated = await db.tinyCloudNativeRequest.updateMany({ where: { id, status: 'PENDING', requestUriExpiresAt: { gt: new Date() } }, data: { status: 'RESOLVED' } });
  return updated.count === 1 ? Object.fromEntries(authoritativeQuery(row)) : null;
}
