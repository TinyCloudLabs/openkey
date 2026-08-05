import { createHash } from 'node:crypto';
import { parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { SiweMessage } from 'siwe';
import { getAddress } from 'viem';

export const COORDINATIONOS_POLICY_VERSION = 'coordinationos-kv-v1';
export const COORDINATIONOS_CONTRACT_VERSION = 'coordinationos-openkey-v1';
export const COORDINATIONOS_CHAIN_ID = 1;
export const COORDINATIONOS_SESSION_TTL_SECONDS = 3_600;

const REQUIRED_ACTIONS = ['tinycloud.kv/get', 'tinycloud.kv/put'] as const;
const REQUIRED_CLIENT_SCOPES = ['openid', 'email', 'keys', 'tinycloud:session'] as const;
const TRANSITION_CLIENT_SCOPES = [
  ...REQUIRED_CLIENT_SCOPES,
  'tinycloud:manage-key',
] as const;
const utf8 = new TextEncoder();

export type CoordinationosPolicyCode =
  | 'wrong_client'
  | 'client_disabled'
  | 'client_misconfigured'
  | 'missing_scope'
  | 'user_not_found'
  | 'email_not_verified'
  | 'key_not_found'
  | 'wrong_user'
  | 'wrong_key_purpose'
  | 'external_key_denied'
  | 'key_archived'
  | 'key_address_mismatch'
  | 'key_unavailable'
  | 'missing_origin'
  | 'wrong_origin'
  | 'siwe_domain_mismatch'
  | 'wrong_chain'
  | 'chain_mismatch'
  | 'wrong_type'
  | 'wrong_purpose'
  | 'invalid_siwe'
  | 'siwe_uri_mismatch'
  | 'wrong_capability'
  | 'capability_escalation'
  | 'invalid_nonce'
  | 'nonce_replayed'
  | 'issued_at_invalid'
  | 'session_expired'
  | 'session_ttl_exceeded'
  | 'token_consumed';

export interface CoordinationosPolicyEvidence {
  oauthAccessTokenId: string | null;
  tokenDigest: string | null;
  clientId: string | null;
  userId: string | null;
  keyId: string | null;
  origin: string | null;
  chainId: number | null;
  purpose: string | null;
  type: string | null;
  siweDigest: string | null;
  capabilityDigest: string | null;
  nonceDigest: string | null;
  issuedAt: string | null;
  expirationTime: string | null;
  sessionTtlSeconds: number | null;
}

export interface CoordinationosSessionPolicyInput {
  now?: Date;
  principal: {
    userId: string;
    clientId: string;
    oauthAccessTokenId: string;
    tokenDigest: string;
  };
  client: {
    clientId: string;
    disabled: boolean;
    mode: string;
    type: string | null;
    public: boolean;
    tokenEndpointAuthMethod: string | null;
    grantTypes: string[];
    responseTypes: string[];
    scopes: string[];
    tinycloudSessionPolicy: string | null;
    tinycloudSessionOrigin: string | null;
  } | null;
  user: { id: string; emailVerified: boolean } | null;
  key: {
    id: string;
    userId: string | null;
    address: string;
    keyType: string;
    keyPurpose: string;
    archivedAt: Date | null;
    sealedBlob: string | null;
  } | null;
  request: {
    address: unknown;
    chainId: unknown;
    message: unknown;
    type: unknown;
    purpose: unknown;
    keyId: unknown;
    origin?: string | null;
  };
  tokenConsumed?: boolean;
  nonceReplayed?: boolean;
}

type CanonicalRecapEntry = {
  service: 'tinycloud.kv';
  space: string;
  path: string;
  actions: string[];
};

export type CoordinationosSessionPolicyResult =
  | {
      allowed: true;
      evidence: CoordinationosPolicyEvidence;
      canonicalCapabilities: CanonicalRecapEntry[];
      parsed: SiweMessage;
    }
  | {
      allowed: false;
      code: CoordinationosPolicyCode;
      evidence: CoordinationosPolicyEvidence;
    };

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function coordinationosUserNamespace(keyId: string): string {
  return createHash('sha256')
    .update(`${COORDINATIONOS_CONTRACT_VERSION}:${keyId}`, 'utf8')
    .digest('base64url')
    .slice(0, 22);
}

export function coordinationosCanaryPath(keyId: string): string {
  return `coordinationos/integration/v1/${coordinationosUserNamespace(keyId)}/canary`;
}

export function coordinationosInviteCodePath(keyId: string): string {
  return `coordinationos/integration/v1/${coordinationosUserNamespace(keyId)}/invite-code`;
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(utf8.encode(left)), Buffer.from(utf8.encode(right)));
}

export function canonicalizeCoordinationosCapabilities(value: unknown): CanonicalRecapEntry[] {
  if (!Array.isArray(value)) throw new Error('ReCap entries must be an array');
  const entries = value.map((raw) => {
    if (!raw || typeof raw !== 'object') throw new Error('ReCap entry must be an object');
    const candidate = raw as Record<string, unknown>;
    const { service, space, path, actions, caveats } = candidate;
    if ((service !== 'kv' && service !== 'tinycloud.kv')
      || typeof space !== 'string'
      || typeof path !== 'string'
      || !Array.isArray(actions)
      || !actions.every((action): action is string => typeof action === 'string')) {
      throw new Error('ReCap entry has an invalid shape');
    }
    if (caveats !== undefined && (!Array.isArray(caveats) || caveats.length > 0)) {
      throw new Error('ReCap caveats are not allowed');
    }
    if (new Set(actions).size !== actions.length) {
      throw new Error('Duplicate ReCap actions are not allowed');
    }
    return {
      service: 'tinycloud.kv' as const,
      space,
      path,
      actions: [...actions].sort(compareUtf8),
    };
  });
  return entries.sort((left, right) => {
    const leftParts = [left.space, left.service, left.path, JSON.stringify(left.actions)];
    const rightParts = [right.space, right.service, right.path, JSON.stringify(right.actions)];
    for (let index = 0; index < leftParts.length; index += 1) {
      const compared = compareUtf8(leftParts[index]!, rightParts[index]!);
      if (compared !== 0) return compared;
    }
    return 0;
  });
}

export function canonicalCapabilityJson(entries: CanonicalRecapEntry[]): string {
  return JSON.stringify(entries.map((entry) => ({
    service: entry.service,
    space: entry.space,
    path: entry.path,
    actions: entry.actions,
  })));
}

export function canonicalCapabilityDigest(entries: CanonicalRecapEntry[]): string {
  return sha256Hex(canonicalCapabilityJson(entries));
}

export function canonicalizeCoordinationosOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0
    || value.trim() !== value || /[\u0000-\u0020\u007f]/.test(value)
    || value.includes('?') || value.includes('#')) return null;
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(value)?.[1];
  if (authority?.includes('@')) return null;
  try {
    const url = new URL(value);
    if ((url.protocol !== 'http:' && url.protocol !== 'https:')
      || url.username || url.password || url.search || url.hash
      || url.pathname !== '/') return null;
    const defaultPort = (url.protocol === 'http:' && url.port === '80')
      || (url.protocol === 'https:' && url.port === '443');
    const port = url.port && !defaultPort ? `:${url.port}` : '';
    const hostname = url.hostname.toLowerCase();
    if (hostname.includes('*')) return null;
    return `${url.protocol.toLowerCase()}//${hostname}${port}`;
  } catch {
    return null;
  }
}

export function validateCoordinationosClientOrigin(value: unknown): string | null {
  const origin = canonicalizeCoordinationosOrigin(value);
  if (!origin) return null;
  const url = new URL(origin);
  const loopback = url.hostname === 'localhost'
    || url.hostname.endsWith('.localhost')
    || url.hostname === '[::1]'
    || /^127(?:\.\d{1,3}){3}$/.test(url.hostname);
  return url.protocol === 'https:' || (url.protocol === 'http:' && loopback)
    ? origin
    : null;
}

function sameStringSet(actual: string[], expected: readonly string[]): boolean {
  return actual.length === expected.length
    && new Set(actual).size === actual.length
    && expected.every((item) => actual.includes(item));
}

function validVerificationMethodUri(uri: string): boolean {
  const match = /^did:key:([^#]+)#([^#]+)$/.exec(uri);
  if (!match || match[1] !== match[2]) return false;
  // did:key method identifiers are multibase values. TinyCloud session keys use
  // base58btc (the `z` prefix), whose alphabet deliberately excludes
  // ambiguous characters such as 0/O/I/l.
  return /^z[1-9A-HJ-NP-Za-km-z]+$/.test(match[1]!);
}

function checksum(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  try {
    return getAddress(value);
  } catch {
    return null;
  }
}

function recapHasNonemptyCaveats(resources: string[] | undefined): boolean {
  for (const resource of resources ?? []) {
    if (!resource.startsWith('urn:recap:')) continue;
    try {
      const recap = JSON.parse(
        Buffer.from(resource.slice('urn:recap:'.length), 'base64url').toString('utf8'),
      ) as { att?: unknown };
      if (!recap.att || typeof recap.att !== 'object') continue;
      for (const abilities of Object.values(recap.att as Record<string, unknown>)) {
        if (!abilities || typeof abilities !== 'object') continue;
        for (const caveats of Object.values(abilities as Record<string, unknown>)) {
          if (!Array.isArray(caveats)) continue;
          // ReCap encodes an uncaveated ability with the required `[{}]`
          // NotaBene sentinel. Accept only that exact encoding; a nested
          // `caveats: [{}]`, multiple sentinels, or any populated object is
          // additional authority and must fail closed.
          if (caveats.length !== 1) return true;
          const [caveat] = caveats;
          if (!caveat || typeof caveat !== 'object'
            || Object.keys(caveat as Record<string, unknown>).length > 0) return true;
        }
      }
    } catch {
      // The normal parser below owns malformed ReCap classification.
    }
  }
  return false;
}

function emptyEvidence(input: CoordinationosSessionPolicyInput): CoordinationosPolicyEvidence {
  const request = input.request;
  return {
    oauthAccessTokenId: input.principal.oauthAccessTokenId,
    tokenDigest: input.principal.tokenDigest,
    clientId: input.principal.clientId,
    userId: input.principal.userId,
    keyId: typeof request.keyId === 'string' ? request.keyId : null,
    origin: canonicalizeCoordinationosOrigin(request.origin),
    chainId: typeof request.chainId === 'number' && Number.isSafeInteger(request.chainId)
      ? request.chainId
      : null,
    purpose: typeof request.purpose === 'string' ? request.purpose : null,
    type: typeof request.type === 'string' ? request.type : null,
    siweDigest: typeof request.message === 'string' ? sha256Hex(request.message) : null,
    capabilityDigest: null,
    nonceDigest: null,
    issuedAt: null,
    expirationTime: null,
    sessionTtlSeconds: null,
  };
}

export function evaluateCoordinationosSessionRequest(
  input: CoordinationosSessionPolicyInput,
): CoordinationosSessionPolicyResult {
  const evidence = emptyEvidence(input);
  const deny = (code: CoordinationosPolicyCode): CoordinationosSessionPolicyResult => ({
    allowed: false,
    code,
    evidence,
  });
  const now = input.now ?? new Date();

  if (!input.client || input.client.clientId !== input.principal.clientId) return deny('wrong_client');
  if (input.client.disabled) return deny('client_disabled');
  if (!input.client.scopes.includes('tinycloud:session')) return deny('missing_scope');
  if (input.client.public
    || input.client.mode !== 'PERSONAL'
    || input.client.type !== 'web'
    || input.client.tokenEndpointAuthMethod !== 'client_secret_basic'
    || !sameStringSet(input.client.grantTypes, ['authorization_code'])
    || !sameStringSet(input.client.responseTypes, ['code'])
    || (!sameStringSet(input.client.scopes, REQUIRED_CLIENT_SCOPES)
      && !sameStringSet(input.client.scopes, TRANSITION_CLIENT_SCOPES))) {
    return deny('client_misconfigured');
  }
  const configuredOrigin = validateCoordinationosClientOrigin(input.client.tinycloudSessionOrigin);
  if (input.client.tinycloudSessionPolicy !== COORDINATIONOS_POLICY_VERSION || !configuredOrigin) {
    return deny('client_misconfigured');
  }
  if (!input.user) return deny('user_not_found');
  if (!input.user.emailVerified) return deny('email_not_verified');
  if (!input.key) return deny('key_not_found');
  if (input.key.userId !== input.principal.userId) return deny('wrong_user');
  if (input.key.keyPurpose !== 'PERSONAL') return deny('wrong_key_purpose');
  if (input.key.keyType !== 'MANAGED') return deny('external_key_denied');
  if (input.key.archivedAt) return deny('key_archived');
  if (!input.key.sealedBlob) return deny('key_unavailable');
  if (input.request.type !== 'siwe') return deny('wrong_type');
  if (input.request.purpose !== 'sign-in') return deny('wrong_purpose');
  if (input.request.chainId !== COORDINATIONOS_CHAIN_ID) return deny('wrong_chain');

  const requestedAddress = checksum(input.request.address);
  const keyAddress = checksum(input.key.address);
  if (!requestedAddress || !keyAddress || requestedAddress !== keyAddress) {
    return deny('key_address_mismatch');
  }

  if (!input.request.origin) return deny('missing_origin');
  const normalizedOrigin = canonicalizeCoordinationosOrigin(input.request.origin);
  evidence.origin = normalizedOrigin;
  if (!normalizedOrigin || normalizedOrigin !== configuredOrigin) {
    return deny('wrong_origin');
  }

  if (typeof input.request.message !== 'string') return deny('invalid_siwe');
  const looksLikeSiwe = input.request.message.includes(
    ' wants you to sign in with your Ethereum account:',
  ) && /^Version: 1$/m.test(input.request.message);
  const rawNonce = /^Nonce: (.*)$/m.exec(input.request.message)?.[1];
  if (looksLikeSiwe && (!rawNonce || !/^[A-Za-z0-9]{16,64}$/.test(rawNonce))) {
    if (rawNonce) evidence.nonceDigest = sha256Hex(rawNonce);
    return deny('invalid_nonce');
  }
  let parsed: SiweMessage;
  try {
    parsed = new SiweMessage(input.request.message);
  } catch {
    return deny('invalid_siwe');
  }
  evidence.issuedAt = parsed.issuedAt ?? null;
  evidence.expirationTime = parsed.expirationTime ?? null;

  const configuredUrl = new URL(configuredOrigin);
  if (parsed.domain.toLowerCase() !== configuredUrl.host.toLowerCase()) {
    return deny('siwe_domain_mismatch');
  }
  if (parsed.chainId !== COORDINATIONOS_CHAIN_ID) return deny('chain_mismatch');
  if (checksum(parsed.address) !== keyAddress) return deny('key_address_mismatch');
  if (!validVerificationMethodUri(parsed.uri)) return deny('siwe_uri_mismatch');
  const recapResources = parsed.resources?.filter((resource) => resource.startsWith('urn:recap:'))
    ?? [];
  if (recapResources.length > 1) return deny('capability_escalation');
  if (recapResources.length !== 1) return deny('wrong_capability');
  if (recapHasNonemptyCaveats(parsed.resources)) return deny('capability_escalation');

  if (!/^[A-Za-z0-9]{16,64}$/.test(parsed.nonce)) return deny('invalid_nonce');
  evidence.nonceDigest = sha256Hex(parsed.nonce);
  if (input.tokenConsumed) return deny('token_consumed');
  if (input.nonceReplayed) return deny('nonce_replayed');

  const issuedAt = parsed.issuedAt ? Date.parse(parsed.issuedAt) : Number.NaN;
  const expirationTime = parsed.expirationTime ? Date.parse(parsed.expirationTime) : Number.NaN;
  if (!Number.isFinite(issuedAt) || issuedAt > now.getTime() + 60_000
    || issuedAt < now.getTime() - 60_000) {
    return deny('issued_at_invalid');
  }
  if (!Number.isFinite(expirationTime) || expirationTime <= now.getTime()) {
    return deny('session_expired');
  }
  const ttlSeconds = (expirationTime - issuedAt) / 1_000;
  evidence.sessionTtlSeconds = ttlSeconds;
  if (ttlSeconds <= 0 || ttlSeconds > COORDINATIONOS_SESSION_TTL_SECONDS) {
    return deny('session_ttl_exceeded');
  }

  let canonicalCapabilities: CanonicalRecapEntry[];
  try {
    const parsedCapabilities = parseRecapFromSiwe(input.request.message);
    if (Array.isArray(parsedCapabilities) && parsedCapabilities.some((raw) => {
      if (!raw || typeof raw !== 'object') return false;
      const candidate = raw as Record<string, unknown>;
      const actions = candidate.actions;
      return (typeof candidate.service === 'string'
          && candidate.service !== 'kv'
          && candidate.service !== 'tinycloud.kv')
        || (Array.isArray(actions) && (
          new Set(actions).size !== actions.length
          || actions.some((action) => typeof action === 'string'
            && !REQUIRED_ACTIONS.includes(action as never))
        ))
        || (Array.isArray(candidate.caveats) && candidate.caveats.length > 0);
    })) return deny('capability_escalation');
    canonicalCapabilities = canonicalizeCoordinationosCapabilities(parsedCapabilities);
  } catch {
    return deny('wrong_capability');
  }
  evidence.capabilityDigest = canonicalCapabilityDigest(canonicalCapabilities);
  if (canonicalCapabilities.length === 0) return deny('wrong_capability');
  if (canonicalCapabilities.length > 2) return deny('capability_escalation');

  const expectedSpace = `tinycloud:pkh:eip155:1:${keyAddress}:applications`;
  const canaryPath = coordinationosCanaryPath(input.key.id);
  const allowedPaths = new Set([
    canaryPath,
    coordinationosInviteCodePath(input.key.id),
  ]);
  const requestedPaths = new Set(canonicalCapabilities.map((capability) => capability.path));
  if (requestedPaths.size !== canonicalCapabilities.length) return deny('capability_escalation');
  if (!requestedPaths.has(canaryPath)) return deny('wrong_capability');
  if ([...requestedPaths].some((path) => !allowedPaths.has(path))) {
    return canonicalCapabilities.length > 1
      ? deny('capability_escalation')
      : deny('wrong_capability');
  }
  for (const capability of canonicalCapabilities) {
    if (capability.space.includes(':eip155:') && !capability.space.includes(':eip155:1:')) {
      return deny('chain_mismatch');
    }
    if (capability.service !== 'tinycloud.kv' || capability.space !== expectedSpace) {
      return deny('wrong_capability');
    }
    if (capability.actions.some((action) => !REQUIRED_ACTIONS.includes(action as never))
      || capability.actions.length > REQUIRED_ACTIONS.length) {
      return deny('capability_escalation');
    }
    if (!sameStringSet(capability.actions, REQUIRED_ACTIONS)) return deny('wrong_capability');
  }

  return { allowed: true, evidence, canonicalCapabilities, parsed };
}
