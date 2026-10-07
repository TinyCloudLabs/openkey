import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { SiweMessage } from 'siwe';
import {
  TINYCLOUD_DELEGATED_PATH,
  TINYCLOUD_DELEGATED_PATH_MAX_LENGTH,
  TINYCLOUD_DENIED_PATH_ROOTS,
  hasDotSegment,
  tinycloudPathSegments,
} from './tinycloud-path-policy';

export const DEVICE_AUTH_TRANSACTION_TTL_MS = 10 * 60 * 1000;
export const DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const DEVICE_AUTH_MAX_DELEGATION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const DEVICE_AUTH_POLL_INTERVAL_SECONDS = 2;
export const DEVICE_AUTH_START_LIMIT = 5;
export const DEVICE_AUTH_START_WINDOW_MS = 10 * 60 * 1000;
export const DEVICE_AUTH_MAX_PERMISSIONS = 16;
export const DEVICE_AUTH_MAX_REASON_LENGTH = 200;
/** Tolerance for clock differences between API instances when signing. */
export const DEVICE_AUTH_CLOCK_SKEW_MS = 5_000;

export interface DevicePermission {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

/**
 * The retired one-shot Share upload request. It is accepted (and normalized)
 * exactly as before TC-539 so existing CLIs keep working.
 */
export const SHARE_DEVICE_PERMISSIONS: readonly DevicePermission[] = Object.freeze([Object.freeze({
  service: 'tinycloud.capabilities',
  space: 'applications',
  path: '',
  actions: Object.freeze(['tinycloud.capabilities/read']) as string[],
})]);

/**
 * Device-flow scope policy (TC-539). A device approval is phishable: anyone
 * can start a request and send its code to a victim. Requests are therefore
 * limited to an explicit allowlist of data abilities on one ordinary space:
 *
 * - services: `tinycloud.kv` and `tinycloud.capabilities` only, always fully
 *   qualified. `tinycloud.sql` is deferred: Node authorizes SQL descendant
 *   paths but selects the database by the final path segment, so a grant for
 *   `notes` could reach database `private` through `notes/private`;
 * - abilities: KV get/list/metadata/put/del and capabilities read. SQL,
 *   delegation, space, hooks, encryption, secrets, DuckDB, VFS, and wildcard
 *   abilities are rejected;
 * - spaces: one per request; `account` (account registry), `applications`
 *   (application registry) and `secrets` are rejected;
 * - paths: KV grants name an explicit relative path (no whole-space grants,
 *   no `.`/`..` segments, no `secrets/` or `vault/` roots) and no KV path may
 *   cover another (Node grants cover every path beneath a granted path);
 *   capabilities grants are space-wide (empty path);
 * - `tinycloud.capabilities/read` is required: every OpenKey delegation
 *   carries it, so it is never optional at consent.
 */
export const DEVICE_FLOW_ABILITIES: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'tinycloud.kv': ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata', 'tinycloud.kv/put', 'tinycloud.kv/del'],
  'tinycloud.capabilities': ['tinycloud.capabilities/read'],
});
const DEVICE_FLOW_DENIED_SPACES: Record<string, true> = { account: true, applications: true, secrets: true };
const DEVICE_PERMISSION_FIELDS: Record<string, true> = { service: true, space: true, path: true, actions: true };
const DEVICE_SPACE_NAME = '[A-Za-z0-9][A-Za-z0-9._-]{0,63}';
const DEVICE_SHORT_SPACE = new RegExp(`^${DEVICE_SPACE_NAME}$`);
const DEVICE_PKH_SPACE = new RegExp(`^tinycloud:pkh:eip155:([1-9][0-9]{0,19}):(0x[0-9a-fA-F]{40}):(${DEVICE_SPACE_NAME})$`);

export interface DeviceAuthorizationRecord {
  id: string;
  userCode: string;
  deviceSecretHash: string;
  codeChallenge: string;
  sessionDid: string;
  publicJwk: Record<string, unknown>;
  relayPublicJwk: Record<string, unknown>;
  /** Requested permissions, already validated against the device-flow policy. */
  permissions: DevicePermission[];
  /** Approved subset of `permissions`; set when the owner approves. */
  approvedPermissions?: DevicePermission[];
  reason?: string;
  nodeOrigin: string;
  shareOrigin: string;
  /**
   * Upper bound for the delegation expiry: transaction deadline plus the
   * requested lifetime while pending, the approved expiry afterwards.
   */
  delegationExpiresAt: Date;
  /** Requested lifetime; an approval may grant at most approval time + this. */
  delegationTtlSeconds: number;
  transactionExpiresAt: Date;
  requestedAt: Date;
  requestIpHash: string;
  nextPollAt: Date;
  pollIntervalSeconds: number;
  status: 'pending' | 'approved' | 'denied' | 'consumed';
  approvedByUserId?: string;
  encryptedResult?: string;
  consumedAt?: Date;
}

export interface DeviceAuthorizationStore {
  create(record: DeviceAuthorizationRecord): Promise<void>;
  findById(id: string): Promise<DeviceAuthorizationRecord | null>;
  findByUserCode(userCode: string): Promise<DeviceAuthorizationRecord | null>;
  countRecentByIpHash(ipHash: string, since: Date): Promise<number>;
  updatePoll(id: string, nextPollAt: Date): Promise<void>;
  approve(id: string, input: {
    userId: string;
    encryptedResult: string;
    delegationExpiresAt: Date;
    approvedPermissions: DevicePermission[];
  }): Promise<boolean>;
  consumeApproved(id: string): Promise<DeviceAuthorizationRecord | null>;
}

export class MemoryDeviceAuthorizationStore implements DeviceAuthorizationStore {
  private records = new Map<string, DeviceAuthorizationRecord>();

  async create(record: DeviceAuthorizationRecord): Promise<void> {
    this.records.set(record.id, { ...record });
  }

  async findById(id: string): Promise<DeviceAuthorizationRecord | null> {
    return this.records.get(id) ?? null;
  }

  async findByUserCode(userCode: string): Promise<DeviceAuthorizationRecord | null> {
    return [...this.records.values()].find((record) => record.userCode === userCode) ?? null;
  }

  async countRecentByIpHash(ipHash: string, since: Date): Promise<number> {
    return [...this.records.values()].filter(
      (record) => record.requestIpHash === ipHash && record.requestedAt >= since,
    ).length;
  }

  async updatePoll(id: string, nextPollAt: Date): Promise<void> {
    const record = this.records.get(id);
    if (record) record.nextPollAt = nextPollAt;
  }

  async approve(id: string, input: {
    userId: string;
    encryptedResult: string;
    delegationExpiresAt: Date;
    approvedPermissions: DevicePermission[];
  }): Promise<boolean> {
    const record = this.records.get(id);
    if (!record || record.status !== 'pending') return false;
    Object.assign(record, {
      status: 'approved' as const,
      approvedByUserId: input.userId,
      encryptedResult: input.encryptedResult,
      delegationExpiresAt: input.delegationExpiresAt,
      approvedPermissions: input.approvedPermissions,
    });
    return true;
  }

  async consumeApproved(id: string): Promise<DeviceAuthorizationRecord | null> {
    const record = this.records.get(id);
    if (!record || record.status !== 'approved' || record.consumedAt) return null;
    record.status = 'consumed';
    record.consumedAt = new Date();
    const consumed = { ...record };
    delete record.encryptedResult;
    return consumed;
  }
}

export type DeviceAuthorizationStart = {
  deviceSecretHash: string;
  codeChallenge: string;
  sessionDid: string;
  publicJwk: Record<string, unknown>;
  relayPublicJwk: Record<string, unknown>;
  permissions: DevicePermission[];
  nodeOrigin: string;
  shareOrigin: string;
  delegationTtlSeconds?: number;
  reason?: string;
};

export type DeviceAuthorizationResult = Record<string, unknown> & {
  delegationHeader: { Authorization: string };
  delegationCid: string;
  spaceId: string;
  verificationMethod: string;
};

export interface DeviceRelayEnvelope {
  version: 1;
  algorithm: 'ECDH-P256-A256GCM';
  ephemeralPublicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  nonce: string;
  ciphertext: string;
}

export class DeviceAuthorizationError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'DeviceAuthorizationError';
  }
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

function equalDigest(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function canonicalOrigin(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new DeviceAuthorizationError('invalid_request', `${label} is required`, 400);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new DeviceAuthorizationError('invalid_request', `${label} must be an origin`, 400);
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost';
  if (url.origin !== value || (url.protocol !== 'https:' && !(loopback && url.protocol === 'http:'))) {
    throw new DeviceAuthorizationError('invalid_request', `${label} must be a canonical HTTPS origin`, 400);
  }
  return value;
}

function publicSessionJwk(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeviceAuthorizationError('invalid_request', 'publicJwk must be an object', 400);
  }
  const jwk = value as Record<string, unknown>;
  if (
    jwk.kty !== 'OKP' ||
    jwk.crv !== 'Ed25519' ||
    typeof jwk.x !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) ||
    ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((field) => field in jwk)
  ) {
    throw new DeviceAuthorizationError('invalid_request', 'publicJwk must be a public Ed25519 JWK', 400);
  }
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: jwk.x,
    ...(typeof jwk.kid === 'string' && jwk.kid.length > 0 ? { kid: jwk.kid } : {}),
  };
}

function publicRelayJwk(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeviceAuthorizationError('invalid_request', 'relayPublicJwk must be an object', 400);
  }
  const jwk = value as Record<string, unknown>;
  if (
    jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
    typeof jwk.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) ||
    typeof jwk.y !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(jwk.y) ||
    'd' in jwk
  ) throw new DeviceAuthorizationError('invalid_request', 'relayPublicJwk must be a public P-256 JWK', 400);
  for (const coordinate of [jwk.x, jwk.y]) {
    const decoded = Buffer.from(coordinate as string, 'base64url');
    if (decoded.length !== 32 || decoded.toString('base64url') !== coordinate) {
      throw new DeviceAuthorizationError('invalid_request', 'relayPublicJwk coordinates must encode 32 canonical bytes', 400);
    }
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

function base58btc(bytes: Uint8Array): string {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      carry += digits[index]! << 8;
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = '';
  for (const byte of bytes) {
    if (byte !== 0) break;
    output += alphabet[0];
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) output += alphabet[digits[index]!]!;
  return output;
}

export function sessionDidForPublicJwk(value: unknown): string {
  const jwk = publicSessionJwk(value);
  const publicKey = Buffer.from(jwk.x as string, 'base64url');
  if (publicKey.length !== 32 || publicKey.toString('base64url') !== jwk.x) {
    throw new DeviceAuthorizationError('invalid_request', 'publicJwk.x must encode 32 canonical bytes', 400);
  }
  const identifier = `z${base58btc(new Uint8Array([0xed, 0x01, ...publicKey]))}`;
  return `did:key:${identifier}#${identifier}`;
}

const DEVICE_SESSION_JWK_FIELDS: Record<string, true> = { kty: true, crv: true, x: true, kid: true };

/**
 * Session DID of a delegation request's JWK, refusing anything but the exact
 * public Ed25519 shape a device request stores (`kty`, `crv`, canonical `x`,
 * and `kid` only when it is a non-empty string): private, unknown, or
 * `null`-valued fields, a non-string or empty `kid`, and padded coordinates
 * are alternate spellings that must not be accepted silently.
 */
function strictSessionDid(value: unknown): string {
  if (
    !value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).some((field) => !Object.hasOwn(DEVICE_SESSION_JWK_FIELDS, field)) ||
    ('kid' in value && (typeof value.kid !== 'string' || value.kid.length === 0))
  ) {
    throw new DeviceAuthorizationError(
      'invalid_request',
      'jwk must be a public Ed25519 JWK with only kty, crv, x, and an optional non-empty string kid',
      400,
    );
  }
  return sessionDidForPublicJwk(value);
}

/**
 * The delegate (`URI`, the CACAO audience) and expiry of a SIWE message,
 * read by the EIP-4361 grammar rather than by searching for lines. Only
 * canonical messages are accepted: the parse must re-serialize to exactly
 * the given bytes. Otherwise a message could carry a decoy `URI:` or
 * `Expiration Time:` line where the positional Rust parser that builds the
 * delegation expects a separator, so a line search and the signed
 * delegation would disagree.
 */
function canonicalSiweFields(message: string): { uri: string; expirationTime: string } | null {
  try {
    const parsed = new SiweMessage(message);
    if (parsed.prepareMessage() !== message || !parsed.expirationTime) return null;
    return { uri: parsed.uri, expirationTime: parsed.expirationTime };
  } catch {
    return null;
  }
}

function scopeError(message: string): DeviceAuthorizationError {
  return new DeviceAuthorizationError('invalid_scope', message, 400);
}

function isLegacyShareRequest(value: unknown): boolean {
  if (!Array.isArray(value) || value.length !== 1) return false;
  const permission = value[0] as Record<string, unknown> | null;
  return Boolean(
    permission &&
    (permission.service === 'tinycloud.capabilities' || permission.service === 'capabilities') &&
    (permission.space === 'applications' || (typeof permission.space === 'string' && permission.space.endsWith(':applications'))) &&
    permission.path === '' &&
    Array.isArray(permission.actions) &&
    permission.actions.length === 1 &&
    permission.actions[0] === 'tinycloud.capabilities/read',
  );
}

export function isShareDevicePermissionSet(permissions: readonly DevicePermission[]): boolean {
  return jsonEqual(permissions, SHARE_DEVICE_PERMISSIONS);
}

/**
 * Comparable identity of a device-request space. Ethereum addresses are
 * case-insensitive (the signed ReCap uses EIP-55), so only the address is
 * lowercased; the chain and space name stay exact. A bare space name and a
 * full URI never compare equal.
 */
function deviceSpaceIdentity(space: unknown): { key: string; name: string } | null {
  if (typeof space !== 'string') return null;
  if (DEVICE_SHORT_SPACE.test(space)) return { key: space, name: space };
  const match = DEVICE_PKH_SPACE.exec(space);
  return match ? { key: `tinycloud:pkh:eip155:${match[1]}:${match[2]!.toLowerCase()}:${match[3]}`, name: match[3]! } : null;
}

function assertDevicePath(service: string, path: string, label: string): void {
  if (service === 'tinycloud.capabilities') {
    if (path !== '') throw scopeError(`${label} must be empty for tinycloud.capabilities`);
    return;
  }
  if (path.length === 0) throw scopeError(`${label} must name an explicit path; whole-space grants are not available over device authorization`);
  if (path.length > TINYCLOUD_DELEGATED_PATH_MAX_LENGTH || !TINYCLOUD_DELEGATED_PATH.test(path)) throw scopeError(`${label} must be a relative path without wildcards or empty segments`);
  if (hasDotSegment(path)) throw scopeError(`${label} must not contain . or .. segments`);
  const segments = tinycloudPathSegments(path);
  if (Object.hasOwn(TINYCLOUD_DENIED_PATH_ROOTS, segments[0]!.toLowerCase())) throw scopeError(`${label} must not address secrets`);
}

/**
 * Validate a device authorization permission request. Returns the canonical
 * Share-only permission for the legacy request, otherwise the explicit
 * manifest permissions after the device-flow policy above.
 */
export function deviceRequestPermissions(value: unknown): DevicePermission[] {
  if (isLegacyShareRequest(value)) {
    return SHARE_DEVICE_PERMISSIONS.map((permission) => ({ ...permission, actions: [...permission.actions] }));
  }
  if (!Array.isArray(value) || value.length === 0 || value.length > DEVICE_AUTH_MAX_PERMISSIONS) {
    throw scopeError(`permissions must list between 1 and ${DEVICE_AUTH_MAX_PERMISSIONS} explicit capabilities`);
  }
  let requestSpace: string | undefined;
  const granted: Array<{ service: string; segments: string[]; index: number }> = [];
  const permissions = value.map((raw, index) => {
    const label = `permissions[${index}]`;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw scopeError(`${label} must be an object`);
    const entry = raw as Record<string, unknown>;
    const unknownField = Object.keys(entry).find((field) => !Object.hasOwn(DEVICE_PERMISSION_FIELDS, field));
    if (unknownField) throw scopeError(`${label}.${unknownField} is not a permission field`);
    const { service, space, path, actions } = entry;
    if (typeof service !== 'string' || !Object.hasOwn(DEVICE_FLOW_ABILITIES, service)) {
      throw scopeError(`${label}.service is not available over device authorization`);
    }
    if (typeof space !== 'string') throw scopeError(`${label}.space is required`);
    const spaceIdentity = deviceSpaceIdentity(space);
    if (!spaceIdentity) throw scopeError(`${label}.space must be a space name or tinycloud:pkh space URI`);
    if (Object.hasOwn(DEVICE_FLOW_DENIED_SPACES, spaceIdentity.name.toLowerCase())) {
      throw scopeError(`${label}.space ${spaceIdentity.name} is not available over device authorization`);
    }
    if (requestSpace === undefined) requestSpace = spaceIdentity.key;
    else if (spaceIdentity.key !== requestSpace) throw scopeError('device authorization accepts one space per request');
    if (typeof path !== 'string') throw scopeError(`${label}.path is required`);
    assertDevicePath(service, path, `${label}.path`);
    // Node grants cover every path beneath a granted path (segment prefix),
    // so an entry covered by another of the same service could not really
    // be unchecked on its own.
    const segments = path.split('/').filter(Boolean);
    const covering = granted.find((other) => {
      if (other.service !== service) return false;
      const [shorter, longer] = other.segments.length <= segments.length ? [other.segments, segments] : [segments, other.segments];
      return shorter.every((segment, position) => segment === longer[position]);
    });
    if (covering) throw scopeError(`${label}.path overlaps permissions[${covering.index}].path; a granted path covers every path beneath it`);
    granted.push({ service, segments, index });
    const allowed = DEVICE_FLOW_ABILITIES[service]!;
    if (!Array.isArray(actions) || actions.length === 0) throw scopeError(`${label}.actions must be a non-empty list`);
    const unique = new Set<string>();
    for (const action of actions) {
      if (typeof action !== 'string' || !allowed.includes(action)) {
        throw scopeError(`${label}.actions contains an ability that is not available over device authorization`);
      }
      if (unique.has(action)) throw scopeError(`${label}.actions repeats ${action}`);
      unique.add(action);
    }
    return { service, space, path, actions: [...unique] };
  });
  if (!permissions.some((permission) => permission.service === 'tinycloud.capabilities')) {
    throw scopeError(
      'permissions must include tinycloud.capabilities/read with path "" in the requested space; every OpenKey delegation carries it and it cannot be unchecked',
    );
  }
  return permissions;
}

function requestReason(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new DeviceAuthorizationError('invalid_request', 'reason must be a string', 400);
  // Control, bidirectional-override, and invisible format characters could
  // disguise the consent text; strip them before measuring and storing.
  const normalized = value
    .replace(/[\p{Cf}\p{Default_Ignorable_Code_Point}\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u3164\ufeff\uffa0\u{e0000}-\u{e007f}]/gu, '')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (normalized.length > DEVICE_AUTH_MAX_REASON_LENGTH) {
    throw new DeviceAuthorizationError('invalid_request', `reason must be at most ${DEVICE_AUTH_MAX_REASON_LENGTH} characters`, 400);
  }
  return normalized || undefined;
}

/**
 * The owner may uncheck optional capabilities, so the approved set is any
 * subset of the request that keeps `tinycloud.capabilities/read`. It must be
 * stated in the request's spelling and order (entries and actions) so the
 * binding and the relayed delegation compare byte-for-byte.
 */
function approvedPermissionSubset(requested: DevicePermission[], value: unknown): DevicePermission[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new DeviceAuthorizationError('invalid_result', 'approved permissions must be a non-empty list', 400);
  }
  const resourceKey = (permission: { service?: unknown; space?: unknown; path?: unknown }) =>
    `${permission.service}\0${deviceSpaceIdentity(permission.space)?.key}\0${permission.path}`;
  const requestedByResource = new Map(requested.map((permission) => [resourceKey(permission), permission]));
  const approvedByResource = new Map<string, Set<string>>();
  for (const raw of value) {
    const entry = (raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}) as Record<string, unknown>;
    const resource = resourceKey(entry);
    const source = requestedByResource.get(resource);
    if (
      !source || approvedByResource.has(resource) ||
      !Array.isArray(entry.actions) || entry.actions.length === 0 ||
      entry.actions.some((action) => typeof action !== 'string' || !source.actions.includes(action))
    ) {
      throw new DeviceAuthorizationError('invalid_result', 'approved permissions exceed the device request', 400);
    }
    approvedByResource.set(resource, new Set(entry.actions as string[]));
  }
  const canonical = requested.flatMap((permission) => {
    const actions = approvedByResource.get(resourceKey(permission));
    return actions ? [{ ...permission, actions: permission.actions.filter((action) => actions.has(action)) }] : [];
  });
  if (!canonical.some((permission) => permission.service === 'tinycloud.capabilities')) {
    throw new DeviceAuthorizationError('invalid_result', 'approved permissions must keep tinycloud.capabilities/read', 400);
  }
  if (!jsonEqual(canonical, value)) {
    throw new DeviceAuthorizationError('invalid_result', 'approved permissions must list each capability once in request spelling and order', 400);
  }
  return canonical;
}

function normalizeUserCode(value: string): string {
  return value.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function displayUserCode(value: string): string {
  const normalized = normalizeUserCode(value);
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}

function randomUserCode(): string {
  const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const bytes = randomBytes(8);
  return [...bytes].map((value) => alphabet[value % alphabet.length]).join('');
}

function requestedTtlSeconds(input: unknown): number {
  const seconds = input === undefined ? DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS / 1000 : Number(input);
  if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > DEVICE_AUTH_MAX_DELEGATION_TTL_MS / 1000) {
    throw new DeviceAuthorizationError('invalid_request', 'delegationTtlSeconds must be between 60 seconds and 30 days', 400);
  }
  return seconds;
}

function jsonEqual(left: unknown, right: unknown): boolean {
  const canonical = (value: unknown): unknown => Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => [key, canonical(entry)]))
      : value;
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

function canonicalRelayBytes(value: unknown, label: string): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new DeviceAuthorizationError('invalid_result', `${label} must be canonical base64url`, 400);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) {
    throw new DeviceAuthorizationError('invalid_result', `${label} must be canonical base64url`, 400);
  }
  return decoded;
}

function validateRelayApproval(record: DeviceAuthorizationRecord, value: unknown, now: Date): {
  relay: DeviceRelayEnvelope;
  delegationExpiresAt: Date;
  approvedPermissions: DevicePermission[];
} {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeviceAuthorizationError('invalid_result', 'encrypted relay approval must be an object', 400);
  }
  const approval = value as Record<string, unknown>;
  const relay = approval.relay as Partial<DeviceRelayEnvelope> | undefined;
  const binding = approval.binding;
  if (
    !relay || relay.version !== 1 || relay.algorithm !== 'ECDH-P256-A256GCM' ||
    !binding || typeof binding !== 'object' || Array.isArray(binding)
  ) {
    throw new DeviceAuthorizationError('invalid_result', 'encrypted relay approval is malformed', 400);
  }
  const bound = binding as Record<string, unknown>;
  if (
    bound.transactionId !== record.id ||
    bound.sessionDid !== record.sessionDid ||
    bound.nodeOrigin !== record.nodeOrigin ||
    bound.shareOrigin !== record.shareOrigin
  ) {
    throw new DeviceAuthorizationError('invalid_result', 'relay binding does not match the device request', 400);
  }
  const approvedPermissions = approvedPermissionSubset(record.permissions, bound.permissions);
  const delegationExpiresAt = typeof bound.delegationExpiresAt === 'string'
    ? new Date(bound.delegationExpiresAt)
    : new Date(Number.NaN);
  // The lifetime starts at approval: never longer than the requested TTL
  // from now, and never past the transaction deadline plus that TTL.
  if (
    Number.isNaN(delegationExpiresAt.getTime()) || delegationExpiresAt <= now ||
    delegationExpiresAt.getTime() > now.getTime() + record.delegationTtlSeconds * 1000 ||
    delegationExpiresAt > record.delegationExpiresAt
  ) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation expiry exceeds the approved window', 400);
  }
  const ephemeralPublicJwk = publicRelayJwk(relay.ephemeralPublicJwk) as DeviceRelayEnvelope['ephemeralPublicJwk'];
  const nonce = canonicalRelayBytes(relay.nonce, 'relay nonce');
  const ciphertext = canonicalRelayBytes(relay.ciphertext, 'relay ciphertext');
  if (nonce.length !== 12 || ciphertext.length <= 16 || ciphertext.length > 1024 * 1024) {
    throw new DeviceAuthorizationError('invalid_result', 'encrypted relay result has an invalid size', 400);
  }
  return {
    relay: {
      version: 1,
      algorithm: 'ECDH-P256-A256GCM',
      ephemeralPublicJwk,
      nonce: nonce.toString('base64url'),
      ciphertext: ciphertext.toString('base64url'),
    },
    delegationExpiresAt,
    approvedPermissions,
  };
}

export class DeviceAuthorizationService {
  constructor(
    private readonly store: DeviceAuthorizationStore,
    private readonly options: {
      verificationOrigin: string;
      encryptionSecret: string;
      now?: () => Date;
    },
  ) {
    if (options.encryptionSecret.length < 32) throw new Error('device authorization encryption secret must be at least 32 characters');
  }

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  async start(input: DeviceAuthorizationStart, requestIp: string): Promise<{
    transactionId: string;
    userCode: string;
    verificationUri: string;
    verificationUriComplete: string;
    expiresIn: number;
    interval: number;
  }> {
    const now = this.now();
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new DeviceAuthorizationError('invalid_request', 'device authorization request must be an object', 400);
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(input.deviceSecretHash) || !/^[A-Za-z0-9_-]{43}$/.test(input.codeChallenge)) {
      throw new DeviceAuthorizationError('invalid_request', 'device secret hash and PKCE challenge must be SHA-256 base64url values', 400);
    }
    const publicJwk = publicSessionJwk(input.publicJwk);
    const relayPublicJwk = publicRelayJwk(input.relayPublicJwk);
    if (input.sessionDid !== sessionDidForPublicJwk(publicJwk)) {
      throw new DeviceAuthorizationError('invalid_request', 'sessionDid does not match publicJwk', 400);
    }
    const permissions = deviceRequestPermissions(input.permissions);
    const reason = requestReason(input.reason);
    const delegationTtlSeconds = requestedTtlSeconds(input.delegationTtlSeconds);
    const nodeOrigin = canonicalOrigin(input.nodeOrigin, 'nodeOrigin');
    const shareOrigin = canonicalOrigin(input.shareOrigin, 'shareOrigin');
    const requestIpHash = sha256(`device-auth-ip\0${this.options.encryptionSecret}\0${requestIp}`);
    const recent = await this.store.countRecentByIpHash(requestIpHash, new Date(now.getTime() - DEVICE_AUTH_START_WINDOW_MS));
    if (recent >= DEVICE_AUTH_START_LIMIT) {
      throw new DeviceAuthorizationError('rate_limited', 'too many device authorization requests', 429);
    }
    const id = randomBytes(18).toString('base64url');
    let rawUserCode = randomUserCode();
    while (await this.store.findByUserCode(rawUserCode)) rawUserCode = randomUserCode();
    const userCode = displayUserCode(rawUserCode);
    const transactionExpiresAt = new Date(now.getTime() + DEVICE_AUTH_TRANSACTION_TTL_MS);
    const record: DeviceAuthorizationRecord = {
      id,
      userCode: rawUserCode,
      deviceSecretHash: input.deviceSecretHash,
      codeChallenge: input.codeChallenge,
      sessionDid: input.sessionDid,
      publicJwk,
      relayPublicJwk,
      permissions,
      ...(reason ? { reason } : {}),
      nodeOrigin,
      shareOrigin,
      // The requested lifetime begins when the person approves, not when the
      // CLI first prints the code: approval may grant at most approval time
      // plus the TTL, so the absolute bound is the transaction deadline plus
      // the TTL.
      delegationExpiresAt: new Date(transactionExpiresAt.getTime() + delegationTtlSeconds * 1000),
      delegationTtlSeconds,
      transactionExpiresAt,
      requestedAt: now,
      requestIpHash,
      nextPollAt: now,
      pollIntervalSeconds: DEVICE_AUTH_POLL_INTERVAL_SECONDS,
      status: 'pending',
    };
    await this.store.create(record);
    const verificationUri = `${canonicalOrigin(this.options.verificationOrigin, 'verificationOrigin')}/device`;
    return {
      transactionId: id,
      userCode,
      verificationUri,
      verificationUriComplete: `${verificationUri}?user_code=${encodeURIComponent(userCode)}`,
      expiresIn: Math.floor(DEVICE_AUTH_TRANSACTION_TTL_MS / 1000),
      interval: DEVICE_AUTH_POLL_INTERVAL_SECONDS,
    };
  }

  /**
   * Guard for the delegate signing routes when a request names a device
   * transaction (`deviceTransactionId`). The delegation must be for that
   * pending transaction's session key and Node origin, and expire within
   * its lifetime (requested TTL from now, and the transaction deadline plus
   * TTL). The session key is taken from the strictly parsed JWK and, once a
   * SIWE exists, from the canonical SIWE that is (or was) actually signed,
   * which also supplies the expiry; they must agree. Checked before signing
   * and before any host activation, so a delegation outside the transaction
   * never exists.
   */
  async assertDelegationWindow(
    transactionId: unknown,
    input: { nodeOrigin: unknown; jwk: unknown } & ({ signedSiwe: string } | { expiresAt: Date }),
  ): Promise<void> {
    const record = typeof transactionId === 'string' ? await this.store.findById(transactionId) : null;
    const now = this.now();
    if (!record || record.status !== 'pending' || record.transactionExpiresAt <= now) {
      throw new DeviceAuthorizationError('expired_token', 'device authorization is no longer pending', 410);
    }
    const jwkDid = strictSessionDid(input.jwk);
    let signedDid = jwkDid;
    let expiresAt: number;
    if ('signedSiwe' in input) {
      const fields = canonicalSiweFields(input.signedSiwe);
      if (!fields) {
        throw new DeviceAuthorizationError('invalid_request', 'the signed message must be a canonical SIWE message with an expiration time', 400);
      }
      signedDid = fields.uri;
      expiresAt = Date.parse(fields.expirationTime);
    } else {
      expiresAt = input.expiresAt.getTime();
    }
    if (input.nodeOrigin !== record.nodeOrigin || jwkDid !== record.sessionDid || signedDid !== record.sessionDid) {
      throw new DeviceAuthorizationError('invalid_request', 'delegation does not match the device request', 400);
    }
    if (
      Number.isNaN(expiresAt) ||
      expiresAt > now.getTime() + record.delegationTtlSeconds * 1000 + DEVICE_AUTH_CLOCK_SKEW_MS ||
      expiresAt > record.delegationExpiresAt.getTime()
    ) {
      throw new DeviceAuthorizationError('invalid_request', 'delegation lifetime exceeds the device request', 400);
    }
  }

  async lookup(userCode: string): Promise<(Omit<DeviceAuthorizationRecord, 'deviceSecretHash' | 'codeChallenge' | 'requestIpHash' | 'encryptedResult'> & {
    /** True for the retired one-shot Share upload request (legacy CLIs). */
    shareOnly: boolean;
  }) | null> {
    const record = await this.store.findByUserCode(normalizeUserCode(userCode));
    if (!record || record.transactionExpiresAt <= this.now() || record.status !== 'pending') return null;
    const { deviceSecretHash: _secret, codeChallenge: _challenge, requestIpHash: _ip, encryptedResult: _result, ...safe } = record;
    return { ...safe, shareOnly: isShareDevicePermissionSet(record.permissions) };
  }

  async approve(transactionId: string, userId: string, value: unknown): Promise<void> {
    const record = await this.store.findById(transactionId);
    if (!record || record.status !== 'pending' || record.transactionExpiresAt <= this.now()) {
      throw new DeviceAuthorizationError('expired_token', 'device authorization is no longer pending', 410);
    }
    const approval = validateRelayApproval(record, value, this.now());
    const approved = await this.store.approve(record.id, {
      userId,
      encryptedResult: JSON.stringify(approval.relay),
      delegationExpiresAt: approval.delegationExpiresAt,
      approvedPermissions: approval.approvedPermissions,
    });
    if (!approved) throw new DeviceAuthorizationError('expired_token', 'device authorization is no longer pending', 410);
  }

  async poll(input: { transactionId: string; deviceSecret: string; codeVerifier: string }): Promise<
    | { status: 'pending'; interval: number }
    | {
        status: 'approved';
        relay: DeviceRelayEnvelope;
        binding: {
          transactionId: string;
          sessionDid: string;
          nodeOrigin: string;
          shareOrigin: string;
          permissions: DevicePermission[];
          delegationExpiresAt: string;
        };
      }
  > {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new DeviceAuthorizationError('invalid_request', 'device token request must be an object', 400);
    }
    const record = await this.store.findById(input.transactionId);
    if (!record || record.transactionExpiresAt <= this.now()) {
      throw new DeviceAuthorizationError('expired_token', 'device authorization expired', 410);
    }
    if (
      !equalDigest(sha256(input.deviceSecret), record.deviceSecretHash) ||
      !equalDigest(sha256(input.codeVerifier), record.codeChallenge)
    ) {
      throw new DeviceAuthorizationError('invalid_grant', 'device secret or PKCE verifier is invalid', 401);
    }
    const now = this.now();
    if (record.nextPollAt > now) {
      throw new DeviceAuthorizationError('slow_down', 'polling faster than the allowed interval', 429);
    }
    await this.store.updatePoll(record.id, new Date(now.getTime() + record.pollIntervalSeconds * 1000));
    if (record.status === 'pending') return { status: 'pending', interval: record.pollIntervalSeconds };
    if (record.status !== 'approved') throw new DeviceAuthorizationError('invalid_grant', 'device authorization was already consumed', 409);
    const consumed = await this.store.consumeApproved(record.id);
    if (!consumed) throw new DeviceAuthorizationError('invalid_grant', 'device authorization was already consumed', 409);
    return {
      status: 'approved',
      relay: (() => {
        try {
          return JSON.parse(consumed.encryptedResult ?? '') as DeviceRelayEnvelope;
        } catch {
          throw new DeviceAuthorizationError('invalid_result', 'approved relay result is unavailable', 500);
        }
      })(),
      binding: {
        transactionId: consumed.id,
        sessionDid: consumed.sessionDid,
        nodeOrigin: consumed.nodeOrigin,
        shareOrigin: consumed.shareOrigin,
        // Rows approved before TC-539 carry no separate approved set; their
        // approval was validated as equal to the request.
        permissions: consumed.approvedPermissions ?? consumed.permissions,
        delegationExpiresAt: consumed.delegationExpiresAt.toISOString(),
      },
    };
  }
}
