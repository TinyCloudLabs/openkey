import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

export const DEVICE_AUTH_TRANSACTION_TTL_MS = 10 * 60 * 1000;
export const DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const DEVICE_AUTH_MAX_DELEGATION_TTL_MS = 90 * 24 * 60 * 60 * 1000;
export const DEVICE_AUTH_POLL_INTERVAL_SECONDS = 2;
export const DEVICE_AUTH_START_LIMIT = 5;
export const DEVICE_AUTH_START_WINDOW_MS = 10 * 60 * 1000;

export interface DevicePermission {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

export interface DeviceAuthorizationRecord {
  id: string;
  userCode: string;
  deviceSecretHash: string;
  codeChallenge: string;
  sessionDid: string;
  publicJwk: Record<string, unknown>;
  permissions: DevicePermission[];
  nodeOrigin: string;
  shareOrigin: string;
  delegationExpiresAt: Date;
  transactionExpiresAt: Date;
  requestedAt: Date;
  requestIpHash: string;
  nextPollAt: Date;
  pollIntervalSeconds: number;
  status: 'pending' | 'approved' | 'denied' | 'consumed';
  approvedByUserId?: string;
  encryptedResult?: string;
  resultNonce?: string;
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
    resultNonce: string;
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
    resultNonce: string;
  }): Promise<boolean> {
    const record = this.records.get(id);
    if (!record || record.status !== 'pending') return false;
    Object.assign(record, {
      status: 'approved' as const,
      approvedByUserId: input.userId,
      encryptedResult: input.encryptedResult,
      resultNonce: input.resultNonce,
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
    delete record.resultNonce;
    return consumed;
  }
}

export type DeviceAuthorizationStart = {
  deviceSecretHash: string;
  codeChallenge: string;
  sessionDid: string;
  publicJwk: Record<string, unknown>;
  permissions: DevicePermission[];
  nodeOrigin: string;
  shareOrigin: string;
  delegationTtlSeconds?: number;
};

export type DeviceAuthorizationResult = Record<string, unknown> & {
  delegationHeader: { Authorization: string };
  delegationCid: string;
  spaceId: string;
  verificationMethod: string;
};

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

function sharePermissions(value: unknown): DevicePermission[] {
  if (!Array.isArray(value) || value.length !== 1) {
    throw new DeviceAuthorizationError('invalid_scope', 'device authorization accepts one Share upload capability', 400);
  }
  const permission = value[0] as Record<string, unknown>;
  if (
    !permission ||
    (permission.service !== 'tinycloud.capabilities' && permission.service !== 'capabilities') ||
    (permission.space !== 'applications' && !(typeof permission.space === 'string' && permission.space.endsWith(':applications'))) ||
    permission.path !== '' ||
    !Array.isArray(permission.actions) ||
    permission.actions.length !== 1 ||
    permission.actions[0] !== 'tinycloud.capabilities/read'
  ) {
    throw new DeviceAuthorizationError('invalid_scope', 'only the one-shot Share upload capability may be requested', 400);
  }
  return [{
    service: 'tinycloud.capabilities',
    space: 'applications',
    path: '',
    actions: ['tinycloud.capabilities/read'],
  }];
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

function delegationExpiry(input: unknown, now: Date): Date {
  const seconds = input === undefined ? DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS / 1000 : Number(input);
  if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > DEVICE_AUTH_MAX_DELEGATION_TTL_MS / 1000) {
    throw new DeviceAuthorizationError('invalid_request', 'delegationTtlSeconds must be between 60 seconds and 90 days', 400);
  }
  return new Date(now.getTime() + seconds * 1000);
}

function jsonEqual(left: unknown, right: unknown): boolean {
  const canonical = (value: unknown): unknown => Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => [key, canonical(entry)]))
      : value;
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

function validateApprovedDelegation(record: DeviceAuthorizationRecord, value: unknown, now: Date): DeviceAuthorizationResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation result must be an object', 400);
  }
  const result = value as DeviceAuthorizationResult;
  const authorization = result.delegationHeader?.Authorization;
  if (
    typeof authorization !== 'string' || authorization.length === 0 ||
    typeof result.delegationCid !== 'string' || result.delegationCid.length === 0 ||
    typeof result.spaceId !== 'string' || !result.spaceId.endsWith(':applications') ||
    result.verificationMethod !== record.sessionDid
  ) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation is not bound to the requested CLI session', 400);
  }
  if (!jsonEqual(publicSessionJwk(result.jwk), record.publicJwk)) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation JWK does not match the requested CLI session key', 400);
  }
  const permissions = sharePermissions(result.permissions);
  if (!jsonEqual(permissions, record.permissions)) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation permissions exceed the approved Share scope', 400);
  }
  const expiresAtValue = result.expiresAt ?? result.expirationTime ?? result.expiry;
  const expiresAt = typeof expiresAtValue === 'string' ? new Date(expiresAtValue) : new Date(Number.NaN);
  if (
    Number.isNaN(expiresAt.getTime()) ||
    expiresAt <= now ||
    expiresAt > record.delegationExpiresAt
  ) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation expiry exceeds the approved window', 400);
  }
  const binding = result.deviceBinding;
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation result is missing its device binding', 400);
  }
  const bound = binding as Record<string, unknown>;
  if (
    bound.transactionId !== record.id ||
    bound.sessionDid !== record.sessionDid ||
    bound.nodeOrigin !== record.nodeOrigin ||
    bound.shareOrigin !== record.shareOrigin ||
    !jsonEqual(bound.permissions, record.permissions)
  ) {
    throw new DeviceAuthorizationError('invalid_result', 'delegation result binding does not match the device request', 400);
  }
  const output = { ...result };
  delete output.deviceBinding;
  return output;
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

  private key(record: Pick<DeviceAuthorizationRecord, 'id' | 'deviceSecretHash'>): Buffer {
    return createHash('sha256')
      .update('openkey-device-authorization-v1\0')
      .update(this.options.encryptionSecret)
      .update('\0')
      .update(record.id)
      .update('\0')
      .update(record.deviceSecretHash)
      .digest();
  }

  private encrypt(record: DeviceAuthorizationRecord, result: DeviceAuthorizationResult): { ciphertext: string; nonce: string } {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key(record), nonce);
    cipher.setAAD(Buffer.from(record.id));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(result), 'utf8'), cipher.final(), cipher.getAuthTag()]);
    return { ciphertext: ciphertext.toString('base64url'), nonce: nonce.toString('base64url') };
  }

  private decrypt(record: DeviceAuthorizationRecord): DeviceAuthorizationResult {
    if (!record.encryptedResult || !record.resultNonce) throw new DeviceAuthorizationError('invalid_result', 'approved result is unavailable', 500);
    const encoded = Buffer.from(record.encryptedResult, 'base64url');
    const nonce = Buffer.from(record.resultNonce, 'base64url');
    if (nonce.length !== 12 || encoded.length <= 16) throw new DeviceAuthorizationError('invalid_result', 'approved result is unavailable', 500);
    const decipher = createDecipheriv('aes-256-gcm', this.key(record), nonce);
    decipher.setAAD(Buffer.from(record.id));
    decipher.setAuthTag(encoded.subarray(encoded.length - 16));
    return JSON.parse(Buffer.concat([decipher.update(encoded.subarray(0, -16)), decipher.final()]).toString('utf8')) as DeviceAuthorizationResult;
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
    if (!/^[A-Za-z0-9_-]{43}$/.test(input.deviceSecretHash) || !/^[A-Za-z0-9_-]{43}$/.test(input.codeChallenge)) {
      throw new DeviceAuthorizationError('invalid_request', 'device secret hash and PKCE challenge must be SHA-256 base64url values', 400);
    }
    const publicJwk = publicSessionJwk(input.publicJwk);
    if (input.sessionDid !== sessionDidForPublicJwk(publicJwk)) {
      throw new DeviceAuthorizationError('invalid_request', 'sessionDid does not match publicJwk', 400);
    }
    const permissions = sharePermissions(input.permissions);
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
      permissions,
      nodeOrigin,
      shareOrigin,
      delegationExpiresAt: delegationExpiry(input.delegationTtlSeconds, now),
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

  async lookup(userCode: string): Promise<Omit<DeviceAuthorizationRecord, 'deviceSecretHash' | 'codeChallenge' | 'requestIpHash' | 'encryptedResult' | 'resultNonce'> | null> {
    const record = await this.store.findByUserCode(normalizeUserCode(userCode));
    if (!record || record.transactionExpiresAt <= this.now() || record.status !== 'pending') return null;
    const { deviceSecretHash: _secret, codeChallenge: _challenge, requestIpHash: _ip, encryptedResult: _result, resultNonce: _nonce, ...safe } = record;
    return safe;
  }

  async approve(transactionId: string, userId: string, value: unknown): Promise<void> {
    const record = await this.store.findById(transactionId);
    if (!record || record.status !== 'pending' || record.transactionExpiresAt <= this.now()) {
      throw new DeviceAuthorizationError('expired_token', 'device authorization is no longer pending', 410);
    }
    const result = validateApprovedDelegation(record, value, this.now());
    const encrypted = this.encrypt(record, result);
    const approved = await this.store.approve(record.id, {
      userId,
      encryptedResult: encrypted.ciphertext,
      resultNonce: encrypted.nonce,
    });
    if (!approved) throw new DeviceAuthorizationError('expired_token', 'device authorization is no longer pending', 410);
  }

  async poll(input: { transactionId: string; deviceSecret: string; codeVerifier: string }): Promise<
    | { status: 'pending'; interval: number }
    | {
        status: 'approved';
        delegation: DeviceAuthorizationResult;
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
      delegation: this.decrypt(consumed),
      binding: {
        transactionId: consumed.id,
        sessionDid: consumed.sessionDid,
        nodeOrigin: consumed.nodeOrigin,
        shareOrigin: consumed.shareOrigin,
        permissions: consumed.permissions,
        delegationExpiresAt: consumed.delegationExpiresAt.toISOString(),
      },
    };
  }
}
