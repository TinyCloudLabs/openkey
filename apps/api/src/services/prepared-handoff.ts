import { createHash, timingSafeEqual } from 'node:crypto';
import { canonicalSiweFields, strictSessionDid } from './device-authorization';
import { digestJwk } from './authorization-signing';
import { appKeyRefusalCode, appKeyRefusalForSiwe, appKeyRefusalMessage, appKeyRefusalStatus } from './app-key-refusal';
import { parseOwnerRevocationRequest, type OwnerRevocationRequest } from '@openkey/capability-review';

export type PreparedHandoffRequest = {
  protocolVersion: 1;
  siwe: string;
  jwk: Record<string, unknown>;
  host: string;
  keyId?: string;
  presentation?: Record<string, unknown>;
  sessionDid: string;
} | OwnerRevocationRequest;

type Delivery = { handoffId: string; callback?: string; state: string; cancelSecret: string };
const REQUEST_FIELDS: Record<keyof Exclude<PreparedHandoffRequest, OwnerRevocationRequest>, true> = {
  protocolVersion: true, siwe: true, jwk: true, host: true,
  keyId: true, presentation: true, sessionDid: true,
};
const DELIVERY_FIELDS: Record<keyof Delivery, true> = { handoffId: true, callback: true, state: true, cancelSecret: true };

export type PreparedHandoffRecord = {
  ticketHash: string;
  cancelSecretHash: string;
  nonceHash: string;
  request: PreparedHandoffRequest;
  callback?: string;
  state: string;
  expiresAt: Date;
  requestedAt: Date;
  status: 'PENDING' | 'CANCELLED' | 'CONSUMED';
  ownerId: string;
  contextTokenHash: string | null;
  selectedKeyId: string | null;
};

export interface PreparedHandoffStore {
  createLimited(record: PreparedHandoffRecord, since: Date, limit: number): Promise<PreparedHandoffRecord | null>;
  find(ticketHash: string): Promise<PreparedHandoffRecord | null>;
  bind(ticketHash: string, userId: string, contextTokenHash: string, selectedKeyId: string, now: Date): Promise<boolean>;
  reserve(ticketHash: string, userId: string, contextTokenHash: string, selectedKeyId: string, now: Date): Promise<boolean>;
  cancel(ticketHash: string, now: Date, ownerId?: string): Promise<boolean>;
}

export class PreparedHandoffError extends Error {
  constructor(public readonly code: string, message: string, public readonly status: 400 | 403 | 404 | 409 | 410 | 429) {
    super(message);
  }
}

const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const opaque = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').length === 32 && Buffer.from(value, 'base64url').toString('base64url') === value;
function fail(code: string, message: string, status: 400 | 403 | 404 | 409 | 410 | 429): never {
  throw new PreparedHandoffError(code, message, status);
}

function validateRequest(input: unknown, now: Date): { request: PreparedHandoffRequest; delivery: Delivery; issuedAt?: string; expirationTime: string; nonce: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
    !('transportVersion' in input) || input.transportVersion !== 2 ||
    !('request' in input) || !input.request || typeof input.request !== 'object' || Array.isArray(input.request) ||
    !('delivery' in input) || !input.delivery || typeof input.delivery !== 'object' || Array.isArray(input.delivery) ||
    Buffer.byteLength(JSON.stringify(input), 'utf8') > 6 * 1024) fail('invalid_request', 'Invalid or oversized handoff request', 400);
  const request = input.request;
  const delivery = input.delivery;
  const ownerRequest = 'kind' in request;
  let revocation: OwnerRevocationRequest | null = null;
  if (ownerRequest) {
    try { revocation = parseOwnerRevocationRequest(request, now); }
    catch (cause) { fail('invalid_request', cause instanceof Error ? cause.message : 'Invalid owner-revocation request', 400); }
  }
  if ((!ownerRequest && Object.keys(request).some((field) => !Object.hasOwn(REQUEST_FIELDS, field))) ||
    Object.keys(delivery).some((field) => !Object.hasOwn(DELIVERY_FIELDS, field)) ||
    (!ownerRequest && (
      !('protocolVersion' in request) || request.protocolVersion !== 1 ||
      !('siwe' in request) || typeof request.siwe !== 'string' || !request.siwe ||
      !('jwk' in request) || !request.jwk || typeof request.jwk !== 'object' || Array.isArray(request.jwk) ||
      !('host' in request) || typeof request.host !== 'string' ||
      !('sessionDid' in request) || typeof request.sessionDid !== 'string' || request.sessionDid.length > 512 ||
      ('keyId' in request && (typeof request.keyId !== 'string' || !request.keyId)) ||
      ('presentation' in request && (!request.presentation || typeof request.presentation !== 'object' || Array.isArray(request.presentation)))
    )) ||
    !('handoffId' in delivery) || !opaque(delivery.handoffId) ||
    !('state' in delivery) || !opaque(delivery.state) ||
    !('cancelSecret' in delivery) || !opaque(delivery.cancelSecret) ||
    delivery.handoffId === delivery.state || delivery.handoffId === delivery.cancelSecret ||
    delivery.state === delivery.cancelSecret) {
    fail('invalid_request', 'Invalid prepared request or delivery secrets', 400);
  }
  const callback = 'callback' in delivery ? delivery.callback : undefined;
  if (callback !== undefined && typeof callback !== 'string') {
    fail('invalid_request', 'Invalid callback', 400);
  }
  const callbackMatch = typeof callback === 'string'
    ? /^http:\/\/(?:127\.0\.0\.1|\[::1\]):([1-9]\d{3,4})\/callback\/([A-Za-z0-9_-]{22})$/.exec(callback)
    : null;
  if (callback !== undefined && (!callbackMatch || Number(callbackMatch[1]) < 1024 ||
    Number(callbackMatch[1]) > 65535 ||
    Buffer.from(callbackMatch[2]!, 'base64url').toString('base64url') !== callbackMatch[2])) {
    fail('invalid_request', 'callback must be a randomized loopback URL', 400);
  }
  if (revocation) return { request: revocation, delivery: {
    handoffId: delivery.handoffId, state: delivery.state, cancelSecret: delivery.cancelSecret, ...(callback ? { callback } : {}),
  }, issuedAt: now.toISOString(), expirationTime: revocation.expiresAt, nonce: revocation.nonce };
  const legacy = request as Exclude<PreparedHandoffRequest, OwnerRevocationRequest>;
  const fields = canonicalSiweFields(legacy.siwe);
  if (!fields) fail('invalid_request', 'Invalid canonical prepared SIWE', 400);
  const appKeyRefusal = appKeyRefusalForSiwe(legacy.siwe);
  if (appKeyRefusal) {
    fail(appKeyRefusalCode(appKeyRefusal), appKeyRefusalMessage(appKeyRefusal, 'non_browser'), appKeyRefusalStatus(appKeyRefusal));
  }
  try {
    const did = strictSessionDid(legacy.jwk);
    if (fields.uri !== did) fail('invalid_request', 'SIWE URI does not match the public session key', 400);
    const url = new URL(legacy.host);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== legacy.host || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
      fail('invalid_request', 'host must be an exact origin', 400);
    }
  } catch {
    fail('invalid_request', 'Invalid public JWK, SIWE, or host', 400);
  }
  return { request: legacy, delivery: {
    handoffId: delivery.handoffId, state: delivery.state, cancelSecret: delivery.cancelSecret, ...(callback ? { callback } : {}),
  }, issuedAt: fields.issuedAt, expirationTime: fields.expirationTime, nonce: fields.nonce };
}

export class PreparedHandoffService {
  constructor(private readonly store: PreparedHandoffStore, private readonly options: { now?: () => number } = {}) {}
  private now() { return new Date(this.options.now?.() ?? Date.now()); }

  async claim(input: unknown, userId: string): Promise<{ transportVersion: 2; ticket: string; expiresAt: string }> {
    if (!userId) fail('handoff_claimed', 'Authenticated user required', 403);
    const now = this.now();
    const { request, delivery, issuedAt, expirationTime, nonce } = validateRequest(input, now);
    const preparedAt = Date.parse(issuedAt ?? '');
    const grantExpiresAt = Date.parse(expirationTime);
    if (!nonce || !Number.isFinite(preparedAt) || !Number.isFinite(grantExpiresAt) ||
      now.getTime() - preparedAt > 300_000 || preparedAt - now.getTime() > 30_000 ||
      grantExpiresAt <= now.getTime()) {
      fail('prepared_expired', 'Prepared sign-in is stale or expired. Restart the CLI command.', 410);
    }
    const ticketHash = digest(delivery.handoffId);
    const nonceHash = digest(`prepared-handoff-nonce\0${nonce}`);
    const expiresAt = new Date(Math.min(now.getTime() + 300_000, grantExpiresAt));
    const record: PreparedHandoffRecord = { ticketHash, cancelSecretHash: digest(delivery.cancelSecret), nonceHash, request,
      ...(delivery.callback ? { callback: delivery.callback } : {}), state: delivery.state, expiresAt,
      requestedAt: now, status: 'PENDING', ownerId: userId, contextTokenHash: null, selectedKeyId: null };
    let stored: PreparedHandoffRecord | null;
    try {
      stored = await this.store.createLimited(record, new Date(now.getTime() - 300_000), 5);
    } catch (cause) {
      // A concurrent account may have claimed this same handoffId. The
      // database primary key wins; do not leak a raw constraint error.
      const other = await this.store.find(ticketHash);
      if (other) fail('handoff_claimed', 'Handoff belongs to another account or request', 403);
      throw cause;
    }
    if (!stored) fail('rate_limited', 'Too many handoffs for this account', 429);
    if (stored.ownerId !== userId) fail('handoff_claimed', 'Handoff belongs to another account', 403);
    if (stored.ticketHash !== ticketHash || stored.nonceHash !== nonceHash ||
      digestJwk(stored.request) !== digestJwk(request) || stored.callback !== delivery.callback ||
      stored.state !== delivery.state ||
      !timingSafeEqual(Buffer.from(stored.cancelSecretHash, 'hex'), Buffer.from(record.cancelSecretHash, 'hex'))) {
      fail('handoff_replayed', 'This SIWE nonce is already bound to another handoff', 409);
    }
    if (stored.status !== 'PENDING' || stored.expiresAt <= now) await this.active(delivery.handoffId);
    return { transportVersion: 2, ticket: delivery.handoffId, expiresAt: stored.expiresAt.toISOString() };
  }

  private async active(ticket: string): Promise<PreparedHandoffRecord> {
    if (!opaque(ticket)) fail('handoff_not_found', 'Handoff not found', 404);
    const record = await this.store.find(digest(ticket));
    if (!record) fail('handoff_not_found', 'Handoff not found', 404);
    if (record.expiresAt <= this.now()) fail('handoff_expired', 'Handoff expired', 410);
    if (record.status === 'CANCELLED') fail('handoff_cancelled', 'Handoff cancelled', 410);
    if (record.status === 'CONSUMED') fail('handoff_consumed', 'Handoff already signed', 409);
    return record;
  }
  async bindOwnerRevocation(ticket: string, userId: string, keyId: string, contextToken: string): Promise<void> {
    const record = await this.active(ticket);
    if (record.ownerId !== userId || !('kind' in record.request) || record.request.kind !== 'owner-revocation') {
      fail('binding_mismatch', 'Owner-revocation handoff does not belong to this account', 403);
    }
    if (record.contextTokenHash || !await this.store.bind(record.ticketHash, userId, digest(contextToken), keyId, this.now())) {
      fail('handoff_context_unavailable', 'Handoff already prepared; cancel and restart', 409);
    }
  }

  async ownerRevocation(ticket: string, userId: string): Promise<OwnerRevocationRequest> {
    const record = await this.active(ticket);
    if (record.ownerId !== userId || !('kind' in record.request) || record.request.kind !== 'owner-revocation') {
      fail('binding_mismatch', 'Owner-revocation handoff does not belong to this account', 403);
    }
    return parseOwnerRevocationRequest(record.request, this.now());
  }


  async assertRequest(ticket: string, userId: string, input: {
    keyId: string; siwe: string; jwk: unknown; host: string; presentation?: unknown; reportedOrigin?: unknown;
  }): Promise<string> {
    const record = await this.active(ticket);
    if (record.ownerId !== userId) fail('handoff_claimed', 'Handoff not claimed by this user', 403);
    if ('kind' in record.request) fail('binding_mismatch', 'Signing request differs from prepared handoff', 403);
    if (record.contextTokenHash) {
      fail('handoff_context_unavailable', 'Context already bound; cancel and restart with a new handoff', 409);
    }
    if (!input || typeof input.keyId !== 'string' || !input.keyId ||
      input.siwe !== record.request.siwe || input.host !== record.request.host ||
      digestJwk(input.jwk) !== digestJwk(record.request.jwk) ||
      digestJwk(input.presentation ?? null) !== digestJwk(record.request.presentation ?? null) ||
      input.reportedOrigin !== undefined ||
      (record.request.keyId && input.keyId !== record.request.keyId)) {
      fail('binding_mismatch', 'Signing request differs from prepared handoff', 403);
    }
    return record.ticketHash;
  }

  async bindContext(ticket: string, userId: string, binding: {
    keyId: string; siwe: string; jwk: unknown; host: string; authorizationContextToken: string;
  }): Promise<void> {
    const record = await this.active(ticket);
    if (record.ownerId !== userId) fail('handoff_claimed', 'Handoff not claimed by this user', 403);
    if ('kind' in record.request) fail('binding_mismatch', 'Signing context differs from prepared request', 403);
    if (!binding || typeof binding.authorizationContextToken !== 'string' || !binding.authorizationContextToken ||
      typeof binding.keyId !== 'string' || !binding.keyId ||
      binding.siwe !== record.request.siwe || binding.host !== record.request.host ||
      digestJwk(binding.jwk) !== digestJwk(record.request.jwk) ||
      (record.request.keyId && binding.keyId !== record.request.keyId)) fail('binding_mismatch', 'Signing context differs from prepared request', 403);
    const contextHash = digest(binding.authorizationContextToken);
    if (record.contextTokenHash && (record.contextTokenHash !== contextHash || record.selectedKeyId !== binding.keyId)) {
      fail('binding_mismatch', 'Handoff already bound to another context', 403);
    }
    if (!record.contextTokenHash && !await this.store.bind(record.ticketHash, userId, contextHash, binding.keyId, this.now())) {
      fail('handoff_context_unavailable', 'Context already bound; cancel and restart with a new handoff', 409);
    }
  }

  async assertContext(ticket: string, userId: string, contextToken: string): Promise<PreparedHandoffRecord> {
    const record = await this.active(ticket);
    if (record.ownerId !== userId) fail('handoff_claimed', 'Handoff not claimed by this user', 403);
    if (!contextToken || record.contextTokenHash !== digest(contextToken)) fail('binding_mismatch', 'Signing context differs from handoff', 403);
    return record;
  }

  async reserveSigning(ticket: string, userId: string, contextToken: string, keyId: string): Promise<void> {
    const record = await this.assertContext(ticket, userId, contextToken);
    if (record.selectedKeyId !== keyId) fail('binding_mismatch', 'Signer key differs from handoff', 403);
    if (!await this.store.reserve(record.ticketHash, userId, digest(contextToken), keyId, this.now())) {
      await this.active(ticket);
      fail('handoff_consumed', 'Handoff already signed', 409);
    }
  }

  // Only the successful signing path calls this; no HTTP endpoint retrieves results by ticket.
  async completeSigning(ticket: string, userId: string, contextToken: string, keyId: string) {
    if (!opaque(ticket)) fail('handoff_not_found', 'Handoff not found', 404);
    const record = await this.store.find(digest(ticket));
    if (!record || record.status !== 'CONSUMED' || record.ownerId !== userId ||
      record.contextTokenHash !== digest(contextToken) || record.selectedKeyId !== keyId) {
      fail('binding_mismatch', 'Handoff signing context is invalid', 403);
    }
    return { deliveryState: record.state, selectedKeyId: keyId };
  }

  async cancelClaimed(ticket: string, userId: string): Promise<void> {
    const record = await this.active(ticket);
    if (!userId || record.ownerId !== userId) fail('handoff_claimed', 'Handoff not claimed by this user', 403);
    if (!await this.store.cancel(record.ticketHash, this.now(), userId)) {
      await this.active(ticket);
      fail('handoff_consumed', 'Handoff already signed', 409);
    }
  }

  async cancel(ticket: string, cancelSecret: string): Promise<void> {
    const record = await this.active(ticket);
    const provided = typeof cancelSecret === 'string' ? digest(cancelSecret) : digest('');
    if (!timingSafeEqual(Buffer.from(provided, 'hex'), Buffer.from(record.cancelSecretHash, 'hex'))) {
      fail('invalid_cancel_secret', 'Invalid cancellation secret', 403);
    }
    if (!await this.store.cancel(record.ticketHash, this.now())) {
      await this.active(ticket);
      fail('handoff_consumed', 'Handoff already signed', 409);
    }
  }
}

export class MemoryPreparedHandoffStore implements PreparedHandoffStore {
  private readonly records = new Map<string, PreparedHandoffRecord>();
  async createLimited(record: PreparedHandoffRecord, since: Date, limit: number) {
    let count = 0;
    for (const current of this.records.values()) {
      if (current.ticketHash === record.ticketHash ||
        (current.ownerId === record.ownerId && current.nonceHash === record.nonceHash)) return current;
      if (current.ownerId === record.ownerId && current.requestedAt >= since) count++;
    }
    if (count >= limit) return null;
    this.records.set(record.ticketHash, record);
    return record;
  }
  async find(hash: string) { return this.records.get(hash) ?? null; }
  async bind(hash: string, userId: string, tokenHash: string, keyId: string, now: Date) {
    const r = this.records.get(hash);
    if (!r || r.status !== 'PENDING' || r.ownerId !== userId || r.contextTokenHash || r.expiresAt <= now) return false;
    r.contextTokenHash = tokenHash;
    r.selectedKeyId = keyId;
    return true;
  }
  async reserve(hash: string, userId: string, tokenHash: string, keyId: string, now: Date) {
    const r = this.records.get(hash);
    if (!r || r.status !== 'PENDING' || r.ownerId !== userId || r.contextTokenHash !== tokenHash || r.selectedKeyId !== keyId || r.expiresAt <= now) return false;
    r.status = 'CONSUMED';
    return true;
  }
  async cancel(hash: string, now: Date, ownerId?: string) {
    const r = this.records.get(hash);
    if (!r || r.status !== 'PENDING' || r.expiresAt <= now || (ownerId !== undefined && r.ownerId !== ownerId)) return false;
    r.status = 'CANCELLED';
    return true;
  }
}
