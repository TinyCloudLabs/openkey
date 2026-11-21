// TC-3657 Bobbie C1 (14:32:09Z): one-time setup ticket for the outside-app
// registry publish flow. Minted when the widget page renders; verified by
// the `/authorize-tinycloud-setup` POST before the server signs/publishes.
//
// Binding (ALL required): owner session, verified requesting origin
// (derived by the widget from `window.opener.origin` and re-asserted
// server-side on mint), record hash (hex sha256 of the canonical location
// payload bytes the server is about to sign), a short TTL, and single-use.
//
// Attack this closes: an outside page that holds the OpenKey session
// cookie cannot POST directly without a ticket. The ticket only exists
// after the widget page rendered in the OpenKey origin, so even a
// session-bearing cross-origin request without a ticket returns 403 (test
// `cross-origin POST with valid session but no ticket is refused` in
// `__tests__/tinycloud-setup.test.ts`).
//
// Store shape today: HMAC-signed opaque ticket + an in-process Map tracking
// consumed nonces. This is a DRAFT; the production replacement (likely
// Prisma-backed, following `approval-request-store.ts`) is a follow-up on
// this ticket — flagged in the design note and this file's TODO below. The
// signature + single-use invariant is enforced by the current code; the
// Prisma swap is a resilience upgrade, not a security-boundary move.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** TC-3657: tight TTL for the ticket, measured from mint. 5 minutes bounds how long
 * the consent screen can sit open before the owner's tap stops working. */
export const SETUP_TICKET_TTL_MS = 5 * 60_000;

export interface SetupTicketBinding {
  /** Owner's `did:pkh`; must match the session's owner at both mint and verify. */
  readonly subject: string;
  /** Browser-derived requesting origin from the OPENER (Bobbie C3). Never from the request body. */
  readonly verifiedRequestingOrigin: string;
  /** Hex sha256 of the canonical LocationRecordV2Payload bytes the server will sign + publish. */
  readonly recordHash: string;
}

export class SetupTicketError extends Error {
  readonly status: 400 | 403 | 409 | 410;
  constructor(public readonly code: string, message: string, status: 400 | 403 | 409 | 410) {
    super(message);
    this.name = 'SetupTicketError';
    this.status = status;
  }
}

export interface SetupTicketStore {
  /** Returns a signed opaque ticket bound to the inputs + a fresh server-minted nonce.
   *  Mint cannot fail for well-formed inputs; it never contacts storage. */
  mint(binding: SetupTicketBinding, now: Date): string;
  /** Verifies the ticket opens to the same binding, is unexpired, and has not been consumed.
   *  Consumes the nonce (single-use) on success; throws SetupTicketError on failure. */
  consume(ticket: string, expected: SetupTicketBinding, now: Date): void;
  /** Size of the consumed-nonce set, for test assertions only. */
  readonly consumedSize: number;
}

interface SignedTicketPayload {
  v: 1;                  // envelope version
  nonce: string;         // base64url, 32 bytes, unique per mint
  subject: string;       // owner did:pkh
  origin: string;        // verifiedRequestingOrigin
  recordHash: string;    // hex sha256
  mintedAtMs: number;    // epoch ms
}

/** Writes nothing to disk. Consumed-nonce retention is limited to one TTL window because a
 *  nonce older than TTL_MS is already expired and cannot pass verification; purging anything
 *  older is safe. The purge runs opportunistically on consume() calls to bound memory. */
export function createSetupTicketStore(signingSecret: Uint8Array): SetupTicketStore {
  if (signingSecret.byteLength < 32) {
    throw new Error('setup ticket signing secret must be at least 32 bytes');
  }
  const consumedNonces = new Map<string, number>(); // nonce -> mintedAtMs
  let lastPurgeMs = 0;
  const purgeIfStale = (nowMs: number): void => {
    if (nowMs - lastPurgeMs < SETUP_TICKET_TTL_MS) return;
    lastPurgeMs = nowMs;
    const cutoffMs = nowMs - SETUP_TICKET_TTL_MS;
    for (const [nonce, mintedAtMs] of consumedNonces) {
      if (mintedAtMs < cutoffMs) consumedNonces.delete(nonce);
    }
  };
  const sign = (payloadJson: string): string =>
    createHmac('sha256', signingSecret).update(payloadJson).digest('base64url');
  const verify = (payloadJson: string, mac: string): boolean => {
    const expected = Buffer.from(sign(payloadJson), 'base64url');
    const actual = Buffer.from(mac, 'base64url');
    if (expected.byteLength !== actual.byteLength) return false;
    return timingSafeEqual(expected, actual);
  };
  const encodeTicket = (payload: SignedTicketPayload): string => {
    const payloadJson = JSON.stringify(payload);
    const mac = sign(payloadJson);
    return Buffer.from(JSON.stringify([payloadJson, mac]), 'utf8').toString('base64url');
  };
  const decodeTicket = (ticket: string): { payload: SignedTicketPayload; mac: string; payloadJson: string } => {
    let outer: unknown;
    try {
      outer = JSON.parse(Buffer.from(ticket, 'base64url').toString('utf8'));
    } catch {
      throw new SetupTicketError('malformed_ticket', 'ticket is not base64url-encoded JSON', 400);
    }
    if (!Array.isArray(outer) || outer.length !== 2 || typeof outer[0] !== 'string' || typeof outer[1] !== 'string') {
      throw new SetupTicketError('malformed_ticket', 'ticket envelope must be a [payload, mac] pair', 400);
    }
    const [payloadJson, mac] = outer as [string, string];
    if (!verify(payloadJson, mac)) {
      throw new SetupTicketError('bad_signature', 'ticket signature does not verify', 403);
    }
    let payload: unknown;
    try {
      payload = JSON.parse(payloadJson);
    } catch {
      throw new SetupTicketError('malformed_ticket', 'ticket payload is not JSON', 400);
    }
    if (!isSignedTicketPayload(payload)) {
      throw new SetupTicketError('malformed_ticket', 'ticket payload has the wrong shape', 400);
    }
    return { payload, mac, payloadJson };
  };
  return {
    mint(binding, now) {
      const payload: SignedTicketPayload = {
        v: 1,
        nonce: randomBytes(32).toString('base64url'),
        subject: binding.subject,
        origin: binding.verifiedRequestingOrigin,
        recordHash: binding.recordHash,
        mintedAtMs: now.getTime(),
      };
      return encodeTicket(payload);
    },
    consume(ticket, expected, now) {
      const nowMs = now.getTime();
      purgeIfStale(nowMs);
      const { payload } = decodeTicket(ticket);
      if (nowMs - payload.mintedAtMs > SETUP_TICKET_TTL_MS) {
        throw new SetupTicketError('expired_ticket', 'ticket has expired', 410);
      }
      if (payload.subject !== expected.subject) {
        throw new SetupTicketError('subject_mismatch', 'ticket subject does not match the session owner', 403);
      }
      if (payload.origin !== expected.verifiedRequestingOrigin) {
        throw new SetupTicketError('origin_mismatch', 'ticket origin does not match the verified requesting origin', 403);
      }
      if (payload.recordHash !== expected.recordHash) {
        throw new SetupTicketError('record_mismatch', 'ticket record hash does not match the payload being signed', 403);
      }
      if (consumedNonces.has(payload.nonce)) {
        throw new SetupTicketError('already_used', 'ticket has already been consumed', 409);
      }
      consumedNonces.set(payload.nonce, payload.mintedAtMs);
    },
    get consumedSize() { return consumedNonces.size; },
  };
}

function isSignedTicketPayload(value: unknown): value is SignedTicketPayload {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return v.v === 1 &&
    typeof v.nonce === 'string' && v.nonce.length > 0 &&
    typeof v.subject === 'string' && v.subject.startsWith('did:pkh:') &&
    typeof v.origin === 'string' && v.origin.length > 0 &&
    typeof v.recordHash === 'string' && /^[0-9a-f]{64}$/.test(v.recordHash) &&
    typeof v.mintedAtMs === 'number' && Number.isFinite(v.mintedAtMs);
}

// TODO(TC-3657 follow-up): swap in a Prisma-backed store (model after
// `approval-request-store.ts`) so consumed nonces survive restarts and the
// per-owner rate limit (see `tinycloud-setup-rate-limit.ts`) can share the same
// transaction. The signed-ticket shape itself stays as-is.
