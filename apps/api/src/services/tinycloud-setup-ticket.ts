// TC-3657 Bobbie C1 (14:32:09Z): one-time setup ticket for the outside-app
// registry publish flow. Minted when the widget page renders; verified by
// the `/authorize-tinycloud-setup` POST before the server signs/publishes.
//
// Binding (ALL required): owner session, verified requesting origin (derived
// by the widget from `window.opener.origin` and sent on mint), record hash
// (hex sha256 of the canonical location payload bytes the server is about
// to sign), a short TTL, and single-use.
//
// Persistence (Naomi 15:12:55Z): consumed nonces live in Postgres via Prisma
// (`TinyCloudSetupConsumedNonce`) so the single-use invariant survives API
// restarts AND is global across API replicas. A replayed ticket from a
// second replica still refuses because the first replica's consume inserted
// the nonce row. Ticket-signature verification is the first gate; the DB
// insert is the second. An in-memory implementation is retained for tests
// and local development (used when no PrismaClient is injected).

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';

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

export interface DecodedSetupTicket {
  readonly subject: string;
  readonly verifiedRequestingOrigin: string;
  readonly recordHash: string;
  readonly mintedAt: Date;
}

export interface SetupTicketStore {
  /** Signs an opaque ticket bound to the inputs + a fresh server-minted nonce. Pure (no I/O). */
  mint(binding: SetupTicketBinding, now: Date): string;
  /** Signature-verifies the ticket + returns its payload WITHOUT TTL or binding checks (so the
   *  caller can read `mintedAt` to rebuild the canonical payload the ticket was bound to).
   *  Throws SetupTicketError on a malformed or forged ticket. Does NOT consume the nonce. */
  decode(ticket: string): DecodedSetupTicket;
  /** Verifies the ticket's signature, TTL, binding, and single-use. Atomic with respect to the
   *  nonce insert (DB unique constraint). Throws SetupTicketError on any failure. */
  consume(ticket: string, expected: SetupTicketBinding, now: Date): Promise<void>;
}

interface SignedTicketPayload {
  v: 1;                  // envelope version
  nonce: string;         // base64url, 32 bytes, unique per mint
  subject: string;       // owner did:pkh
  origin: string;        // verifiedRequestingOrigin
  recordHash: string;    // hex sha256
  mintedAtMs: number;    // epoch ms
}

/** Minimal persistence surface. The default is Prisma-backed (durable, replica-safe).
 *  Tests inject their own to assert behaviour without a running DB. */
export interface SetupNonceStore {
  /** Returns true if the nonce was inserted now (first use); false if already present. */
  insertIfAbsent(nonce: string, subject: string, mintedAt: Date): Promise<boolean>;
}

export function prismaSetupNonceStore(prisma: PrismaClient): SetupNonceStore {
  return {
    async insertIfAbsent(nonce, subject, mintedAt) {
      try {
        await prisma.tinyCloudSetupConsumedNonce.create({
          data: { nonce, subject, mintedAt },
        });
        return true;
      } catch (error) {
        // P2002 is the Prisma unique-constraint violation; the row already exists.
        if (error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'P2002') {
          return false;
        }
        throw error;
      }
    },
  };
}

/** In-memory nonce store used by unit tests and local dev. Not safe across restarts or
 *  replicas; production must use `prismaSetupNonceStore`. */
export function createInMemorySetupNonceStore(): SetupNonceStore {
  const seen = new Set<string>();
  return {
    async insertIfAbsent(nonce) {
      if (seen.has(nonce)) return false;
      seen.add(nonce);
      return true;
    },
  };
}

export function createSetupTicketStore(signingSecret: Uint8Array, nonceStore: SetupNonceStore): SetupTicketStore {
  if (signingSecret.byteLength < 32) {
    throw new Error('setup ticket signing secret must be at least 32 bytes');
  }
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
  const decodeTicket = (ticket: string): SignedTicketPayload => {
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
    try { payload = JSON.parse(payloadJson); }
    catch { throw new SetupTicketError('malformed_ticket', 'ticket payload is not JSON', 400); }
    if (!isSignedTicketPayload(payload)) {
      throw new SetupTicketError('malformed_ticket', 'ticket payload has the wrong shape', 400);
    }
    return payload;
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
    decode(ticket) {
      const payload = decodeTicket(ticket);
      return {
        subject: payload.subject,
        verifiedRequestingOrigin: payload.origin,
        recordHash: payload.recordHash,
        mintedAt: new Date(payload.mintedAtMs),
      };
    },
    async consume(ticket, expected, now) {
      const payload = decodeTicket(ticket);
      const nowMs = now.getTime();
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
      const fresh = await nonceStore.insertIfAbsent(payload.nonce, payload.subject, new Date(payload.mintedAtMs));
      if (!fresh) {
        throw new SetupTicketError('already_used', 'ticket has already been consumed', 409);
      }
    },
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
