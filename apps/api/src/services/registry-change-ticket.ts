// TC-3893: single-use HMAC ticket (`changeId`) for the registry-change flow.
//
// Reuses the durable Prisma nonce table (`TinyCloudSetupConsumedNonce`) via the `rc:`
// nonce prefix and domain-separates the HMAC key + `purpose: 'registry_change'` field
// so setup tickets and registry-change tickets can never cross-verify.
//
// Binding: owner subject, verified requesting origin, current sequence + beforeHash,
// canonical prepared payload + recordHash, short TTL, and single-use nonce.

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { SetupNonceStore } from './tinycloud-setup-ticket';

export const REGISTRY_CHANGE_TICKET_TTL_MS = 5 * 60_000;
export const REGISTRY_CHANGE_TICKET_PURPOSE = 'registry_change';
export const REGISTRY_CHANGE_NONCE_PREFIX = 'rc:';

const TICKET_KEY_DOMAIN = 'openkey:registry-change-ticket:v1';
const MAX_CANONICAL_PAYLOAD_BYTES = 64 * 1024;

export interface RegistryChangeTicketBinding {
  readonly subject: string;
  readonly verifiedRequestingOrigin: string;
  readonly currentSequence: number;
  readonly beforeHash: string;
  readonly recordHash: string;
  readonly payloadCanonical: string;
}

export interface DecodedRegistryChangeTicket extends RegistryChangeTicketBinding {
  readonly nonce: string;
  readonly mintedAt: Date;
}

export class RegistryChangeTicketError extends Error {
  readonly status: 400 | 403 | 409 | 410;
  constructor(public readonly code: string, message: string, status: 400 | 403 | 409 | 410) {
    super(message);
    this.name = 'RegistryChangeTicketError';
    this.status = status;
  }
}

export interface RegistryChangeTicketStore {
  mint(binding: RegistryChangeTicketBinding, now: Date): string;
  /** Verifies HMAC + payload shape + recordHash integrity WITHOUT consuming the nonce. */
  decode(ticket: string): DecodedRegistryChangeTicket;
  /** Verifies HMAC, TTL, binding, and atomically consumes the single-use nonce. */
  consume(
    ticket: string,
    expected: Pick<RegistryChangeTicketBinding, 'subject' | 'verifiedRequestingOrigin' | 'recordHash' | 'currentSequence'>,
    now: Date,
  ): Promise<DecodedRegistryChangeTicket>;
}

interface SignedRegistryChangeTicketPayload {
  v: 1;
  purpose: typeof REGISTRY_CHANGE_TICKET_PURPOSE;
  nonce: string;
  subject: string;
  origin: string;
  currentSequence: number;
  beforeHash: string;
  recordHash: string;
  payloadCanonical: string;
  mintedAtMs: number;
}

export function createRegistryChangeTicketStore(
  signingSecret: Uint8Array,
  nonceStore: SetupNonceStore,
): RegistryChangeTicketStore {
  if (signingSecret.byteLength < 32) {
    throw new Error('registry change ticket signing secret must be at least 32 bytes');
  }
  // Domain-separate from the setup ticket key so the two ticket types can never verify interchangeably.
  const derivedKey = createHmac('sha256', signingSecret).update(TICKET_KEY_DOMAIN).digest();

  const sign = (payloadJson: string): string =>
    createHmac('sha256', derivedKey).update(payloadJson).digest('base64url');

  const verify = (payloadJson: string, mac: string): boolean => {
    const expected = Buffer.from(sign(payloadJson), 'base64url');
    const actual = Buffer.from(mac, 'base64url');
    if (expected.byteLength !== actual.byteLength) return false;
    return timingSafeEqual(expected, actual);
  };

  const decodeTicket = (ticket: string): SignedRegistryChangeTicketPayload => {
    let outer: unknown;
    try {
      outer = JSON.parse(Buffer.from(ticket, 'base64url').toString('utf8'));
    } catch {
      throw new RegistryChangeTicketError('malformed_ticket', 'changeId is not base64url-encoded JSON', 400);
    }
    if (!Array.isArray(outer) || outer.length !== 2 || typeof outer[0] !== 'string' || typeof outer[1] !== 'string') {
      throw new RegistryChangeTicketError('malformed_ticket', 'changeId envelope must be a [payload, mac] pair', 400);
    }
    const [payloadJson, mac] = outer as [string, string];
    if (!verify(payloadJson, mac)) {
      throw new RegistryChangeTicketError('bad_signature', 'changeId signature does not verify', 403);
    }
    let payload: unknown;
    try {
      payload = JSON.parse(payloadJson);
    } catch {
      throw new RegistryChangeTicketError('malformed_ticket', 'changeId payload is not JSON', 400);
    }
    if (!isSignedRegistryChangePayload(payload)) {
      throw new RegistryChangeTicketError('malformed_ticket', 'changeId payload has the wrong shape', 400);
    }
    const computedHash = createHash('sha256').update(payload.payloadCanonical, 'utf8').digest('hex');
    if (computedHash !== payload.recordHash) {
      throw new RegistryChangeTicketError('record_mismatch', 'changeId payload does not match recordHash', 403);
    }
    return payload;
  };

  const toDecoded = (payload: SignedRegistryChangeTicketPayload): DecodedRegistryChangeTicket => ({
    nonce: payload.nonce,
    subject: payload.subject,
    verifiedRequestingOrigin: payload.origin,
    currentSequence: payload.currentSequence,
    beforeHash: payload.beforeHash,
    recordHash: payload.recordHash,
    payloadCanonical: payload.payloadCanonical,
    mintedAt: new Date(payload.mintedAtMs),
  });

  return {
    mint(binding, now) {
      const payload: SignedRegistryChangeTicketPayload = {
        v: 1,
        purpose: REGISTRY_CHANGE_TICKET_PURPOSE,
        nonce: randomBytes(32).toString('base64url'),
        subject: binding.subject,
        origin: binding.verifiedRequestingOrigin,
        currentSequence: binding.currentSequence,
        beforeHash: binding.beforeHash,
        recordHash: binding.recordHash,
        payloadCanonical: binding.payloadCanonical,
        mintedAtMs: now.getTime(),
      };
      const payloadJson = JSON.stringify(payload);
      const mac = sign(payloadJson);
      return Buffer.from(JSON.stringify([payloadJson, mac]), 'utf8').toString('base64url');
    },

    decode(ticket) {
      return toDecoded(decodeTicket(ticket));
    },

    async consume(ticket, expected, now) {
      const payload = decodeTicket(ticket);
      if (now.getTime() - payload.mintedAtMs > REGISTRY_CHANGE_TICKET_TTL_MS) {
        throw new RegistryChangeTicketError('expired_ticket', 'changeId has expired', 410);
      }
      if (payload.subject !== expected.subject) {
        throw new RegistryChangeTicketError('subject_mismatch', 'changeId subject does not match session owner', 403);
      }
      if (payload.origin !== expected.verifiedRequestingOrigin) {
        throw new RegistryChangeTicketError('origin_mismatch', 'changeId origin does not match', 403);
      }
      if (payload.recordHash !== expected.recordHash) {
        throw new RegistryChangeTicketError('record_mismatch', 'changeId record hash does not match', 403);
      }
      if (payload.currentSequence !== expected.currentSequence) {
        throw new RegistryChangeTicketError('registry_change_stale', 'changeId sequence is stale', 409);
      }
      const prefixedNonce = `${REGISTRY_CHANGE_NONCE_PREFIX}${payload.nonce}`;
      const fresh = await nonceStore.insertIfAbsent(prefixedNonce, payload.subject, new Date(payload.mintedAtMs));
      if (!fresh) {
        throw new RegistryChangeTicketError('already_used', 'changeId has already been consumed', 409);
      }
      return toDecoded(payload);
    },
  };
}

function isSignedRegistryChangePayload(value: unknown): value is SignedRegistryChangeTicketPayload {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return v.v === 1 &&
    v.purpose === REGISTRY_CHANGE_TICKET_PURPOSE &&
    typeof v.nonce === 'string' && v.nonce.length > 0 &&
    typeof v.subject === 'string' && v.subject.startsWith('did:pkh:') &&
    typeof v.origin === 'string' && v.origin.length > 0 &&
    typeof v.currentSequence === 'number' && Number.isSafeInteger(v.currentSequence) && v.currentSequence >= 0 &&
    typeof v.beforeHash === 'string' && /^[0-9a-f]{64}$/.test(v.beforeHash) &&
    typeof v.recordHash === 'string' && /^[0-9a-f]{64}$/.test(v.recordHash) &&
    typeof v.payloadCanonical === 'string' &&
    v.payloadCanonical.length > 0 &&
    Buffer.byteLength(v.payloadCanonical, 'utf8') <= MAX_CANONICAL_PAYLOAD_BYTES &&
    typeof v.mintedAtMs === 'number' && Number.isFinite(v.mintedAtMs);
}
