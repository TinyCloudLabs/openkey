import { randomBytes } from 'node:crypto';
import type { TeeClient } from '@openkey/tee';

const SEALING_CONTEXT_BYTES = 32;
const SEALING_CONTEXT_LENGTH = 43;
const SEALING_CONTEXT_RE = /^[A-Za-z0-9_-]{43}$/;

/** A new context is exactly 256 bits of random, canonical base64url data. */
export function createSealingContext(): string {
  return randomBytes(SEALING_CONTEXT_BYTES).toString('base64url');
}

export function isValidSealingContext(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== SEALING_CONTEXT_LENGTH) return false;
  if (!SEALING_CONTEXT_RE.test(value)) return false;

  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.length === SEALING_CONTEXT_BYTES && decoded.toString('base64url') === value;
  } catch {
    return false;
  }
}

export function assertSealingContext(value: unknown): asserts value is string {
  if (!isValidSealingContext(value)) {
    throw new Error('Invalid sealing context');
  }
}

export type SealingContextKey = {
  userId: string;
  sealingContext?: string | null;
};

/**
 * NULL is the sole legacy marker. Empty, malformed, and non-canonical values
 * are rejected instead of silently selecting a different derivation path.
 */
export function resolveSealingContext(key: SealingContextKey): string {
  if (key.sealingContext === null || key.sealingContext === undefined) {
    return `openkey/user/${key.userId}/keys`;
  }

  assertSealingContext(key.sealingContext);
  return `openkey/key/${key.sealingContext}`;
}

export function deriveKeyForRecord(tee: TeeClient, key: SealingContextKey): Promise<Uint8Array> {
  return tee.deriveKey(resolveSealingContext(key));
}
