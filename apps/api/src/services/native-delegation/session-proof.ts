import { createHash, createPublicKey, verify } from 'node:crypto';

/**
 * `OpenKey-Session-Proof` verification (spec: "Session proof"). The proof is
 * checked only against the session key stored at PAR; a key supplied with the
 * request is never used. Replay is prevented by single-use credentials
 * consumed under lock, so `jti` is shape-checked but not remembered.
 */

export const SESSION_PROOF_TYP = 'openkey-session-proof+jwt';
export const SESSION_PROOF_MAX_SKEW_SECONDS = 60;

const SEGMENT = /^[A-Za-z0-9_-]+$/;
const HEADER_KEYS = ['alg', 'kid', 'typ'];
const PAYLOAD_KEYS = ['client_id', 'cred_hash', 'htm', 'htu', 'iat', 'jti'];

export interface SessionProofExpectation {
  /** The public Ed25519 JWK stored at PAR. */
  sessionJwk: { x: string };
  /** The stored RFC 7638 thumbprint; the proof's `kid` must equal it. */
  sessionJkt: string;
  /** `BETTER_AUTH_URL` + `/api/auth` + the endpoint path. */
  htu: string;
  clientId: string;
  /** The literal `code` or `refresh_token` the proof binds. */
  credential: string;
}

export function credentialHash(credential: string): string {
  return createHash('sha256').update(credential).digest('base64url');
}

function decodeObject(segment: string, keys: string[]): Record<string, unknown> | null {
  let value: unknown;
  try { value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const present = Object.keys(value).sort();
  if (present.length !== keys.length || present.some((key, index) => key !== keys[index])) return null;
  return value as Record<string, unknown>;
}

/** True only for a proof that satisfies every rule in the spec. */
export function verifySessionProof(
  proof: string | null | undefined,
  expected: SessionProofExpectation,
  nowMs = Date.now(),
): boolean {
  if (typeof proof !== 'string') return false;
  const parts = proof.split('.');
  if (parts.length !== 3 || parts.some((part) => !SEGMENT.test(part))) return false;
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];

  const header = decodeObject(encodedHeader, HEADER_KEYS);
  if (!header || header.typ !== SESSION_PROOF_TYP || header.alg !== 'EdDSA' || header.kid !== expected.sessionJkt) return false;

  const payload = decodeObject(encodedPayload, PAYLOAD_KEYS);
  if (!payload) return false;
  const { jti, iat, htm, htu, client_id: clientId, cred_hash: credHash } = payload;
  if (typeof jti !== 'string' || jti.length < 16 || jti.length > 128) return false;
  if (typeof iat !== 'number' || !Number.isInteger(iat) ||
    Math.abs(nowMs / 1000 - iat) > SESSION_PROOF_MAX_SKEW_SECONDS) return false;
  if (htm !== 'POST' || htu !== expected.htu || clientId !== expected.clientId) return false;
  if (credHash !== credentialHash(expected.credential)) return false;

  const signature = Buffer.from(encodedSignature, 'base64url');
  if (signature.length !== 64 || signature.toString('base64url') !== encodedSignature) return false;
  const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: expected.sessionJwk.x }, format: 'jwk' });
  return verify(null, Buffer.from(`${encodedHeader}.${encodedPayload}`, 'ascii'), publicKey, signature);
}
