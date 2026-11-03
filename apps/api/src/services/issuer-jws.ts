import type { JWK } from 'jose';

// Shared by every verifier of a JWS signed by the pinned OpenCredentials issuer key
// (the registration intent and the org-owner check). Only the pinned issuer DID can supply keys.

export const ISSUER_DID = 'did:web:issuer.credentials.org';
const ISSUER_DID_URL = 'https://issuer.credentials.org/.well-known/did.json';
const DID_CACHE_MS = 5 * 60 * 1000;
const FORCED_REFRESH_INTERVAL_MS = 10_000;
const utf8 = new TextDecoder('utf-8', { fatal: true });

export type IssuerFetch = (url: string, init?: RequestInit) => Promise<Response>;

/** The issuer DID document could not be fetched or is malformed. */
export class IssuerDidUnavailable extends Error {}

export function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
export function exactFields(value: Record<string, unknown>, names: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === names.length && keys.every((key) => names.includes(key));
}
export function canonicalBytes(value: unknown, length: number): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === length && bytes.toString('base64url') === value;
}
/** Same duplicate-member detection pattern as app-key-refusal.ts; never accept JSON.parse's last-wins ambiguity. */
export function strictJson(text: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(text);
  if (!object(parsed)) throw new Error('Expected a JSON object');
  const objects: Array<Set<string> | null> = [];
  let expectKey = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      const keys = objects[objects.length - 1];
      if (keys && expectKey) {
        const key = JSON.parse(text.slice(i, end + 1)) as string;
        if (keys.has(key)) throw new Error('Repeated JSON member');
        keys.add(key);
        expectKey = false;
      }
      i = end + 1;
      continue;
    }
    if (ch === '{') {
      objects.push(new Set());
      expectKey = true;
    } else if (ch === '[') {
      objects.push(null);
      expectKey = false;
    } else if (ch === '}' || ch === ']') {
      objects.pop();
      expectKey = false;
    } else if (ch === ',') {
      expectKey = objects[objects.length - 1] instanceof Set;
    }
    i += 1;
  }
  return parsed;
}
export function decodeObject(segment: string): Record<string, unknown> {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Error('Noncanonical JWS encoding');
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) throw new Error('Noncanonical JWS encoding');
  return strictJson(utf8.decode(bytes));
}

/**
 * Resolves a verification method of the pinned issuer DID. The kid never selects an outbound URL.
 * An unknown kid forces at most one DID refresh per FORCED_REFRESH_INTERVAL_MS.
 * Resolves undefined when the issuer does not assert the kid; throws IssuerDidUnavailable when the DID cannot be read.
 */
export function createIssuerMethodResolver(fetcher: IssuerFetch = fetch): (kid: string) => Promise<Record<string, unknown> | undefined> {
  let document: Record<string, unknown> | undefined;
  let expiresAt = 0;
  let inFlight: Promise<void> | undefined;
  let lastForcedRefresh = Number.NEGATIVE_INFINITY;
  async function refresh(forced: boolean): Promise<void> {
    if (inFlight) return inFlight;
    const now = Date.now();
    if (forced && now - lastForcedRefresh < FORCED_REFRESH_INTERVAL_MS) return;
    if (forced) lastForcedRefresh = now;
    inFlight = (async () => {
      try {
        const response = await fetcher(ISSUER_DID_URL, { redirect: 'error', cache: forced ? 'no-store' : 'default', signal: AbortSignal.timeout(10_000) });
        if (!response.ok || response.status >= 300) throw new Error('Issuer DID unavailable');
        const text = await response.text();
        const parsed = strictJson(text);
        if (parsed.id !== ISSUER_DID || !Array.isArray(parsed.verificationMethod) || !Array.isArray(parsed.assertionMethod)) {
          throw new Error('Issuer DID is malformed');
        }
        document = parsed;
        expiresAt = Date.now() + DID_CACHE_MS;
      } catch {
        throw new IssuerDidUnavailable('Issuer DID unavailable');
      }
    })();
    try { await inFlight; } finally { inFlight = undefined; }
  }
  function methodFor(keyId: string): Record<string, unknown> | undefined {
    if (!document) return undefined;
    const assertions = document.assertionMethod as unknown[];
    const asserted = assertions.some((method) => method === keyId || (object(method) && method.id === keyId));
    if (!asserted) return undefined;
    const methods = (document.verificationMethod as unknown[]).filter((method) => object(method) && method.id === keyId);
    return methods.length === 1 ? methods[0] as Record<string, unknown> : undefined;
  }
  return async (kid: string) => {
    if (!document || expiresAt <= Date.now()) await refresh(false);
    let method = methodFor(kid);
    if (!method) { await refresh(true); method = methodFor(kid); }
    return method;
  };
}

export type IssuerKeyRefusal = 'not_asserted' | 'invalid_key';

/** The Ed25519 public JWK of an issuer-asserted method, or the reason it cannot verify. */
export function issuerEd25519Jwk(method: Record<string, unknown> | undefined): { jwk: JWK } | { refusal: IssuerKeyRefusal } {
  if (!method || method.controller !== ISSUER_DID || !object(method.publicKeyJwk)) return { refusal: 'not_asserted' };
  const jwk = method.publicKeyJwk;
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !canonicalBytes(jwk.x, 32) || 'd' in jwk
    || (jwk.alg !== undefined && jwk.alg !== 'EdDSA')) {
    return { refusal: 'invalid_key' };
  }
  return { jwk: jwk as JWK };
}
