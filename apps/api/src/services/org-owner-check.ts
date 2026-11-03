import { compactVerify, importJWK } from 'jose';
import {
  canonicalBytes, createIssuerMethodResolver, decodeObject, exactFields, issuerEd25519Jwk,
  ISSUER_DID, type IssuerFetch,
} from './issuer-jws';

// TC-128 OK-1 (contract v3 section 1): OpenCredentials signs one short-lived JWS per question with its credential
// ISSUER key, "is `account` an owner of org key `keyId`?". OpenKey does its own time checks: the registration
// intent verifier deliberately skips expiry, this one must not.

export const ORG_OWNER_CHECK_PATH = '/api/internal/org-owner-check';
const AUDIENCE = 'https://api.openkey.so';
const PURPOSE = 'org-owner-check/v1';
const TYP = 'org-owner-check+jwt';
const MAX_TOKEN_LENGTH = 2048;
const MAX_LIFETIME_SECONDS = 60;
const MAX_IAT_SKEW_SECONDS = 5;
const CLAIM_NAMES = ['iss', 'aud', 'purpose', 'keyId', 'account', 'jti', 'iat', 'exp'];
const ACCOUNT = /^0x[0-9a-f]{40}$/;

export interface OrgOwnerCheckClaims {
  keyId: string;
  account: string;
}

/** The token is not an acceptable owner-check JWS. Carries no detail: every cause answers 401 alike. */
export class OrgOwnerCheckUnauthorized extends Error {}

function boundedString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128;
}

export function createOrgOwnerCheckVerifier(fetcher?: IssuerFetch) {
  const resolveMethod = createIssuerMethodResolver(fetcher);
  return async (authorization: string | undefined): Promise<OrgOwnerCheckClaims> => {
    const token = authorization?.startsWith('Bearer ') ? authorization.slice('Bearer '.length) : undefined;
    let header: Record<string, unknown>;
    let claims: Record<string, unknown>;
    try {
      if (!token || token.length > MAX_TOKEN_LENGTH) throw new Error('Missing or oversized token');
      const segments = token.split('.');
      if (segments.length !== 3 || !canonicalBytes(segments[2], 64)) throw new Error('Malformed compact JWS');
      header = decodeObject(segments[0]!);
      if (!exactFields(header, ['alg', 'kid', 'typ']) || header.alg !== 'EdDSA' || header.typ !== TYP
        || typeof header.kid !== 'string' || header.kid.length > 256 || !header.kid.startsWith(`${ISSUER_DID}#`)) {
        throw new Error('Invalid owner-check header');
      }
      claims = decodeObject(segments[1]!);
      if (!exactFields(claims, CLAIM_NAMES) || claims.iss !== ISSUER_DID || claims.aud !== AUDIENCE || claims.purpose !== PURPOSE
        || !boundedString(claims.keyId) || typeof claims.account !== 'string' || !ACCOUNT.test(claims.account) || !boundedString(claims.jti)
        || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)) {
        throw new Error('Invalid owner-check claims');
      }
      const now = Math.floor(Date.now() / 1000);
      const iat = claims.iat as number;
      const exp = claims.exp as number;
      if (exp <= iat || exp - iat > MAX_LIFETIME_SECONDS || iat > now + MAX_IAT_SKEW_SECONDS || exp <= now) {
        throw new Error('Owner-check token is outside its validity window');
      }
    } catch {
      throw new OrgOwnerCheckUnauthorized();
    }
    // IssuerDidUnavailable propagates: an unreadable issuer DID is not an authentication verdict.
    const issuerKey = issuerEd25519Jwk(await resolveMethod(header.kid as string));
    if ('refusal' in issuerKey) throw new OrgOwnerCheckUnauthorized();
    try {
      await compactVerify(token!, await importJWK(issuerKey.jwk, 'EdDSA'), { algorithms: ['EdDSA'] });
    } catch {
      throw new OrgOwnerCheckUnauthorized();
    }
    return { keyId: claims.keyId as string, account: claims.account as string };
  };
}
