export const PUBLIC_DELEGATION_FIELDS = [
  'delegationHeader', 'delegationCid', 'spaceId', 'ownerDid', 'verificationMethod', 'jwk',
  'address', 'chainId', 'hostActivated', 'spaceReady', 'spaceError', 'spacePending',
  'primary', 'edited', 'reason', 'expirationTime', 'expiresAt', 'expiry', 'siwe',
  'signature', 'signedMessage', 'permissions',
] as const;
export const PUBLIC_JWK_FIELDS = ['kty', 'crv', 'x', 'kid'] as const;
export const NEVER_SENT_TO_BROKER_FIELDS = ['requestedSpaces'] as const;

export function publicDelegationForCode(payload: Record<string, unknown>): Record<string, unknown> {
  const publicDelegation: Record<string, unknown> = {};
  for (const field of PUBLIC_DELEGATION_FIELDS) {
    if (field in payload) publicDelegation[field] = payload[field];
  }
  const jwk = publicDelegation.jwk;
  if (typeof jwk === 'object' && jwk !== null && !Array.isArray(jwk)) {
    const prototype = Object.getPrototypeOf(jwk);
    if (prototype === Object.prototype || prototype === null) {
      const publicJwk: Record<string, unknown> = {};
      for (const field of PUBLIC_JWK_FIELDS) {
        if (Object.hasOwn(jwk, field)) publicJwk[field] = (jwk as Record<string, unknown>)[field];
      }
      publicDelegation.jwk = publicJwk;
    }
  }
  return publicDelegation;
}
