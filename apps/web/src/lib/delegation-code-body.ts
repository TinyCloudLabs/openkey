const PUBLIC_DELEGATION_FIELDS = [
  'delegationHeader', 'delegationCid', 'spaceId', 'ownerDid', 'verificationMethod', 'jwk',
  'address', 'chainId', 'hostActivated', 'spaceReady', 'spaceError', 'spacePending',
  'primary', 'edited', 'reason', 'expirationTime', 'expiresAt', 'expiry', 'siwe',
  'signature', 'signedMessage', 'permissions',
] as const;

// Keep in sync with PUBLIC_DELEGATION_FIELDS in apps/api/src/routes/delegation-codes.ts.
export function publicDelegationForCode(payload: Record<string, unknown>): Record<string, unknown> {
  const publicDelegation: Record<string, unknown> = {};
  for (const field of PUBLIC_DELEGATION_FIELDS) {
    if (field in payload) publicDelegation[field] = payload[field];
  }
  return publicDelegation;
}
