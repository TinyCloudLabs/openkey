// Connect widget response (TC-688).
//
// The response carries only the selected key. It never includes the OpenKey
// session token: the embedding page is a third party and must not receive a
// credential for OpenKey's key and account APIs. Later embedded widgets read
// the token from OpenKey-origin storage themselves.

export function connectAuthResponse(key: {
  address: string;
  id: string;
  keyType: 'MANAGED' | 'EXTERNAL';
}) {
  return {
    type: 'openkey:auth:response' as const,
    success: true as const,
    address: key.address,
    keyId: key.id,
    keyType: key.keyType,
  };
}
