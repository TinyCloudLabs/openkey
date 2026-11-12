import { randomUUID } from 'node:crypto';
import { Wallet, concat, getBytes, sha256, toUtf8Bytes } from 'ethers';

export type DeletionInvocation = {
  resource: string;
  action: 'tinycloud.space/retire-owner' | 'tinycloud.space/delete';
  idempotencyKey: string;
};

// SSI did-pkh requires the public JWK and the blockchainAccountId issuer
// fragment. This signs SHA-256 directly, without an Ethereum message prefix.
export function signDeletionInvocation(privateKey: string, intent: DeletionInvocation): string {
  const wallet = new Wallet(privateKey);
  const owner = `did:pkh:eip155:1:${wallet.address}`;
  if (intent.action === 'tinycloud.space/retire-owner' && intent.resource !== owner) {
    throw new Error('Retirement resource must match owner');
  }
  const publicKey = getBytes(wallet.signingKey.publicKey);
  const b64 = (value: Uint8Array) => Buffer.from(value).toString('base64url');
  const header = {
    alg: 'ES256K-R', typ: 'JWT', ucv: '0.10.0',
    jwk: { alg: 'ES256K-R', crv: 'secp256k1', kty: 'EC', x: b64(publicKey.slice(1, 33)), y: b64(publicKey.slice(33, 65)) },
  };
  const nbf = Math.floor(Date.now() / 1000);
  const payload = {
    iss: `${owner}#blockchainAccountId`, aud: owner,
    att: { [intent.resource]: { [intent.action]: [{}] } },
    nbf, exp: nbf + 300, nnc: randomUUID(),
    fct: [{ idempotency_key: intent.idempotencyKey }], prf: [],
  };
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode(header)}.${encode(payload)}`;
  const signature = wallet.signingKey.sign(sha256(toUtf8Bytes(input)));
  return `${input}.${b64(getBytes(concat([signature.r, signature.s, new Uint8Array([signature.yParity])])))}`;
}
