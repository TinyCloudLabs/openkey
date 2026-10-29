// Other strings that a JWT's signature can take while the same signing input stays signed.
// A shared helper for the revoke tests; not a test file.

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/** Every token that differs only in the last character of its signature. Some still verify: that character has spare bits. */
export function lastCharVariants(token: string): string[] {
  const head = token.slice(0, -1);
  return [...BASE64URL].map((char) => head + char).filter((variant) => variant !== token);
}

const P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;

/** An ES256 token with its signature's `s` replaced by `n - s`: the other valid form of the same signature. */
export function otherFormEs256(token: string): string {
  const [header, payload, signature] = token.split('.') as [string, string, string];
  const bytes = Buffer.from(signature, 'base64url');
  const s = BigInt(`0x${bytes.subarray(32).toString('hex')}`);
  const flipped = Buffer.from((P256_ORDER - s).toString(16).padStart(64, '0'), 'hex');
  return `${header}.${payload}.${Buffer.concat([bytes.subarray(0, 32), flipped]).toString('base64url')}`;
}
