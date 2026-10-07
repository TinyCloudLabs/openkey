import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

import { credentialHash, verifySessionProof } from '../services/native-delegation/session-proof';

const sha256 = (value: string) => createHash('sha256').update(value).digest('base64url');
const segment = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
const NOW = 1_791_374_400_000;
const HTU = 'https://api.openkey.so/api/auth/oauth2/token';

function key() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' }) as { x: string };
  return { privateKey, x, jkt: sha256(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })) };
}

const session = key();
const expected = { sessionJwk: { x: session.x }, sessionJkt: session.jkt, htu: HTU, clientId: 'exo-native', credential: 'the-code' };

function proof(
  header: Record<string, unknown> = {},
  claims: Record<string, unknown> = {},
  signer: KeyObject = session.privateKey,
) {
  const encodedHeader = segment({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: session.jkt, ...header });
  const encodedPayload = segment({
    jti: 'abcdefghijklmnop', iat: NOW / 1000, htm: 'POST', htu: HTU, client_id: 'exo-native', cred_hash: sha256('the-code'), ...claims,
  });
  const signature = sign(null, Buffer.from(`${encodedHeader}.${encodedPayload}`), signer).toString('base64url');
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

describe('OpenKey-Session-Proof verification', () => {
  test('cred_hash is unpadded base64url SHA-256 of the literal credential', () => {
    expect(credentialHash('the-code')).toBe(sha256('the-code'));
    expect(credentialHash('the-code')).not.toContain('=');
  });

  test('accepts a proof that satisfies every rule', () => {
    expect(verifySessionProof(proof(), expected, NOW)).toBe(true);
  });

  test('iat is accepted within ±60 s and refused beyond', () => {
    for (const offset of [-60, 60]) expect(verifySessionProof(proof({}, { iat: NOW / 1000 + offset }), expected, NOW)).toBe(true);
    for (const offset of [-61, 61]) expect(verifySessionProof(proof({}, { iat: NOW / 1000 + offset }), expected, NOW)).toBe(false);
    expect(verifySessionProof(proof({}, { iat: NOW / 1000 + 0.5 }), expected, NOW)).toBe(false);
    expect(verifySessionProof(proof({}, { iat: String(NOW / 1000) }), expected, NOW)).toBe(false);
  });

  test('refuses a missing or malformed proof', () => {
    for (const value of [undefined, null, '', 'a.b', 'a.b.c.d', 'not a jws', `${proof()}=`, `${proof()}, ${proof()}`]) {
      expect(verifySessionProof(value, expected, NOW), String(value)).toBe(false);
    }
  });

  test('refuses a wrong header', () => {
    for (const header of [{ typ: 'JWT' }, { alg: 'ES256' }, { alg: 'none' }, { kid: 'other' }, { jwk: { x: session.x } }]) {
      expect(verifySessionProof(proof(header), expected, NOW), JSON.stringify(header)).toBe(false);
    }
  });

  test('refuses wrong, missing or extra claims', () => {
    for (const claims of [
      { htm: 'GET' }, { htu: `${HTU}/` }, { htu: 'https://api.openkey.so/oauth2/token' }, { client_id: 'other' },
      { cred_hash: sha256('other-code') }, { jti: 'a'.repeat(15) }, { jti: 'a'.repeat(129) }, { jti: 1234567890123456 },
      { jti: undefined }, { scope: 'openid' },
    ]) {
      expect(verifySessionProof(proof({}, claims), expected, NOW), JSON.stringify(claims)).toBe(false);
    }
    expect(verifySessionProof(proof({}, { jti: 'a'.repeat(16) }), expected, NOW)).toBe(true);
    expect(verifySessionProof(proof({}, { jti: 'a'.repeat(128) }), expected, NOW)).toBe(true);
  });

  test('verifies only against the stored key', () => {
    const other = key();
    expect(verifySessionProof(proof({}, {}, other.privateKey), expected, NOW)).toBe(false);
    expect(verifySessionProof(proof({ kid: other.jkt }, {}, other.privateKey), expected, NOW)).toBe(false);
  });

  test('refuses a signature over different bytes or in a non-canonical encoding', () => {
    const [header, payload, signature] = proof().split('.') as [string, string, string];
    const otherPayload = proof({}, { client_id: 'other' }).split('.')[1]!;
    expect(verifySessionProof(`${header}.${otherPayload}.${signature}`, expected, NOW)).toBe(false);
    expect(verifySessionProof(`${header}.${payload}.${signature.slice(0, -1)}`, expected, NOW)).toBe(false);
    const last = signature.at(-1)!;
    const sibling = 'AQgw'.includes(last) ? String.fromCharCode(last.charCodeAt(0) + 1) : last;
    if (sibling !== last) expect(verifySessionProof(`${header}.${payload}.${signature.slice(0, -1)}${sibling}`, expected, NOW)).toBe(false);
  });
});
