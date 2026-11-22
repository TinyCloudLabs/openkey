// TC-3842: the public GET /attestation route. The preimage format is a contract with the verifier
// (js-sdk tee-verify, TC-3841), so it is pinned here character for character.
import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { symmetricEncrypt } from 'better-auth/crypto';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';
import { Hono } from 'hono';
import type { TeeAppInfo, TeeQuote } from '@openkey/tee';
import { createAttestationRouter, jwksPrivateKeyLoader, type AttestationRouterOptions } from '../routes/attestation';

const ISSUER = 'https://api.openkey.so/api/auth';
const COMPOSE_HASH = 'f29afbb944c28ff89ea21d778a8b556c3d269a5155fb15c2ca3403ef73e12126';
const APP_ID = 'b7d6e87778f73904a8f5fd26e4d0f1d1310234be';
const AUTH_SECRET = 'public-attestation-test-secret-not-a-real-secret';

interface KeyPair { publicJwk: JWK; privateJwk: JWK }

/** An Ed25519 pair as Better Auth's jwt plugin makes it: the served public JWK carries kid and alg. */
async function keyPair(): Promise<KeyPair> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const kid = crypto.randomUUID();
  return { publicJwk: { ...(await exportJWK(publicKey)), kid, alg: 'EdDSA' }, privateJwk: await exportJWK(privateKey) };
}

/** A loader that holds the private keys of `held`, and nothing for any other kid. */
function holding(held: KeyPair[]): (kid: string) => Promise<JWK | null> {
  const byKid = new Map(held.map((pair) => [pair.publicJwk.kid, pair.privateJwk]));
  return async (kid) => byKid.get(kid) ?? null;
}

function fakeTee(overrides: Partial<AttestationRouterOptions['tee']> = {}) {
  const bindings: string[] = [];
  const tee: AttestationRouterOptions['tee'] = {
    isInTee: () => true,
    appInfo: async (): Promise<TeeAppInfo> => ({ appId: APP_ID, composeHash: COMPOSE_HASH }),
    getQuote: async (binding: string): Promise<TeeQuote> => {
      bindings.push(binding);
      return { quote: 'ab'.repeat(700), eventLog: '[]', reportDataSha256: createHash('sha256').update(binding, 'utf8').digest('hex') };
    },
    ...overrides,
  };
  return { tee, bindings };
}

function app(options: Partial<AttestationRouterOptions> & Pick<AttestationRouterOptions, 'tee'>, served: KeyPair[], held = served) {
  const root = new Hono();
  root.route('/attestation', createAttestationRouter({
    issuer: ISSUER,
    readSigningKeys: async () => ({ keys: served.map((pair) => pair.publicJwk) }),
    loadPrivateKey: holding(held),
    ...options,
  }));
  return root;
}

async function identityOf(pairs: KeyPair[]): Promise<string> {
  const thumbprints = await Promise.all(pairs.map((pair) => calculateJwkThumbprint(pair.publicJwk, 'sha256')));
  return `${ISSUER}#${thumbprints.sort().join(',')}`;
}

describe('GET /attestation', () => {
  test('quotes SHA-256 of so.openkey/tee-key/v1\\0:<issuer>#<sorted thumbprints>:<nonce>', async () => {
    const pairs = [await keyPair(), await keyPair()];
    const { tee, bindings } = fakeTee();
    const response = await app({ tee }, pairs).request('/attestation?nonce=Ab9-_x');
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body: unknown = await response.json();
    const identity = await identityOf(pairs);
    // Backslash and zero, two characters, as in tinycloud-node's preimage; not a NUL byte.
    const binding = `so.openkey/tee-key/v1\\0:${identity}:Ab9-_x`;
    expect(binding).toContain('v1\\0:');
    expect(binding.includes('\u0000')).toBe(false);
    expect(bindings).toEqual([binding]);
    expect(body).toEqual({
      mode: 'dstack',
      quote: 'ab'.repeat(700),
      event_log: '[]',
      compose_hash: COMPOSE_HASH,
      app_id: APP_ID,
      identity,
      excluded_keys: 0,
      key_binding: binding,
      key_binding_sha256: createHash('sha256').update(binding, 'utf8').digest('hex'),
      timestamp: expect.any(String),
    });
  });

  test('leaves out a served key this process holds no private key for, and counts it', async () => {
    const real = await keyPair();
    // A public key written straight into the jwks table: served, but with no private key the CVM can open.
    const injected = await keyPair();
    const { tee, bindings } = fakeTee();
    const response = await app({ tee }, [real, injected], [real]).request('/attestation?nonce=n');
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({ identity: await identityOf([real]), excluded_keys: 1 });
    expect(bindings).toEqual([`so.openkey/tee-key/v1\\0:${await identityOf([real])}:n`]);
  });

  test('leaves out a served key whose stored private key belongs to another pair', async () => {
    const real = await keyPair();
    const other = await keyPair();
    const mismatched: KeyPair = { publicJwk: (await keyPair()).publicJwk, privateJwk: other.privateJwk };
    const response = await app({ tee: fakeTee().tee }, [real, mismatched]).request('/attestation?nonce=n');
    expect(await response.json()).toMatchObject({ identity: await identityOf([real]), excluded_keys: 1 });
  });

  test('requires a nonce of 1-64 characters from A-Z a-z 0-9 - _', async () => {
    const { tee, bindings } = fakeTee();
    const routes = app({ tee }, [await keyPair()]);
    for (const query of ['', '?nonce=', `?nonce=${'a'.repeat(65)}`, '?nonce=a:b', '?nonce=a%00b', '?nonce=%C3%A9']) {
      const response = await routes.request(`/attestation${query}`);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "nonce must be 1-64 characters of A-Z, a-z, 0-9, '-' or '_'" });
    }
    expect((await routes.request(`/attestation?nonce=${'a'.repeat(64)}`)).status).toBe(200);
    expect(bindings).toHaveLength(1);
  });

  test('answers classic outside a TEE, without quoting', async () => {
    const { tee, bindings } = fakeTee({ isInTee: () => false });
    const response = await app({ tee }, [await keyPair()]).request('/attestation?nonce=n');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ mode: 'classic', message: 'This instance is not running in a TEE' });
    expect(bindings).toEqual([]);
  });

  test('503 quote_unavailable when the quote, the app info, the key set or the key lookup fails, or no key is held', async () => {
    const pair = await keyPair();
    const failures: Array<[Partial<AttestationRouterOptions>, KeyPair[], KeyPair[]]> = [
      [{ tee: fakeTee({ getQuote: async () => { throw new Error('report data mismatch'); } }).tee }, [pair], [pair]],
      [{ tee: fakeTee({ appInfo: async () => { throw new Error('no info'); } }).tee }, [pair], [pair]],
      [{ readSigningKeys: async () => { throw new Error('signing keys unavailable'); } }, [pair], [pair]],
      [{ loadPrivateKey: async () => { throw new Error('database unavailable'); } }, [pair], [pair]],
      [{}, [], []],
      [{}, [pair], []],
    ];
    for (const [overrides, served, held] of failures) {
      const response = await app({ tee: fakeTee().tee, ...overrides }, served, held).request('/attestation?nonce=n');
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: 'quote_unavailable' });
    }
  });

  test('caps quotes per minute for the whole process; a malformed nonce spends no slot', async () => {
    let now = 1_000_000;
    const { tee, bindings } = fakeTee();
    const routes = app({ tee, limitPerMinute: 2, now: () => now }, [await keyPair()]);
    expect((await routes.request('/attestation?nonce=a:b')).status).toBe(400);
    expect((await routes.request('/attestation?nonce=a')).status).toBe(200);
    expect((await routes.request('/attestation?nonce=b')).status).toBe(200);
    expect((await routes.request('/attestation?nonce=c')).status).toBe(429);
    now += 60_000;
    expect((await routes.request('/attestation?nonce=d')).status).toBe(200);
    expect(bindings).toHaveLength(3);
  });
});

describe('jwksPrivateKeyLoader', () => {
  /** A jwks row's privateKey column as Better Auth writes it: JSON of the ciphertext string. */
  async function storedRow(privateJwk: JWK, secret: string): Promise<string> {
    return JSON.stringify(await symmetricEncrypt({ key: secret, data: JSON.stringify(privateJwk) }));
  }

  test('opens a row encrypted under the auth secret; a row it cannot open, or no row, is null', async () => {
    const pair = await keyPair();
    const rows: Record<string, string> = {
      real: await storedRow(pair.privateJwk, AUTH_SECRET),
      'other-secret': await storedRow(pair.privateJwk, 'a-different-secret-not-this-process'),
      'public-only': JSON.stringify(JSON.stringify(pair.publicJwk)),
      'not-json': 'not json',
    };
    const load = jwksPrivateKeyLoader({
      readEncryptedPrivateKey: async (kid) => (Object.hasOwn(rows, kid) ? rows[kid] ?? null : null),
      secret: async () => AUTH_SECRET,
    });
    expect(await load('real')).toEqual({ kty: 'OKP', crv: 'Ed25519', x: pair.privateJwk.x, d: pair.privateJwk.d });
    for (const kid of ['other-secret', 'public-only', 'not-json', 'missing']) expect(await load(kid)).toBeNull();
  });

  test('a failed row read throws, so the route answers 503 rather than excluding the key', async () => {
    const load = jwksPrivateKeyLoader({ readEncryptedPrivateKey: async () => { throw new Error('database unavailable'); }, secret: async () => AUTH_SECRET });
    await expect(load('real')).rejects.toThrow('database unavailable');
  });
});
