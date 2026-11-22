// TC-3842: the public GET /attestation route. The preimage format is a contract with the verifier
// (js-sdk tee-verify, TC-3841), so it is pinned here character for character.
import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';
import { Hono } from 'hono';
import type { TeeAppInfo, TeeQuote } from '@openkey/tee';
import { createAttestationRouter, type AttestationRouterOptions } from '../routes/attestation';

const ISSUER = 'https://api.openkey.so/api/auth';
const COMPOSE_HASH = 'f29afbb944c28ff89ea21d778a8b556c3d269a5155fb15c2ca3403ef73e12126';
const APP_ID = 'b7d6e87778f73904a8f5fd26e4d0f1d1310234be';

async function publicJwk(): Promise<JWK> {
  const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  return { ...(await exportJWK(publicKey)), kid: crypto.randomUUID(), alg: 'EdDSA' };
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

function app(options: Partial<AttestationRouterOptions> & Pick<AttestationRouterOptions, 'tee'>, keys: JWK[]) {
  const root = new Hono();
  root.route('/attestation', createAttestationRouter({ issuer: ISSUER, readSigningKeys: async () => ({ keys }), ...options }));
  return root;
}

describe('GET /attestation', () => {
  test('quotes SHA-256 of so.openkey/tee-key/v1\\0:<issuer>#<sorted thumbprints>:<nonce>', async () => {
    const keys = [await publicJwk(), await publicJwk()];
    const thumbprints = (await Promise.all(keys.map((key) => calculateJwkThumbprint(key, 'sha256')))).sort();
    const { tee, bindings } = fakeTee();
    const response = await app({ tee }, keys).request('/attestation?nonce=Ab9-_x');
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body: unknown = await response.json();
    const identity = `${ISSUER}#${thumbprints.join(',')}`;
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
      key_binding: binding,
      key_binding_sha256: createHash('sha256').update(binding, 'utf8').digest('hex'),
      timestamp: expect.any(String),
    });
  });

  test('requires a nonce of 1-64 characters from A-Z a-z 0-9 - _', async () => {
    const { tee, bindings } = fakeTee();
    const routes = app({ tee }, [await publicJwk()]);
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
    const response = await app({ tee }, [await publicJwk()]).request('/attestation?nonce=n');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ mode: 'classic', message: 'This instance is not running in a TEE' });
    expect(bindings).toEqual([]);
  });

  test('503 quote_unavailable when the quote, the app info or the key set fails, or there are no keys', async () => {
    const key = await publicJwk();
    const failures: Array<[Partial<AttestationRouterOptions['tee']>, JWK[]]> = [
      [{ getQuote: async () => { throw new Error('report data mismatch'); } }, [key]],
      [{ appInfo: async () => { throw new Error('no info'); } }, [key]],
      [{}, []],
    ];
    for (const [overrides, keys] of failures) {
      const response = await app({ tee: fakeTee(overrides).tee }, keys).request('/attestation?nonce=n');
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: 'quote_unavailable' });
    }
    const unreadable = app({ tee: fakeTee().tee, readSigningKeys: async () => { throw new Error('signing keys unavailable'); } }, []);
    expect((await unreadable.request('/attestation?nonce=n')).status).toBe(503);
  });

  test('caps quotes per minute for the whole process', async () => {
    let now = 1_000_000;
    const { tee, bindings } = fakeTee();
    const routes = app({ tee, limitPerMinute: 2, now: () => now }, [await publicJwk()]);
    expect((await routes.request('/attestation?nonce=a')).status).toBe(200);
    expect((await routes.request('/attestation?nonce=b')).status).toBe(200);
    expect((await routes.request('/attestation?nonce=c')).status).toBe(429);
    now += 60_000;
    expect((await routes.request('/attestation?nonce=d')).status).toBe(200);
    expect(bindings).toHaveLength(3);
  });
});
