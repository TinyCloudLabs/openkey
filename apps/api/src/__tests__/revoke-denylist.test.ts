// The wrapper around the provider's /oauth2/revoke (services/revoked-access-token.ts), with signed
// tokens, an in-memory database and a stand-in for the provider. The real provider and database
// run in oauth-resource-introspect.test.ts.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet, type JWK } from 'jose';
import { createAccessTokenVerifier } from '../services/access-token-verifier';
import { accessTokenKey, createRevokeDenylist } from '../services/revoked-access-token';
import { lastCharVariants } from './token-variants';

const ISSUER = 'https://api.openkey.test/api/auth';
const RESOURCE = 'https://mcp.tinycloud.xyz/mcp';
const OTHER_RESOURCE = 'https://not-ours.example/mcp';
const NOW_MS = Date.UTC(2026, 9, 26, 12, 0, 0);
const NOW_S = NOW_MS / 1000;
const REVOKE = 'https://api.openkey.test/api/auth/oauth2/revoke';
const FORM = 'application/x-www-form-urlencoded';

interface Signer { privateKey: CryptoKey; jwk: JWK }
async function newSigner(kid: string): Promise<Signer> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { extractable: true });
  return { privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg: 'EdDSA', use: 'sig' } };
}
let signer: Signer;
let strangerSigner: Signer;
beforeAll(async () => {
  signer = await newSigner('key-1');
  strangerSigner = await newSigner('key-2');
});

// ---- the database ---------------------------------------------------------------
interface Row { tokenHash: string; clientId: string; expiresAt: Date }
let rows: Map<string, Row>;
let failInsert: boolean;
let failSweep: boolean;
let failJwks: boolean;
let sweeps: number;
let clock: number;

const database = {
  revokedAccessToken: {
    createMany: async ({ data, skipDuplicates }: { data: Row[]; skipDuplicates?: boolean }) => {
      if (failInsert) throw new Error('database down');
      let count = 0;
      for (const row of data) {
        if (rows.has(row.tokenHash)) {
          if (!skipDuplicates) throw new Error('unique constraint');
          continue;
        }
        rows.set(row.tokenHash, row);
        count += 1;
      }
      return { count };
    },
    deleteMany: async ({ where }: { where: { expiresAt: { lt: Date } } }) => {
      sweeps += 1;
      if (failSweep) throw new Error('database down');
      for (const [key, row] of rows) if (row.expiresAt < where.expiresAt.lt) rows.delete(key);
      return { count: 0 };
    },
  },
};

// ---- the provider stand-in --------------------------------------------------------
/** What the stand-in answers, and the bodies it received. */
let answer: { status: number; body: string; headers: Record<string, string> };
let received: string[];

function makeApp(options: { sweepIntervalMs?: number } = {}) {
  const app = new Hono();
  app.use('/api/auth/*', createRevokeDenylist({
    database: database as never,
    verify: createAccessTokenVerifier({
      issuer: ISSUER,
      getJwks: async (): Promise<JSONWebKeySet> => {
        if (failJwks) throw new Error('keys unavailable');
        return { keys: [signer.jwk] };
      },
      now: () => clock,
    }),
    validAudiences: [RESOURCE],
    now: () => clock,
    ...options,
  }));
  app.all('/api/auth/*', async (c) => {
    received.push(await c.req.text());
    return new Response(answer.body, { status: answer.status, headers: answer.headers });
  });
  return app;
}
let app = makeApp();

beforeEach(() => {
  rows = new Map();
  failInsert = false;
  failSweep = false;
  failJwks = false;
  sweeps = 0;
  clock = NOW_MS;
  answer = { status: 200, body: '', headers: { 'x-from': 'provider' } };
  received = [];
  app = makeApp();
});

// ---- tokens and requests ----------------------------------------------------------
async function mint(claims: Record<string, unknown> = {}, options: { signer?: Signer; issuer?: string; expiresIn?: number | null } = {}): Promise<string> {
  const using = options.signer ?? signer;
  const jwt = new SignJWT({ sub: 'user_1', azp: 'app_1', sid: 'sess_1', scope: 'tinycloud:mcp', aud: RESOURCE, ...claims } as never)
    .setProtectedHeader({ alg: 'EdDSA', kid: using.jwk.kid })
    .setIssuer(options.issuer ?? ISSUER)
    .setIssuedAt(NOW_S - 10);
  if (options.expiresIn !== null) jwt.setExpirationTime(NOW_S + (options.expiresIn ?? 300));
  return jwt.sign(using.privateKey);
}

const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

function revoke(form: Record<string, string>, init: { auth?: string; contentType?: string; rawBody?: string; method?: string; url?: string } = {}) {
  return app.request(init.url ?? REVOKE, {
    method: init.method ?? 'POST',
    headers: { 'content-type': init.contentType ?? FORM, ...(init.auth ? { authorization: init.auth } : {}) },
    body: init.method === 'GET' ? undefined : (init.rawBody ?? new URLSearchParams(form).toString()),
  });
}

const stored = () => [...rows.values()];

describe('a verified token of the calling client, after the provider answered 200', () => {
  test('is recorded under its key, with the client and the token\'s own expiry, and the answer is the provider\'s', async () => {
    const token = await mint();
    const response = await revoke({ token, client_id: 'app_1' });
    expect(response.status).toBe(200);
    expect(response.headers.get('x-from')).toBe('provider');
    expect(await response.text()).toBe('');
    expect(stored()).toEqual([{ tokenHash: accessTokenKey(token)!, clientId: 'app_1', expiresAt: new Date((NOW_S + 300) * 1000) }]);
  });

  test('only the key is stored: no row carries the token, its payload or its signature', async () => {
    const token = await mint();
    await revoke({ token, client_id: 'app_1' });
    const [header, payload, signature] = token.split('.') as [string, string, string];
    const text = JSON.stringify(stored());
    for (const part of [token, header, payload, signature]) expect(text).not.toContain(part);
  });

  test('the request reaches the provider unchanged, once', async () => {
    const token = await mint();
    const body = new URLSearchParams({ token, client_id: 'app_1', token_type_hint: 'access_token' }).toString();
    await revoke({}, { rawBody: body });
    expect(received).toEqual([body]);
  });

  test('a confidential client is recorded by its Basic header, which wins over a client_id in the body', async () => {
    const token = await mint({ azp: 'conf_1' });
    await revoke({ token, client_id: 'someone_else' }, { auth: basic('conf_1', 'secret') });
    expect(stored().map((row) => row.clientId)).toEqual(['conf_1']);
  });

  test('a token of the body\'s client is not recorded when the Basic header names another client', async () => {
    const token = await mint({ azp: 'someone_else' });
    await revoke({ token, client_id: 'someone_else' }, { auth: basic('conf_1', 'secret') });
    expect(stored()).toEqual([]);
  });

  test('whatever the type hint says', async () => {
    for (const hint of ['access_token', 'refresh_token', 'nonsense']) {
      rows.clear();
      await revoke({ token: await mint({ jti: hint }), client_id: 'app_1', token_type_hint: hint });
      expect(stored()).toHaveLength(1);
    }
  });

  test('revoking twice is fine: one row, the same answer', async () => {
    const token = await mint();
    expect((await revoke({ token, client_id: 'app_1' })).status).toBe(200);
    expect((await revoke({ token, client_id: 'app_1' })).status).toBe(200);
    expect(stored()).toHaveLength(1);
  });

  test('a signature form that differs in its last character is the same row', async () => {
    const token = await mint();
    await revoke({ token, client_id: 'app_1' });
    for (const variant of lastCharVariants(token)) await revoke({ token: variant, client_id: 'app_1' });
    expect(stored()).toHaveLength(1);
  });
});

describe('what is not recorded, with the provider\'s answer unchanged', () => {
  // No delete of expired rows here, so a row written for an expired token would still be seen.
  beforeEach(() => { app = makeApp({ sweepIntervalMs: Number.POSITIVE_INFINITY }); });

  const stranger = () => mint({}, { signer: strangerSigner });
  const noneAlg = () => `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: 'u', azp: 'app_1', aud: RESOURCE, iss: ISSUER, exp: NOW_S + 300 })).toString('base64url')}.x`;

  test.each([
    ['a token issued to another client', () => mint({ azp: 'another_client' })],
    ['garbage', async () => 'not-a-token'],
    ['a token with no signature part', async () => 'aaa.bbb'],
    ['an unsigned token', async () => noneAlg()],
    ['a token signed with another key', stranger],
    ['an expired token', () => mint({}, { expiresIn: -60 })],
    ['a token with no expiry', () => mint({}, { expiresIn: null })],
    ['a token from another issuer', () => mint({}, { issuer: 'https://elsewhere.example/api/auth' })],
    ['a token for an audience this server does not issue for', () => mint({ aud: OTHER_RESOURCE })],
    ['a token with no azp', () => mint({ azp: undefined })],
    ['a token over 8 KiB', () => mint({ padding: 'x'.repeat(9 * 1024) })],
  ] as Array<[string, () => Promise<string>]>)('%s', async (_name, make) => {
    answer = { status: 200, body: '{"ok":true}', headers: { 'x-from': 'provider' } };
    const response = await revoke({ token: await make(), client_id: 'app_1' });
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('{"ok":true}');
    expect(response.headers.get('x-from')).toBe('provider');
    expect(stored()).toEqual([]);
    expect(received).toHaveLength(1);
  });

  test.each([
    ['400 (a refusal, as the interceptors give for a Bearer prefix or a token of another client)', 400],
    ['401 (client credentials the provider did not accept)', 401],
    ['429 (the provider\'s limit)', 429],
    ['500', 500],
  ])('a provider answer of %s', async (_name, status) => {
    answer = { status, body: '{"error":"x"}', headers: { 'x-from': 'provider' } };
    const response = await revoke({ token: await mint(), client_id: 'app_1' });
    expect(response.status).toBe(status);
    expect(await response.text()).toBe('{"error":"x"}');
    expect(stored()).toEqual([]);
  });

  test('a request with no token, no client, a Bearer-prefixed token or a repeated parameter', async () => {
    const token = await mint();
    await revoke({ client_id: 'app_1' });
    await revoke({ token });
    await revoke({ token: `Bearer ${token}`, client_id: 'app_1' });
    await revoke({}, { rawBody: `token=${token}&token=${token}&client_id=app_1` });
    await revoke({ token, client_id: 'app_1' }, { auth: 'Basic !!!not-base64' });
    expect(stored()).toEqual([]);
  });

  test('a body that is not a form, other paths and other methods', async () => {
    const token = await mint();
    await revoke({}, { contentType: 'application/json', rawBody: JSON.stringify({ token, client_id: 'app_1' }) });
    await revoke({ token, client_id: 'app_1' }, { url: 'https://api.openkey.test/api/auth/oauth2/introspect' });
    await revoke({ token, client_id: 'app_1' }, { url: 'https://api.openkey.test/api/auth/oauth2/tinycloud/revoke' });
    await revoke({ token, client_id: 'app_1' }, { method: 'GET' });
    expect(stored()).toEqual([]);
    expect(received).toHaveLength(4);
  });
});

describe('a write that fails', () => {
  test('is a 503 with Retry-After in place of the provider\'s answer, and nothing is recorded', async () => {
    answer = { status: 200, body: '{"ok":true}', headers: { 'x-from': 'provider' } };
    failInsert = true;
    const response = await revoke({ token: await mint(), client_id: 'app_1' });
    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('5');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('x-from')).toBeNull();
    expect(await response.json()).toEqual({ error: 'temporarily_unavailable', error_description: 'the revocation could not be recorded; try again' });
    expect(stored()).toEqual([]);
  });

  test('so is a failure to read the signing keys', async () => {
    failJwks = true;
    const response = await revoke({ token: await mint(), client_id: 'app_1' });
    expect(response.status).toBe(503);
    expect(stored()).toEqual([]);
  });

  test('a failure of the database for a token that does not qualify changes nothing: the answer stays the provider\'s', async () => {
    failInsert = true;
    expect((await revoke({ token: 'garbage', client_id: 'app_1' })).status).toBe(200);
    expect((await revoke({ token: await mint({ azp: 'another_client' }), client_id: 'app_1' })).status).toBe(200);
  });

  test('the retry after a failure records the token', async () => {
    const token = await mint();
    failInsert = true;
    expect((await revoke({ token, client_id: 'app_1' })).status).toBe(503);
    failInsert = false;
    expect((await revoke({ token, client_id: 'app_1' })).status).toBe(200);
    expect(stored()).toHaveLength(1);
  });
});

describe('expired rows', () => {
  test('are deleted after a record, at most once per interval', async () => {
    rows.set('old', { tokenHash: 'old', clientId: 'app_1', expiresAt: new Date(NOW_MS - 1000) });
    rows.set('live', { tokenHash: 'live', clientId: 'app_1', expiresAt: new Date(NOW_MS + 100_000) });
    clock = NOW_MS + 70_000;
    await revoke({ token: await mint({ jti: 'a' }, { expiresIn: 600 }), client_id: 'app_1' });
    expect([...rows.keys()]).not.toContain('old');
    expect([...rows.keys()]).toContain('live');
    expect(sweeps).toBe(1);

    rows.set('old2', { tokenHash: 'old2', clientId: 'app_1', expiresAt: new Date(NOW_MS) });
    await revoke({ token: await mint({ jti: 'b' }, { expiresIn: 600 }), client_id: 'app_1' });
    expect(sweeps).toBe(1);
    expect([...rows.keys()]).toContain('old2');

    clock += 61_000;
    await revoke({ token: await mint({ jti: 'c' }, { expiresIn: 600 }), client_id: 'app_1' });
    expect(sweeps).toBe(2);
    expect([...rows.keys()]).not.toContain('old2');
  });

  test('a delete that fails does not fail the revoke', async () => {
    failSweep = true;
    const response = await revoke({ token: await mint(), client_id: 'app_1' });
    expect(response.status).toBe(200);
    expect(stored()).toHaveLength(1);
  });

  test('no record, no delete', async () => {
    await revoke({ token: 'garbage', client_id: 'app_1' });
    expect(sweeps).toBe(0);
  });
});
