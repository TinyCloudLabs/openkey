// POST /api/oauth/resource/introspect: the route itself, with signed tokens and an
// in-memory database. The real provider and database run in
// oauth-resource-introspect.test.ts.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet, type JWK } from 'jose';
import { createResourceIntrospectRouter } from '../routes/oauth-resource-introspect';
import { hashClientSecret, resourceServerMetadata } from '../services/resource-server';

const ISSUER = 'https://api.openkey.test/api/auth';
const RESOURCE = 'https://mcp.tinycloud.xyz/mcp';
const CHATGPT_RESOURCE = 'https://mcp.tinycloud.xyz/chatgpt/mcp';
const OTHER_RESOURCE = 'https://other.example/mcp';
const USERINFO = `${ISSUER}/oauth2/userinfo`;
const NOW_MS = Date.UTC(2026, 9, 26, 12, 0, 0);
const NOW_S = NOW_MS / 1000;

interface Signer { privateKey: CryptoKey; jwk: JWK }
async function newSigner(kid: string): Promise<Signer> {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { extractable: true });
  return { privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg: 'EdDSA', use: 'sig' } };
}

let signer: Signer;
let otherSigner: Signer;
beforeAll(async () => {
  signer = await newSigner('key-1');
  otherSigner = await newSigner('key-2');
});

// ---- the database ----------------------------------------------------------------
interface ClientRow { clientId: string; clientSecret: string | null; disabled: boolean; public: boolean; metadata: unknown }
const secrets = { rs: 'rs-secret-0123456789abcdefghijklmnopqrstuvwxyz', rs2: 'rs2-secret-0123456789abcdefghijklmnopqrstuvwxyz', both: 'both-secret-0123456789abcdefghijklmnopqrstuvwxy', slow: 'slow-secret-0123456789abcdefghijklmnopqrstuvwxy', conf: 'conf-secret-0123456789abcdefghijklmnopqrstuvwxy' };
let clients: Map<string, ClientRow>;
let consents: Map<string, { scopes: string[]; createdAt: Date }>;
/** When the consent rows were given: long before the tokens below, which are issued seconds before NOW. */
const CONSENT_AT = new Date(NOW_MS - 3_600_000);
let sessions: Map<string, { id: string; userId: string; expiresAt: Date }>;
let failDatabase: boolean;
let jwksCalls: number;
let jwksKeys: JWK[];
let failJwks: boolean;
let clock: number;

const prisma = {
  oauthClient: {
    findUnique: async ({ where }: { where: { clientId: string } }) => {
      if (failDatabase) throw new Error('database down');
      return clients.get(where.clientId) ?? null;
    },
  },
  oauthConsent: {
    findUnique: async ({ where }: { where: { userId_clientId: { userId: string; clientId: string } } }) => {
      if (failDatabase) throw new Error('database down');
      return consents.get(`${where.userId_clientId.userId}:${where.userId_clientId.clientId}`) ?? null;
    },
  },
  session: {
    findFirst: async ({ where }: { where: { id: string; userId: string; expiresAt: { gt: Date } } }) => {
      if (failDatabase) throw new Error('database down');
      const session = sessions.get(where.id);
      return session && session.userId === where.userId && session.expiresAt > where.expiresAt.gt ? { id: session.id } : null;
    },
  },
};

function makeRouter(limits?: { authenticatedPerWindow?: number; failedAuthPerWindow?: number }) {
  return createResourceIntrospectRouter({
    prisma: prisma as never,
    issuer: ISSUER,
    validAudiences: [RESOURCE, CHATGPT_RESOURCE, OTHER_RESOURCE, USERINFO],
    getJwks: async (): Promise<JSONWebKeySet> => {
      jwksCalls += 1;
      if (failJwks) throw new Error('keys unavailable');
      return { keys: jwksKeys };
    },
    now: () => clock,
    limits,
  });
}
let router = makeRouter();

beforeEach(() => {
  clock = NOW_MS;
  failDatabase = false;
  failJwks = false;
  jwksCalls = 0;
  jwksKeys = [signer.jwk];
  clients = new Map([
    ['rs_1', { clientId: 'rs_1', clientSecret: hashClientSecret(secrets.rs), disabled: false, public: false, metadata: resourceServerMetadata([RESOURCE]) }],
    ['rs_2', { clientId: 'rs_2', clientSecret: hashClientSecret(secrets.rs2), disabled: false, public: false, metadata: resourceServerMetadata([RESOURCE]) }],
    ['rs_both', { clientId: 'rs_both', clientSecret: hashClientSecret(secrets.both), disabled: false, public: false, metadata: resourceServerMetadata([RESOURCE, CHATGPT_RESOURCE]) }],
    ['rs_slow', { clientId: 'rs_slow', clientSecret: hashClientSecret(secrets.slow), disabled: false, public: false, metadata: resourceServerMetadata([RESOURCE], { rateLimitPerMinute: 2 }) }],
    ['conf_1', { clientId: 'conf_1', clientSecret: hashClientSecret(secrets.conf), disabled: false, public: false, metadata: null }],
    ['pub_1', { clientId: 'pub_1', clientSecret: null, disabled: false, public: true, metadata: null }],
    ['app_1', { clientId: 'app_1', clientSecret: null, disabled: false, public: true, metadata: null }],
  ]);
  consents = new Map([['user_1:app_1', { scopes: ['tinycloud:mcp'], createdAt: CONSENT_AT }]]);
  sessions = new Map([['sess_1', { id: 'sess_1', userId: 'user_1', expiresAt: new Date(NOW_MS + 3_600_000) }]]);
  router = makeRouter();
});

// ---- tokens and requests ---------------------------------------------------------
type Claims = Record<string, unknown>;
async function mint(claims: Claims = {}, options: { signer?: Signer; issuer?: string; expiresIn?: number; issuedAt?: number | null } = {}): Promise<string> {
  const using = options.signer ?? signer;
  const payload: Claims = {
    sub: 'user_1', azp: 'app_1', sid: 'sess_1', scope: 'tinycloud:mcp', aud: RESOURCE,
    'https://tinycloud.xyz/owner_dids': ['did:pkh:eip155:1:0x0000000000000000000000000000000000000001'],
    ...claims,
  };
  const jwt = new SignJWT(payload as never)
    .setProtectedHeader({ alg: 'EdDSA', kid: using.jwk.kid })
    .setIssuer(options.issuer ?? ISSUER)
    .setExpirationTime(NOW_S + (options.expiresIn ?? 300));
  // `issuedAt: null` leaves `iat` out.
  if (options.issuedAt !== null) jwt.setIssuedAt(options.issuedAt ?? NOW_S - 10);
  return jwt.sign(using.privateKey);
}

const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;
const FORM = 'application/x-www-form-urlencoded';

function call(token: string | undefined, init: { auth?: string | null; form?: Record<string, string>; contentType?: string; headers?: Record<string, string>; rawBody?: string } = {}) {
  const auth = init.auth === undefined ? basic('rs_1', secrets.rs) : init.auth;
  const params = new URLSearchParams(init.form ?? {});
  if (token !== undefined) params.append('token', token);
  return router.request('/', {
    method: 'POST',
    headers: { 'content-type': init.contentType ?? FORM, ...(auth ? { authorization: auth } : {}), ...init.headers },
    body: init.rawBody ?? params.toString(),
  });
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

const INACTIVE = { active: false };

describe('a live token', () => {
  test('answers active with exactly the RFC 7662 fields and nothing else', async () => {
    const token = await mint();
    const response = await call(token);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toContain('application/json');
    expect(await json(response)).toEqual({
      active: true, scope: 'tinycloud:mcp', client_id: 'app_1', sub: 'user_1', aud: RESOURCE,
      exp: NOW_S + 300, iat: NOW_S - 10, iss: ISSUER, token_type: 'Bearer',
    });
  });

  test('carries no claim beyond the listed ones, whatever the token holds', async () => {
    const token = await mint({ email: 'a@example.test', name: 'A', jti: 'x', nonce: 'n', extra: { nested: true } });
    const body = await json(await call(token));
    expect(Object.keys(body).sort()).toEqual(['active', 'aud', 'client_id', 'exp', 'iat', 'iss', 'scope', 'sub', 'token_type']);
  });

  test('client authentication by HTTP Basic and by form fields both work', async () => {
    const token = await mint();
    expect((await json(await call(token, { auth: basic('rs_1', secrets.rs) }))).active).toBe(true);
    expect((await json(await call(token, { auth: null, form: { client_id: 'rs_1', client_secret: secrets.rs } }))).active).toBe(true);
  });

  test('another registered resource server with the same resource may check the same token', async () => {
    expect((await json(await call(await mint(), { auth: basic('rs_2', secrets.rs2) }))).active).toBe(true);
  });

  test('only the audiences the server is allowed are reported, as an array when the token has an array', async () => {
    expect((await json(await call(await mint({ aud: [RESOURCE, USERINFO] })))).aud).toEqual([RESOURCE]);
    expect((await json(await call(await mint({ aud: [RESOURCE] })))).aud).toEqual([RESOURCE]);
    expect((await json(await call(await mint({ aud: [RESOURCE, OTHER_RESOURCE, USERINFO] })))).aud).toEqual([RESOURCE]);
  });

  test('a string audience is reported as a string', async () => {
    expect((await json(await call(await mint({ aud: RESOURCE })))).aud).toBe(RESOURCE);
  });

  test('a token whose audiences the server may not check at all is inactive, however many it carries', async () => {
    expect(await json(await call(await mint({ aud: [OTHER_RESOURCE, USERINFO] })))).toEqual(INACTIVE);
    expect(await json(await call(await mint({ aud: [CHATGPT_RESOURCE, USERINFO] })))).toEqual(INACTIVE);
  });

  describe('a server registered for both the broad and the chatgpt MCP resource', () => {
    const both = { auth: basic('rs_both', secrets.both) };

    test.each([RESOURCE, CHATGPT_RESOURCE])('is told a token for %s is active', async (resource) => {
      const body = await json(await call(await mint({ aud: resource }), both));
      expect(body.active).toBe(true);
      expect(body.aud).toBe(resource);
    });

    test('gets the intersection of a token\'s audiences with its two resources', async () => {
      expect((await json(await call(await mint({ aud: [RESOURCE, CHATGPT_RESOURCE, USERINFO, OTHER_RESOURCE] }), both))).aud).toEqual([RESOURCE, CHATGPT_RESOURCE]);
      expect((await json(await call(await mint({ aud: [CHATGPT_RESOURCE, USERINFO] }), both))).aud).toEqual([CHATGPT_RESOURCE]);
    });

    test('a server registered for only the broad resource is not told about a chatgpt token', async () => {
      expect(await json(await call(await mint({ aud: CHATGPT_RESOURCE })))).toEqual(INACTIVE);
    });
  });
});

describe('a token whose standing has ended is inactive', () => {
  test.each([
    ['consent deleted', () => consents.delete('user_1:app_1')],
    ['consent no longer holds the token scope', () => consents.set('user_1:app_1', { scopes: ['openid'], createdAt: CONSENT_AT })],
    ['session deleted (sign-out)', () => sessions.delete('sess_1')],
    ['session expired', () => sessions.set('sess_1', { id: 'sess_1', userId: 'user_1', expiresAt: new Date(NOW_MS - 1) })],
    ['session belongs to another user', () => sessions.set('sess_1', { id: 'sess_1', userId: 'user_2', expiresAt: new Date(NOW_MS + 60_000) })],
    ['issuing client disabled', () => clients.set('app_1', { ...clients.get('app_1')!, disabled: true })],
    ['issuing client deleted', () => clients.delete('app_1')],
  ] as Array<[string, () => void]>)('%s', async (_name, change) => {
    const token = await mint();
    expect((await json(await call(token))).active).toBe(true);
    change();
    const response = await call(token);
    expect(response.status).toBe(200);
    expect(await json(response)).toEqual(INACTIVE);
  });

  test('a token without a session id or subject is inactive', async () => {
    for (const claims of [{ sid: undefined }, { sub: undefined }, { azp: undefined }, { scope: undefined }]) {
      expect(await json(await call(await mint(claims)))).toEqual(INACTIVE);
    }
  });
});

describe('a consent that was withdrawn and given again', () => {
  const at = (secondsFromNow: number, extraMs = 0) => new Date((NOW_S + secondsFromNow) * 1000 + extraMs);
  /** Disconnect, then reconnect: the old row is deleted and a new one is created at `createdAt`. */
  const reconnect = (createdAt: Date) => {
    consents.delete('user_1:app_1');
    consents.set('user_1:app_1', { scopes: ['tinycloud:mcp'], createdAt });
  };

  test('a token issued before the new consent is inactive, and one issued after it is active', async () => {
    const old = await mint({}, { issuedAt: NOW_S - 120 });
    expect((await json(await call(old))).active).toBe(true);
    reconnect(at(-60));
    const response = await call(old);
    expect(response.status).toBe(200);
    expect(await json(response)).toEqual(INACTIVE);
    expect((await json(await call(await mint({}, { issuedAt: NOW_S - 30 })))).active).toBe(true);
  });

  test('whole seconds are compared: a token from the second the consent was created stays active, one from the second before does not', async () => {
    reconnect(at(-100, 999));
    expect((await json(await call(await mint({}, { issuedAt: NOW_S - 100 })))).active).toBe(true);
    expect(await json(await call(await mint({}, { issuedAt: NOW_S - 101 })))).toEqual(INACTIVE);
  });

  test('a token issued a moment before a consent created in the next second is inactive', async () => {
    reconnect(at(-99));
    expect(await json(await call(await mint({}, { issuedAt: NOW_S - 100 })))).toEqual(INACTIVE);
  });

  test('a token with no iat is inactive', async () => {
    expect(await json(await call(await mint({}, { issuedAt: null })))).toEqual(INACTIVE);
  });

  test('a consent time that cannot be read ends the token', async () => {
    const token = await mint();
    consents.set('user_1:app_1', { scopes: ['tinycloud:mcp'], createdAt: new Date(Number.NaN) });
    expect(await json(await call(token))).toEqual(INACTIVE);
    consents.set('user_1:app_1', { scopes: ['tinycloud:mcp'], createdAt: 'not a date' as unknown as Date });
    expect(await json(await call(token))).toEqual(INACTIVE);
  });
});

describe('audience', () => {
  test('a token for a resource the server is not allowed to check is inactive', async () => {
    expect(await json(await call(await mint({ aud: OTHER_RESOURCE })))).toEqual(INACTIVE);
  });

  test('an allowed resource this server does not issue tokens for is never active', async () => {
    clients.set('rs_1', { ...clients.get('rs_1')!, metadata: resourceServerMetadata(['https://elsewhere.example/mcp']) });
    expect(await json(await call(await mint({ aud: 'https://elsewhere.example/mcp' })))).toEqual(INACTIVE);
  });

  test('a token with no audience is inactive', async () => {
    expect(await json(await call(await mint({ aud: undefined })))).toEqual(INACTIVE);
  });
});

describe('a bad token is a 200 inactive, never an error', () => {
  async function cases(): Promise<Array<[string, string | undefined, Parameters<typeof call>[1]?]>> {
    const good = await mint();
    const [header, payload, signature] = good.split('.') as [string, string, string];
    const flip = (value: string) => value.slice(0, 10) + (value[10] === 'A' ? 'B' : 'A') + value.slice(11);
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    return [
      ['empty token', ''],
      ['no token field', undefined],
      ['not a JWT', 'not-a-token-at-all'],
      ['two segments', 'aaaa.bbbb'],
      ['four segments', 'a.b.c.d'],
      ['garbage JWT shape', 'aaa.bbb.ccc'],
      ['tampered payload', `${header}.${flip(payload)}.${signature}`],
      ['tampered signature', `${header}.${payload}.${flip(signature)}`],
      ['tampered header', `${flip(header)}.${payload}.${signature}`],
      ['signed by another key under a known key id', await mint({}, { signer: { ...otherSigner, jwk: { ...otherSigner.jwk, kid: 'key-1' } } })],
      ['signed by an unknown key', await mint({}, { signer: otherSigner })],
      ['another issuer', await mint({}, { issuer: 'https://evil.example/api/auth' })],
      ['expired', await mint({}, { expiresIn: -5 })],
      ['not yet valid', await mint({ nbf: NOW_S + 3600 })],
      ['alg none', `${noneHeader}.${payload}.`],
      ['alg none with a signature part', `${noneHeader}.${payload}.${signature}`],
      ['oversized token', `${header}.${'A'.repeat(9 * 1024)}.${signature}`],
      ['non-ASCII token', `${header}.${payload}.sig\u0000nature`],
      ['token in a non-form body', good, { contentType: 'application/json', rawBody: JSON.stringify({ token: good }) }],
      ['two token fields', good, { form: { token: good } }],
      ['body over the size cap', good, { form: { padding: 'x'.repeat(20 * 1024) } }],
    ];
  }

  test('every shape of bad input answers 200 {"active":false}', async () => {
    for (const [name, token, init] of await cases()) {
      const response = await call(token, init);
      expect(response.status, name).toBe(200);
      expect(await json(response), name).toEqual(INACTIVE);
    }
  });
});

describe('client authentication', () => {
  const invalidClient = (description: string) => ({ error_description: description, error: 'invalid_client' });

  test.each([
    ['no credentials', { auth: null }, 'missing required credentials'],
    ['a wrong secret', { auth: basic('rs_1', 'wrong-secret') }, 'invalid client credentials'],
    ['an unknown client', { auth: basic('nobody', secrets.rs) }, 'invalid client credentials'],
    ['a public client', { auth: basic('pub_1', secrets.rs) }, 'invalid client credentials'],
    ['a confidential client that is not a resource server', { auth: basic('conf_1', secrets.conf) }, 'invalid client credentials'],
    ['malformed Basic', { auth: 'Basic !!!not-base64:' }, 'missing required credentials'],
    ['Basic without a secret', { auth: `Basic ${Buffer.from('rs_1:').toString('base64')}` }, 'missing required credentials'],
    ['Basic and a form secret together', { auth: basic('rs_1', secrets.rs), form: { client_secret: secrets.rs } }, 'missing required credentials'],
    ['Basic for one client and a form id for another', { auth: basic('rs_1', secrets.rs), form: { client_id: 'rs_2' } }, 'missing required credentials'],
    ['form credentials with no secret', { auth: null, form: { client_id: 'rs_1' } }, 'missing required credentials'],
  ] as Array<[string, Parameters<typeof call>[1], string]>)('%s is a 401 invalid_client, even with a live token', async (_name, init, description) => {
    const response = await call(await mint(), init);
    expect(response.status).toBe(401);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('www-authenticate')).toContain('Basic');
    expect(await json(response)).toEqual(invalidClient(description));
  });

  test('a repeated form secret is a 401', async () => {
    const token = await mint();
    const response = await router.request('/', {
      method: 'POST', headers: { 'content-type': FORM },
      body: `client_id=rs_1&client_secret=${secrets.rs}&client_secret=${secrets.rs}&token=${token}`,
    });
    expect(response.status).toBe(401);
    expect(await json(response)).toEqual(invalidClient('missing required credentials'));
  });

  test('a disabled resource server is a 401', async () => {
    clients.set('rs_1', { ...clients.get('rs_1')!, disabled: true });
    expect((await call(await mint())).status).toBe(401);
  });

  test('a public client row is never accepted, even with a stored secret and a registration', async () => {
    clients.set('rs_1', { ...clients.get('rs_1')!, public: true });
    expect((await call(await mint())).status).toBe(401);
  });

  test('a registration with no allowed resources is a 401', async () => {
    clients.set('rs_1', { ...clients.get('rs_1')!, metadata: { tinycloudResourceServer: { allowedResources: [] } } });
    expect((await call(await mint())).status).toBe(401);
  });

  test('the secret is compared against the stored hash, not the stored value', async () => {
    clients.set('rs_1', { ...clients.get('rs_1')!, clientSecret: secrets.rs });
    expect((await call(await mint())).status).toBe(401);
  });
});

describe('failures on our side are 503, so the caller fails closed', () => {
  test('a database error', async () => {
    const token = await mint();
    failDatabase = true;
    const response = await call(token);
    expect(response.status).toBe(503);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await json(response)).toEqual({ error: 'temporarily_unavailable' });
  });

  test('signing keys that cannot be read', async () => {
    const token = await mint();
    failJwks = true;
    const response = await call(token);
    expect(response.status).toBe(503);
    expect(await json(response)).toEqual({ error: 'temporarily_unavailable' });
  });

  test('a token that is not even shaped like a JWT needs no signing keys', async () => {
    failJwks = true;
    expect(await json(await call('not-a-token'))).toEqual(INACTIVE);
  });
});

describe('signing keys', () => {
  test('are cached between requests', async () => {
    const token = await mint();
    await call(token);
    await call(token);
    await call(token);
    expect(jwksCalls).toBe(1);
  });

  test('a key published after the cache was filled is picked up once, at most every few seconds', async () => {
    await call(await mint());
    expect(jwksCalls).toBe(1);
    jwksKeys = [signer.jwk, otherSigner.jwk];
    clock += 11_000;
    expect((await json(await call(await mint({}, { signer: otherSigner })))).active).toBe(true);
    expect(jwksCalls).toBe(2);
    // A key that does not exist is not looked for again within the pause, only after it.
    const stranger = await newSigner('key-3');
    expect(await json(await call(await mint({}, { signer: stranger })))).toEqual(INACTIVE);
    expect(jwksCalls).toBe(2);
    clock += 11_000;
    expect(await json(await call(await mint({}, { signer: stranger })))).toEqual(INACTIVE);
    expect(jwksCalls).toBe(3);
    expect(await json(await call(await mint({}, { signer: stranger })))).toEqual(INACTIVE);
    expect(jwksCalls).toBe(3);
  });
});

describe('rate limits', () => {
  test('one resource server is limited per window, others are not, and the window resets', async () => {
    router = makeRouter({ authenticatedPerWindow: 3 });
    const token = await mint();
    for (let i = 0; i < 3; i++) expect((await call(token)).status).toBe(200);
    const limited = await call(token);
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(limited.headers.get('cache-control')).toBe('no-store');
    expect(await json(limited)).toEqual({ error: 'too_many_requests' });
    expect((await call(token, { auth: basic('rs_2', secrets.rs2) })).status).toBe(200);
    clock += 61_000;
    expect((await call(token)).status).toBe(200);
  });

  test('failed client authentication is limited per source address, and a valid client is not caught by it', async () => {
    router = makeRouter({ failedAuthPerWindow: 2 });
    const token = await mint();
    const bad = (address: string) => call(token, { auth: basic('rs_1', 'wrong'), headers: { 'cf-connecting-ip': address } });
    expect((await bad('203.0.113.7')).status).toBe(401);
    expect((await bad('203.0.113.7')).status).toBe(401);
    const limited = await bad('203.0.113.7');
    expect(limited.status).toBe(429);
    expect(await json(limited)).toEqual({ error: 'too_many_requests' });
    expect((await bad('203.0.113.8')).status).toBe(401);
    // The right secret from the limited address still works.
    expect((await call(token, { headers: { 'cf-connecting-ip': '203.0.113.7' } })).status).toBe(200);
    clock += 61_000;
    expect((await bad('203.0.113.7')).status).toBe(401);
  });

  test('a registration can set its own limit, which replaces the default for that client only', async () => {
    router = makeRouter({ authenticatedPerWindow: 5 });
    const token = await mint();
    const slow = { auth: basic('rs_slow', secrets.slow) };
    expect((await call(token, slow)).status).toBe(200);
    expect((await call(token, slow)).status).toBe(200);
    const limited = await call(token, slow);
    expect(limited.status).toBe(429);
    expect(await json(limited)).toEqual({ error: 'too_many_requests' });
    // A client without a setting of its own gets the router's default (5 here), more than the 2 above.
    for (let i = 0; i < 5; i++) expect((await call(token)).status).toBe(200);
    expect((await call(token)).status).toBe(429);
    clock += 61_000;
    expect((await call(token, slow)).status).toBe(200);
  });

  test('a registration may raise its limit above the default', async () => {
    router = makeRouter({ authenticatedPerWindow: 2 });
    clients.set('rs_fast', { clientId: 'rs_fast', clientSecret: hashClientSecret(secrets.rs), disabled: false, public: false, metadata: resourceServerMetadata([RESOURCE], { rateLimitPerMinute: 4 }) });
    const token = await mint();
    for (let i = 0; i < 4; i++) expect((await call(token, { auth: basic('rs_fast', secrets.rs) })).status).toBe(200);
    expect((await call(token, { auth: basic('rs_fast', secrets.rs) })).status).toBe(429);
  });

  test('the default is 3000 requests per client and 20 failures per address in a minute', async () => {
    router = makeRouter();
    const token = await mint();
    for (let i = 0; i < 3000; i++) expect((await call(token)).status).toBe(200);
    expect((await call(token)).status).toBe(429);
    expect((await call(token, { auth: basic('rs_2', secrets.rs2) })).status).toBe(200);
    const failures: number[] = [];
    for (let i = 0; i < 21; i++) failures.push((await call(token, { auth: basic('rs_2', 'wrong'), headers: { 'x-forwarded-for': '198.51.100.9, 10.0.0.1' } })).status);
    expect(failures.slice(0, 20).every((status) => status === 401)).toBe(true);
    expect(failures[20]).toBe(429);
  });
});
