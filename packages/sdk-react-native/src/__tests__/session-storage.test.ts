/**
 * Interleaving tests for the CAS session storage model: every write and
 * remove of the stored session is a compare-and-set inside the storage
 * queue, against a fake OpenKey server that tracks grants and refresh
 * tokens the way the spec does (current/previous token, grant status).
 */
import { describe, it, expect } from 'bun:test';
import { OpenKeyRN } from '../OpenKeyRN';
import type { BrowserOpener, BrowserResult, OpenKeyRNFullConfig } from '../OpenKeyRN';
import type { OpenKeySecureStore } from '../types';
import {
  OpenKeyNativeError,
  base64UrlDecode,
  generateSessionKeypair,
  sessionDidForPublicKey,
} from '@openkey/core';
import type {
  NativeDelegationPermission,
  NativeFetch,
  NativeFetchInit,
  NativeSessionKeypair,
} from '@openkey/core';

const ISSUER = 'https://auth.example.com/api/auth';
const CLIENT_ID = 'test-client-id';
const REDIRECT_URI = 'myapp://callback';
const TC_HOST = 'https://tee.node.tinycloud.xyz';
const SESSION_KEY = `openkey:tinycloud-delegation:${CLIENT_ID}`;
const PENDING_KEY = `openkey:tinycloud-delegation-pending-revoke:${CLIENT_ID}`;
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

const METADATA = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/oauth2/authorize`,
  token_endpoint: `${ISSUER}/oauth2/token`,
  pushed_authorization_request_endpoint: `${ISSUER}/oauth2/par`,
  tinycloud_delegation_renew_endpoint: `${ISSUER}/oauth2/tinycloud/renew`,
  tinycloud_delegation_revocation_endpoint: `${ISSUER}/oauth2/tinycloud/revoke`,
  code_challenge_methods_supported: ['S256'],
  authorization_response_iss_parameter_supported: true,
};

const KV_PERMISSION: NativeDelegationPermission = {
  service: 'tinycloud.kv',
  space: 'applications',
  path: 'xyz.tinycloud.testapp/threads/',
  actions: ['tinycloud.kv/get', 'tinycloud.kv/put'],
};
const CAP_READ: NativeDelegationPermission = {
  service: 'tinycloud.capabilities',
  space: 'applications',
  path: '',
  actions: ['tinycloud.capabilities/read'],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function memoryStore(): OpenKeySecureStore & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    get: (key) => Promise.resolve(map.get(key) ?? null),
    set: (key, value) => {
      map.set(key, value);
      return Promise.resolve();
    },
    remove: (key) => {
      map.delete(key);
      return Promise.resolve();
    },
  };
}

/**
 * A store object over `map`. `pause` is awaited at the start of every call
 * (e.g. to hand the step to a scheduler), so calls from different instances
 * interleave; `cas` adds an atomic compareAndSet.
 */
function backendStore(
  map: Map<string, string>,
  opts: { cas?: boolean; pause?: () => Promise<void> } = {},
): OpenKeySecureStore & { map: Map<string, string> } {
  const pause = async () => {
    await opts.pause?.();
  };
  const store: OpenKeySecureStore & { map: Map<string, string> } = {
    map,
    get: async (key) => {
      await pause();
      return map.get(key) ?? null;
    },
    set: async (key, value) => {
      await pause();
      map.set(key, value);
    },
    remove: async (key) => {
      await pause();
      map.delete(key);
    },
  };
  if (opts.cas) {
    store.compareAndSet = async (key, expected, next) => {
      await pause();
      // Atomic: the check and the write happen in one synchronous step.
      if ((map.get(key) ?? null) !== expected) return false;
      if (next === null) map.delete(key);
      else map.set(key, next);
      return true;
    };
  }
  return store;
}

function storedSid(store: { map: Map<string, string> }): string | null {
  const raw = store.map.get(SESSION_KEY);
  return raw ? (JSON.parse(raw) as { privateJwk: { x: string } }).privateJwk.x : null;
}

function storedToken(store: { map: Map<string, string> }): string | null {
  const raw = store.map.get(SESSION_KEY);
  return raw ? (JSON.parse(raw) as { refreshToken: string }).refreshToken : null;
}

function pendingTokens(store: { map: Map<string, string> }): string[] {
  const raw = store.map.get(PENDING_KEY);
  return raw ? (JSON.parse(raw) as { refreshToken: string }[]).map((e) => e.refreshToken) : [];
}

async function rejection(promise: Promise<unknown>): Promise<OpenKeyNativeError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(OpenKeyNativeError);
    return error as OpenKeyNativeError;
  }
  throw new Error('expected a rejection');
}

type TokenStatus = 'current' | 'previous' | 'dead';

/**
 * Fake authorization server. A grant is identified by its session id (the
 * session public key `x`). Renew rotates current → previous; renewing with
 * the previous token is `renewal_conflict`; revoke accepts the current or
 * previous token and revokes the grant (spec).
 */
class FakeServer {
  private n = 0;
  private pars = new Map<string, { state: string; sid: string; permissions: NativeDelegationPermission[] }>();
  readonly tokens = new Map<string, { sid: string; status: TokenStatus }>();
  readonly grants = new Map<string, 'active' | 'revoked'>();
  readonly revokeCalls: string[] = [];
  readonly renewCalls: string[] = [];
  /** Refresh tokens issued by renew / code exchange, in order. */
  readonly renewIssued: string[] = [];
  readonly exchangeIssued: string[] = [];
  /** Sids that received a terminal (4xx) revoke response. */
  readonly terminalRevokeSids = new Set<string>();
  /** Renews that rotate but answer `hosting: "failed"` (terminal). */
  hostingFailedRenews = 0;
  /** Exchanges whose delegation is already inside the renewal lead window. */
  leadWindowExchanges = 0;
  revokeFailRate = 0;
  rng: () => number = Math.random;
  /** Awaited before every request is handled (scheduler / gates). */
  gate: (url: string) => Promise<void> = () => Promise.resolve();
  /** Awaited after a request is handled, before its response returns. */
  responseGate: (url: string) => Promise<void> = () => Promise.resolve();

  private issue(sid: string): string {
    const token = `rt-${sid.slice(0, 6)}-${++this.n}`;
    for (const info of this.tokens.values()) {
      if (info.sid !== sid) continue;
      if (info.status === 'previous') info.status = 'dead';
      else if (info.status === 'current') info.status = 'previous';
    }
    this.tokens.set(token, { sid, status: 'current' });
    return token;
  }

  /** A signed-in session A already in `store`, with an active grant. */
  async seedSession(store: OpenKeySecureStore): Promise<{ sessionKey: NativeSessionKeypair; token: string }> {
    const sessionKey = generateSessionKeypair();
    const sid = sessionKey.publicJwk.x;
    this.grants.set(sid, 'active');
    const token = this.issue(sid);
    await store.set(SESSION_KEY, JSON.stringify({
      privateJwk: sessionKey.privateJwk,
      refreshToken: token,
      permissions: [CAP_READ, KV_PERMISSION],
    }));
    return { sessionKey, token };
  }

  /** A grant left in the pending-revoke record by an earlier signOut(). */
  async seedPending(store: OpenKeySecureStore): Promise<string> {
    const sessionKey = generateSessionKeypair();
    const sid = sessionKey.publicJwk.x;
    this.grants.set(sid, 'active');
    const token = this.issue(sid);
    await store.set(PENDING_KEY, JSON.stringify([
      { privateJwk: sessionKey.privateJwk, refreshToken: token, attempts: 1, expiresAt: Date.now() + SEVEN_DAYS_MS },
    ]));
    return sid;
  }

  private delegation(sid: string, permissions: NativeDelegationPermission[], leadWindow = false) {
    const did = sessionDidForPublicKey(base64UrlDecode(sid));
    return {
      verificationMethod: `${did}#${did.slice('did:key:'.length)}`,
      issuedAt: new Date(Date.now() - (leadWindow ? 3_600_000 : 0)).toISOString(),
      expiresAt: new Date(Date.now() + (leadWindow ? 60_000 : 3_600_000)).toISOString(),
      renewableUntil: new Date(Date.now() + 86_400_000).toISOString(),
      permissions,
      tinycloudHost: TC_HOST,
    };
  }

  liveSids(): string[] {
    return [...this.grants].filter(([, status]) => status === 'active').map(([sid]) => sid);
  }

  sidOf(token: string): string | undefined {
    return this.tokens.get(token)?.sid;
  }

  isCurrent(token: string): boolean {
    const info = this.tokens.get(token);
    return info?.status === 'current' && this.grants.get(info.sid) === 'active';
  }

  readonly fetch: NativeFetch = async (url: string, init?: NativeFetchInit) => {
    await this.gate(url);
    const response = await this.handle(url, init);
    await this.responseGate(url);
    return response;
  };

  private async handle(url: string, init?: NativeFetchInit): Promise<Response> {
    const body = new URLSearchParams(init?.body ?? '');
    if (url.includes('/.well-known/')) return jsonResponse(METADATA);
    if (url.endsWith('/oauth2/par')) {
      const details = JSON.parse(body.get('authorization_details')!) as {
        session_key: { x: string };
        permissions: NativeDelegationPermission[];
      }[];
      const id = `req-${++this.n}`;
      this.pars.set(id, { state: body.get('state')!, sid: details[0]!.session_key.x, permissions: details[0]!.permissions });
      return jsonResponse({ request_uri: `urn:ietf:params:oauth:request_uri:${id}`, expires_in: 90 }, 201);
    }
    if (url.endsWith('/oauth2/token')) {
      const par = this.pars.get(body.get('code')!)!;
      this.grants.set(par.sid, 'active');
      const leadWindow = this.leadWindowExchanges > 0;
      if (leadWindow) this.leadWindowExchanges -= 1;
      const refreshToken = this.issue(par.sid);
      this.exchangeIssued.push(refreshToken);
      return jsonResponse({
        access_token: `at-${par.sid.slice(0, 6)}`,
        refresh_token: refreshToken,
        expires_in: 300,
        tinycloud_delegation: this.delegation(par.sid, par.permissions, leadWindow),
      });
    }
    if (url.endsWith('/oauth2/tinycloud/renew')) {
      const token = body.get('refresh_token')!;
      this.renewCalls.push(token);
      const info = this.tokens.get(token);
      if (!info || this.grants.get(info.sid) !== 'active' || info.status === 'dead') {
        return jsonResponse({ error: 'invalid_grant' }, 400);
      }
      if (info.status === 'previous') return jsonResponse({ error: 'renewal_conflict' }, 409);
      const details = body.get('authorization_details');
      const permissions = details
        ? (JSON.parse(details) as { permissions: NativeDelegationPermission[] }[])[0]!.permissions
        : [CAP_READ, KV_PERMISSION];
      const delegation: Record<string, unknown> = this.delegation(info.sid, permissions);
      if (this.hostingFailedRenews > 0) {
        this.hostingFailedRenews -= 1;
        delegation.hosting = 'failed';
      }
      const refreshToken = this.issue(info.sid);
      this.renewIssued.push(refreshToken);
      return jsonResponse({ refresh_token: refreshToken, tinycloud_delegation: delegation });
    }
    if (url.endsWith('/oauth2/tinycloud/revoke')) {
      const token = body.get('refresh_token')!;
      this.revokeCalls.push(token);
      const info = this.tokens.get(token);
      if (!info || info.status === 'dead') {
        if (info) this.terminalRevokeSids.add(info.sid);
        return jsonResponse({ error: 'invalid_grant' }, 400);
      }
      if (this.rng() < this.revokeFailRate) {
        return jsonResponse({ error: 'temporarily_unavailable' }, 503);
      }
      this.grants.set(info.sid, 'revoked');
      return new Response(null, { status: 200 });
    }
    throw new Error(`unexpected fetch: ${url}`);
  }

  /** Opener that completes the authorization for the PAR it was given. */
  readonly openBrowser: BrowserOpener = async (url: string): Promise<BrowserResult | void> => {
    const requestUri = new URL(url).searchParams.get('request_uri')!;
    const id = requestUri.split(':').pop()!;
    const state = this.pars.get(id)!.state;
    const query = new URLSearchParams({ code: id, state, iss: ISSUER });
    return { type: 'success', url: `${REDIRECT_URI}?${query.toString()}` };
  };

  client(store: OpenKeySecureStore, overrides?: Partial<OpenKeyRNFullConfig>): OpenKeyRN {
    return new OpenKeyRN({
      host: 'https://auth.example.com',
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      openBrowser: this.openBrowser,
      delegation: {
        permissions: [KV_PERMISSION],
        tinycloudHost: TC_HOST,
        storage: store,
        verifyDelegation: () => Promise.resolve(),
        fetchFn: this.fetch,
        sleepFn: () => Promise.resolve(),
      },
      ...overrides,
    });
  }
}

/**
 * Hold the first request matching `match` until released — before the
 * server handles it, or (`response`) after the server handled it, so its
 * effect (e.g. a rotation) has happened but the client hasn't seen it.
 */
function holdFirst(
  server: FakeServer,
  match: (url: string) => boolean,
  phase: 'request' | 'response' = 'request',
) {
  const reached = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  let held = false;
  server[phase === 'request' ? 'gate' : 'responseGate'] = async (url) => {
    if (!held && match(url)) {
      held = true;
      reached.resolve();
      await release.promise;
    }
  };
  return { reached: reached.promise, release: () => release.resolve() };
}

describe('CAS session storage model', () => {
  it('signOut() signs out a session another instance stored mid-revoke', async () => {
    const server = new FakeServer();
    const store = memoryStore();
    const { sessionKey: keyA } = await server.seedSession(store);
    const signingOut = server.client(store);
    const other = server.client(store); // e.g. a second instance sharing the store
    const hold = holdFirst(server, (url) => url.endsWith('/revoke'));

    const out = signingOut.signOut();
    await hold.reached; // A's revoke is in flight
    await other.signIn(); // B lands in storage mid-revoke
    const sidB = storedSid(store)!;
    expect(sidB).not.toBe(keyA.publicJwk.x);
    hold.release();
    await out;

    // signOut signs out whatever is current: B is revoked and removed too.
    expect(store.map.has(SESSION_KEY)).toBe(false);
    expect(server.liveSids()).toEqual([]);
  });

  it('a signIn() started after signOut() saves after it and survives', async () => {
    const server = new FakeServer();
    const store = memoryStore();
    const { sessionKey: keyA } = await server.seedSession(store);
    const client = server.client(store);
    const hold = holdFirst(server, (url) => url.endsWith('/revoke'));
    const exchanged = Promise.withResolvers<void>();
    const holdGate = server.gate;
    server.gate = async (url) => {
      await holdGate(url);
      if (url.endsWith('/oauth2/token')) exchanged.resolve();
    };

    const out = client.signOut();
    await hold.reached; // A's revoke is in flight
    const signIn = client.signIn(); // started after signOut()
    await exchanged.promise; // B's code exchange is done before A's revoke
    for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
    hold.release();
    await out;
    const tokens = await signIn;

    // B was saved after signOut() finished, so signOut() never removed it.
    expect(server.grants.get(keyA.publicJwk.x)).toBe('revoked');
    expect(storedToken(store)).toBe(tokens.refreshToken);
    expect(server.isCurrent(tokens.refreshToken)).toBe(true);
  });

  it("an immediate renew never overwrites a newer sign-in's session", async () => {
    const server = new FakeServer();
    const store = memoryStore();
    const client = server.client(store);
    server.leadWindowExchanges = 1; // the first sign-in renews immediately
    const hold = holdFirst(server, (url) => url.endsWith('/renew'), 'response');

    const first = client.signIn();
    first.catch(() => {});
    await hold.reached; // B saved; the server rotated B, response in flight
    const second = await client.signIn(); // C replaces B (B is revoked)
    hold.release();

    const thrown = await rejection(first);
    expect(thrown.code).toBe('NOT_SIGNED_IN');
    // The abandoned token is not a recovery token: it is not on the error.
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    // C is intact; B's rotated token was abandoned, not written over C.
    expect(storedToken(store)).toBe(second.refreshToken);
    expect(server.revokeCalls).toContain(server.renewIssued[0]!);
    expect(server.liveSids()).toEqual([server.sidOf(second.refreshToken)!]);
  });

  it("a rotated-token recovery write never overwrites a newer sign-in's session", async () => {
    const server = new FakeServer();
    const store = memoryStore();
    const { sessionKey: keyA } = await server.seedSession(store);
    const client = server.client(store);
    const hold = holdFirst(server, (url) => url.endsWith('/renew'), 'response');
    const verifying = new OpenKeyRN({
      host: 'https://auth.example.com',
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      openBrowser: server.openBrowser,
      delegation: {
        permissions: [KV_PERMISSION],
        tinycloudHost: TC_HOST,
        storage: store,
        // A's renewed delegation fails verification (non-terminal, with
        // the rotated token on the error).
        verifyDelegation: (d) =>
          d.verificationMethod === keyA.keyId
            ? Promise.reject(new Error('cid mismatch'))
            : Promise.resolve(),
        fetchFn: server.fetch,
        sleepFn: () => Promise.resolve(),
      },
    });

    const renew = verifying.renew();
    renew.catch(() => {});
    await hold.reached;
    const signedIn = await client.signIn(); // C replaces A
    hold.release();

    const thrown = await rejection(renew);
    expect(thrown.code).toBe('SERVER');
    // The refused recovery write abandoned the rotated token, so the
    // SERVER error no longer carries it.
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect(storedToken(store)).toBe(signedIn.refreshToken);
    // A was replaced (and revoked); its rotated token was abandoned too.
    expect(server.revokeCalls).toContain(server.renewIssued[0]!);
    expect(server.liveSids()).toEqual([server.sidOf(signedIn.refreshToken)!]);
  });

  it('renew() always uses the stored session, never an older in-memory one', async () => {
    const server = new FakeServer();
    const store = memoryStore();
    await server.seedSession(store);
    const first = server.client(store);
    const second = server.client(store);

    await first.renew(); // first has now used A
    const signedIn = await second.signIn(); // C replaces A in shared storage
    const renewed = await first.renew();

    expect(server.renewCalls.at(-1)).toBe(signedIn.refreshToken);
    expect(storedToken(store)).toBe(renewed.refreshToken);
    expect(server.sidOf(renewed.refreshToken)).toBe(server.sidOf(signedIn.refreshToken));
  });

  it('signIn() revokes the session it replaces', async () => {
    const server = new FakeServer();
    const store = memoryStore();
    const { sessionKey: keyA } = await server.seedSession(store);
    const tokens = await server.client(store).signIn();

    expect(server.grants.get(keyA.publicJwk.x)).toBe('revoked');
    expect(server.liveSids()).toEqual([server.sidOf(tokens.refreshToken)!]);
    expect(pendingTokens(store)).toEqual([]);
  });

  it('signIn() keeps a pending revoke for the replaced session when its revoke fails transiently', async () => {
    const server = new FakeServer();
    const store = memoryStore();
    const { sessionKey: keyA, token: tokenA } = await server.seedSession(store);
    server.revokeFailRate = 1;
    const tokens = await server.client(store).signIn();

    expect(storedToken(store)).toBe(tokens.refreshToken);
    const entries = JSON.parse(store.map.get(PENDING_KEY)!);
    expect(entries).toEqual([
      { privateJwk: keyA.privateJwk, refreshToken: tokenA, attempts: 1, expiresAt: expect.any(Number) },
    ]);
    expect(entries[0].expiresAt).toBeLessThanOrEqual(Date.now() + SEVEN_DAYS_MS);
  });

  it("a superseded renew's rotated grant becomes a pending revoke on a transient failure", async () => {
    const server = new FakeServer();
    const store = memoryStore();
    await server.seedSession(store);
    const client = server.client(store);
    const hold = holdFirst(server, (url) => url.endsWith('/renew'), 'response');

    const renew = client.renew();
    renew.catch(() => {});
    await hold.reached; // the server rotated A
    server.revokeFailRate = 1;
    const signedIn = await client.signIn(); // replaces A
    hold.release();

    const thrown = await rejection(renew);
    expect(thrown.code).toBe('NOT_SIGNED_IN');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect(storedToken(store)).toBe(signedIn.refreshToken);
    expect(pendingTokens(store)).toContain(server.renewIssued[0]!);
  });

  it("a terminal outcome's rotated grant becomes a pending revoke on a transient failure", async () => {
    const server = new FakeServer();
    const store = memoryStore();
    await server.seedSession(store);
    server.hostingFailedRenews = 1;
    server.revokeFailRate = 1;

    const thrown = await rejection(server.client(store).renew());
    expect(thrown.code).toBe('SPACE_UNAVAILABLE');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect(store.map.has(SESSION_KEY)).toBe(false);
    expect(pendingTokens(store)).toEqual([server.renewIssued[0]!]);
  });

  it("a sign-in's refused recovery write abandons the token and drops it from the error", async () => {
    const server = new FakeServer();
    const store = memoryStore();
    // Verification of the exchanged delegation fails (non-terminal SERVER
    // carrying the live token), but only after a signOut() has started, so
    // the recovery save is refused.
    const verifying = Promise.withResolvers<void>();
    const verdict = Promise.withResolvers<void>();
    const client = new OpenKeyRN({
      host: 'https://auth.example.com',
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      openBrowser: server.openBrowser,
      delegation: {
        permissions: [KV_PERMISSION],
        tinycloudHost: TC_HOST,
        storage: store,
        verifyDelegation: async () => {
          verifying.resolve();
          await verdict.promise;
          throw new Error('cid mismatch');
        },
        fetchFn: server.fetch,
        sleepFn: () => Promise.resolve(),
      },
    });

    const signIn = client.signIn();
    signIn.catch(() => {});
    await verifying.promise;
    await client.signOut();
    verdict.resolve();

    const thrown = await rejection(signIn);
    expect(thrown.code).toBe('SERVER');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect(store.map.has(SESSION_KEY)).toBe(false);
    expect(server.revokeCalls).toEqual([server.exchangeIssued[0]!]);
    expect(server.liveSids()).toEqual([]);
  });

  it('an orphaned exchange becomes a pending revoke on a transient failure', async () => {
    const server = new FakeServer();
    const store = memoryStore();
    const client = server.client(store);
    const hold = holdFirst(server, (url) => url.endsWith('/oauth2/token'), 'response');

    const signIn = client.signIn();
    signIn.catch(() => {});
    await hold.reached; // the server issued B's tokens
    server.revokeFailRate = 1;
    await client.signOut();
    hold.release();

    const thrown = await rejection(signIn);
    expect(thrown.code).toBe('NOT_SIGNED_IN');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect(store.map.has(SESSION_KEY)).toBe(false);
    const orphan = server.exchangeIssued[0]!;
    expect(pendingTokens(store)).toEqual([orphan]);
    expect(server.liveSids()).toEqual([server.sidOf(orphan)!]);
  });

  /** Store whose writes to the keys in `failing` reject. */
  function failingWrites(base: ReturnType<typeof memoryStore>, failing: string[]): OpenKeySecureStore {
    return {
      ...base,
      set: (key, value) =>
        failing.includes(key) ? Promise.reject(new Error('disk full')) : base.set(key, value),
    };
  }

  it('a failed session write revokes the grant instead of handing the token back', async () => {
    const server = new FakeServer();
    const base = memoryStore();
    const thrown = await rejection(server.client(failingWrites(base, [SESSION_KEY])).signIn());

    expect(thrown.code).toBe('STORAGE');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect(server.revokeCalls).toHaveLength(1);
    expect(server.liveSids()).toEqual([]);
    expect(pendingTokens(base)).toEqual([]);
  });

  it('a failed session write keeps a pending revoke when the revoke fails transiently', async () => {
    const server = new FakeServer();
    const base = memoryStore();
    const { sessionKey: keyA } = await server.seedSession(base);
    server.revokeFailRate = 1;
    const thrown = await rejection(server.client(failingWrites(base, [SESSION_KEY])).renew());

    expect(thrown.code).toBe('STORAGE');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    // The rotated token went to the pending-revoke record for a later retry.
    const [entry] = JSON.parse(base.map.get(PENDING_KEY)!);
    expect(server.sidOf(entry.refreshToken)).toBe(keyA.publicJwk.x);
    expect(server.isCurrent(entry.refreshToken)).toBe(true);
  });

  it('when the pending-revoke write fails too, the revoke was still attempted', async () => {
    const server = new FakeServer();
    const base = memoryStore();
    server.revokeFailRate = 1;
    const thrown = await rejection(
      server.client(failingWrites(base, [SESSION_KEY, PENDING_KEY])).signIn(),
    );

    expect(thrown.code).toBe('STORAGE');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    // Best effort is all that is left: the revoke was sent (and retried
    // once by core); nothing could be recorded.
    expect(server.revokeCalls).toHaveLength(2);
    expect(base.map.has(PENDING_KEY)).toBe(false);
  });

  it("renew(): a failed recovery write surfaces STORAGE (cause: the original error) and revokes the token", async () => {
    const server = new FakeServer();
    const base = memoryStore();
    const { sessionKey: keyA } = await server.seedSession(base);
    const client = new OpenKeyRN({
      host: 'https://auth.example.com',
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      openBrowser: server.openBrowser,
      delegation: {
        permissions: [KV_PERMISSION],
        tinycloudHost: TC_HOST,
        storage: failingWrites(base, [SESSION_KEY]),
        verifyDelegation: () => Promise.reject(new Error('cid mismatch')),
        fetchFn: server.fetch,
        sleepFn: () => Promise.resolve(),
      },
    });

    const thrown = await rejection(client.renew());
    // Local state could not be saved: STORAGE, with the verification
    // failure as its cause, and no token on either error.
    expect(thrown.code).toBe('STORAGE');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect(thrown.cause).toBeInstanceOf(OpenKeyNativeError);
    expect((thrown.cause as OpenKeyNativeError).code).toBe('SERVER');
    expect((thrown.cause as OpenKeyNativeError).rotatedRefreshToken).toBeUndefined();
    expect(server.grants.get(keyA.publicJwk.x)).toBe('revoked');
  });

  it('signIn(): a failed recovery write surfaces STORAGE (cause: the original error) and revokes the token', async () => {
    const server = new FakeServer();
    const base = memoryStore();
    // The exchanged delegation fails verification (SERVER with the live
    // token), and the recovery save of that token then fails to write.
    const client = new OpenKeyRN({
      host: 'https://auth.example.com',
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      issuer: ISSUER,
      openBrowser: server.openBrowser,
      delegation: {
        permissions: [KV_PERMISSION],
        tinycloudHost: TC_HOST,
        storage: failingWrites(base, [SESSION_KEY]),
        verifyDelegation: () => Promise.reject(new Error('cid mismatch')),
        fetchFn: server.fetch,
        sleepFn: () => Promise.resolve(),
      },
    });

    const thrown = await rejection(client.signIn());
    expect(thrown.code).toBe('STORAGE');
    expect(thrown.rotatedRefreshToken).toBeUndefined();
    expect((thrown.cause as OpenKeyNativeError).code).toBe('SERVER');
    expect((thrown.cause as OpenKeyNativeError).rotatedRefreshToken).toBeUndefined();
    expect(server.revokeCalls).toEqual([server.exchangeIssued[0]!]);
    expect(server.liveSids()).toEqual([]);
  });

  it('signOut(): a transient revoke plus a failed pending-revoke write is STORAGE, and nothing is removed', async () => {
    const server = new FakeServer();
    const base = memoryStore();
    const { token } = await server.seedSession(base);
    server.revokeFailRate = 1;
    const client = server.client(failingWrites(base, [PENDING_KEY]));

    const thrown = await rejection(client.signOut());
    expect(thrown.code).toBe('STORAGE');
    expect((thrown.cause as OpenKeyNativeError).code).toBe('TEMPORARILY_UNAVAILABLE');
    // The token could not be parked, so the session record (its only
    // copy) was kept for the next signOut().
    expect(storedToken(base)).toBe(token);
    expect(base.map.has(PENDING_KEY)).toBe(false);
  });

  it('signOut(): a transient revoke plus a failed session removal is STORAGE', async () => {
    const server = new FakeServer();
    const base = memoryStore();
    const { token } = await server.seedSession(base);
    server.revokeFailRate = 1;
    const store: OpenKeySecureStore = {
      ...base,
      remove: (key) =>
        key === SESSION_KEY ? Promise.reject(new Error('keychain locked')) : base.remove(key),
    };
    const client = server.client(store);

    const thrown = await rejection(client.signOut());
    expect(thrown.code).toBe('STORAGE');
    expect((thrown.cause as OpenKeyNativeError).code).toBe('TEMPORARILY_UNAVAILABLE');
    expect(pendingTokens(base)).toEqual([token]);
    expect(storedToken(base)).toBe(token);
  });

  /**
   * Sol's lost update across instances: instance A's renew reads the old
   * session for its save, instance B saves a new sign-in, then A writes.
   * `stores` gives each instance its store object.
   */
  async function lostUpdateRace(stores: [OpenKeySecureStore, OpenKeySecureStore], map: Map<string, string>) {
    const server = new FakeServer();
    await server.seedSession(stores[0]);
    const [first] = stores;
    // Hold A's save-time read of the session record.
    const readReached = Promise.withResolvers<void>();
    const readGate = Promise.withResolvers<void>();
    let armed = false;
    const gatedGet = first.get.bind(first);
    first.get = async (key) => {
      if (armed && key === SESSION_KEY) {
        armed = false;
        const value = map.get(key) ?? null; // read now, delivered later
        readReached.resolve();
        await readGate.promise;
        return value;
      }
      return gatedGet(key);
    };
    server.responseGate = async (url) => {
      if (url.endsWith('/renew')) armed = true;
    };
    const exchanged = Promise.withResolvers<void>();
    server.gate = async (url) => {
      if (url.endsWith('/oauth2/token')) exchanged.resolve();
    };

    const instanceA = server.client(stores[0]);
    const instanceB = server.client(stores[1]);
    const renew = instanceA.renew();
    renew.catch(() => {});
    await readReached.promise; // A holds a stale read of the old session
    const signIn = instanceB.signIn();
    await exchanged.promise;
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
    readGate.resolve();
    await renew.catch(() => {});
    const tokens = await signIn;
    return { server, tokens };
  }

  it('two instances on one store object never lose a sign-in', async () => {
    const map = new Map<string, string>();
    const store = backendStore(map);
    const { server, tokens } = await lostUpdateRace([store, store], map);

    // B's sign-in survives; A's renew landed before it, then was replaced.
    expect(storedSid({ map })).toBe(server.sidOf(tokens.refreshToken)!);
    expect(server.liveSids()).toEqual([server.sidOf(tokens.refreshToken)!]);
  });

  it('separate store objects with compareAndSet never lose a sign-in', async () => {
    const map = new Map<string, string>();
    const { server, tokens } = await lostUpdateRace(
      [backendStore(map, { cas: true }), backendStore(map, { cas: true })],
      map,
    );

    // A's write saw the record change under it, re-checked, and refused.
    expect(storedSid({ map })).toBe(server.sidOf(tokens.refreshToken)!);
    expect(server.liveSids()).toEqual([server.sidOf(tokens.refreshToken)!]);
  });

  it('signOut() rejects on a storage read failure and removes nothing', async () => {
    const server = new FakeServer();
    const base = memoryStore();
    const { token } = await server.seedSession(base);
    let failReads = false;
    const removed: string[] = [];
    const store: OpenKeySecureStore = {
      ...base,
      get: (key) =>
        failReads && key === SESSION_KEY
          ? Promise.reject(new Error('keychain locked'))
          : base.get(key),
      remove: (key) => {
        removed.push(key);
        return base.remove(key);
      },
    };
    const client = server.client(store);

    failReads = true;
    const thrown = await rejection(client.signOut());
    expect(thrown.code).toBe('STORAGE');
    expect(thrown.message).toContain('keychain locked');
    // Nothing removed or revoked: the user is not signed out.
    expect(removed).not.toContain(SESSION_KEY);
    expect(storedToken(base)).toBe(token);
    expect(server.revokeCalls).toEqual([]);

    // Once storage is readable, the session is still usable.
    failReads = false;
    const renewed = await client.renew();
    expect(storedToken(base)).toBe(renewed.refreshToken);
  });
});

/** Small seeded PRNG (mulberry32). */
function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

type Op = 'renew' | 'signIn' | 'signOut';
type Outcome = { ok: true } | { ok: false; code: string };

/**
 * Run renew(A), signIn(), signOut() against a seeded scheduler: each op
 * starts at a random point, every request is held, and held requests are
 * released one at a time in random order. A pending revoke from an earlier
 * signOut() is also in storage, and revokes fail transiently at random.
 */
async function runSchedule(seed: number) {
  const rng = seeded(seed);
  const server = new FakeServer();
  server.rng = rng;
  server.revokeFailRate = rng() < 0.5 ? 0 : 0.4;
  const waiting: (() => void)[] = [];
  server.gate = () => new Promise<void>((resolve) => waiting.push(resolve));

  // Two instances over one backend: one shared store object, or (with an
  // atomic compareAndSet) one store object each. Half the storage calls are
  // held by the same scheduler as the requests, so the instances' reads
  // and writes interleave with each other and with the network.
  const map = new Map<string, string>();
  const mode: 'shared object' | 'separate objects + CAS' =
    rng() < 0.5 ? 'shared object' : 'separate objects + CAS';
  let scheduling = false;
  const pause = () =>
    scheduling && rng() < 0.5
      ? new Promise<void>((resolve) => waiting.push(resolve))
      : Promise.resolve();
  const stores =
    mode === 'shared object'
      ? (() => {
          const shared = backendStore(map, { pause });
          return [shared, shared];
        })()
      : [backendStore(map, { cas: true, pause }), backendStore(map, { cas: true, pause })];
  const store = stores[0]!;
  await server.seedSession(store);
  await server.seedPending(store);
  scheduling = true;
  const clients = [server.client(stores[0]!), server.client(stores[1]!)];
  const clientOf = new Map<Op, number>();

  const order: Op[] = ['renew', 'signIn', 'signOut'];
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [order[i], order[j]] = [order[j]!, order[i]!];
  }
  const outcomes = new Map<Op, Outcome>();
  const started: Op[] = [];
  let signInToken: string | undefined;
  const start = (op: Op) => {
    started.push(op);
    const which = Math.floor(rng() * 2);
    clientOf.set(op, which);
    const client = clients[which]!;
    const promise =
      op === 'renew' ? client.renew()
      : op === 'signIn' ? client.signIn().then((t) => { signInToken = t.refreshToken; })
      : client.signOut();
    promise.then(
      () => outcomes.set(op, { ok: true }),
      (error: { code?: string }) => outcomes.set(op, { ok: false, code: error.code ?? 'UNKNOWN' }),
    );
  };

  for (let steps = 0; ; steps++) {
    if (steps > 500) throw new Error(`seed ${seed}: schedule did not settle`);
    await tick();
    if (started.length < order.length && (waiting.length === 0 || rng() < 0.35)) {
      start(order[started.length]!);
      continue;
    }
    if (waiting.length > 0) {
      waiting.splice(Math.floor(rng() * waiting.length), 1)[0]!();
      continue;
    }
    if (outcomes.size === order.length) {
      await tick();
      await tick();
      if (waiting.length === 0) break;
    }
  }
  return { server, store, order, outcomes, signInToken, mode, clientOf };
}

describe('randomized interleavings (two instances: signIn / signOut / renew / pending revoke)', () => {
  const SEEDS = 150;
  it(`keeps the stored session consistent across ${SEEDS} seeded schedules`, async () => {
    for (let seed = 1; seed <= SEEDS; seed++) {
      const { server, store, order, outcomes, signInToken, mode, clientOf } = await runSchedule(seed);
      const context = `seed ${seed}, ${mode}, start order ${order
        .map((op) => `${op}@${clientOf.get(op)}`)
        .join(' → ')}, outcomes ${JSON.stringify([...outcomes])}`;
      const check = (ok: boolean, what: string) => {
        if (!ok) throw new Error(`${what} (${context})`);
      };

      const allowed: Record<Op, string[]> = {
        renew: ['NOT_SIGNED_IN', 'INVALID_GRANT'],
        signIn: ['NOT_SIGNED_IN', 'USER_CANCELLED'],
        signOut: ['TEMPORARILY_UNAVAILABLE'],
      };
      for (const [op, outcome] of outcomes) {
        check(outcome.ok || allowed[op].includes(outcome.code), `${op} rejected with ${!outcome.ok && outcome.code}`);
      }

      // The stored session, if any, holds its grant's current, live token.
      const token = storedToken(store);
      check(token === null || server.isCurrent(token), `stored token ${token} is not current`);

      // No abandoned live grants: every grant still live on the server is
      // the stored session, waiting in the pending-revoke record, or one
      // whose revoke got a terminal response.
      const accounted = new Set<string>(server.terminalRevokeSids);
      if (token) accounted.add(server.sidOf(token)!);
      for (const t of pendingTokens(store)) accounted.add(server.sidOf(t)!);
      for (const sid of server.liveSids()) {
        check(accounted.has(sid), `live grant ${sid.slice(0, 6)} is abandoned`);
      }

      // Sign-out intent, for a signIn() on the same instance as signOut():
      // a signOut() that started after it (and after renew) leaves nothing
      // stored; a signIn() that started after signOut() and succeeded is
      // what remains. (Across instances, a sign-in that saves after the
      // other instance's signOut() finished legitimately survives it.)
      const sameInstance = clientOf.get('signIn') === clientOf.get('signOut');
      if (order[2] === 'signOut' && sameInstance) {
        check(token === null, 'session stored after the last-started signOut');
      }
      if (sameInstance && order.indexOf('signIn') > order.indexOf('signOut') && signInToken) {
        // (A renew that started later may have rotated its token since.)
        check(
          token !== null && server.sidOf(token) === server.sidOf(signInToken),
          'sign-in after signOut did not survive',
        );
      }
    }
  }, 60_000);
});
