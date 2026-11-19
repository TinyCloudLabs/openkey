// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, describe, expect, test } from 'bun:test';
import {
  getSessionToken,
  readSignedSessionToken,
  revokeEmbeddedSession,
  setSessionToken,
} from './embed-passkey';

const originalSessionStorage = globalThis.sessionStorage;

function installSessionStorage() {
  const values = new Map<string, string>();
  (globalThis as any).sessionStorage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  };
}

afterEach(() => {
  (globalThis as any).sessionStorage = originalSessionStorage;
});

describe('revokeEmbeddedSession', () => {
  test('uses the bearer session and clears embedded state after successful revocation', async () => {
    installSessionStorage();
    setSessionToken('active-session');
    let signedOut = false;
    const { impl, requests } = routedFetch({
      '/api/auth/get-session': () => Response.json(signedOut ? null : { session: {}, user: { id: 'user-1' } }),
      '/api/auth/sign-out': () => { signedOut = true; return new Response(null, { status: 200 }); },
    });

    const revoked = await revokeEmbeddedSession(undefined, impl);

    expect(revoked).toBe(true);
    expect(requests).toHaveLength(3);
    expect(requests[0]?.url).toEndWith('/api/auth/get-session?disableRefresh=true');
    expect(requests[0]?.init?.credentials).toBe('omit');
    expect(requests[0]?.init?.headers).toEqual({ Authorization: 'Bearer active-session' });
    expect(requests[1]?.url).toEndWith('/api/auth/sign-out');
    expect(requests[1]?.init?.method).toBe('POST');
    expect(requests[1]?.init?.headers).toEqual({ Authorization: 'Bearer active-session' });
    expect(requests[2]?.url).toEndWith('/api/auth/get-session?disableRefresh=true');
    expect(requests[2]?.init?.credentials).toBe('omit');
    expect(requests[2]?.init?.headers).toEqual({ Authorization: 'Bearer active-session' });
    expect(getSessionToken()).toBeNull();
  });

  test('captures and verifies the cookie session token before signing out', async () => {
    installSessionStorage();
    let signedOut = false;
    const { impl, requests } = routedFetch({
      '/api/auth/session-token': () => Response.json({ token: 'cookie-session.sig' }),
      '/api/auth/get-session': () => Response.json(signedOut ? null : { session: {}, user: { id: 'user-1' } }),
      '/api/auth/sign-out': () => { signedOut = true; return Response.json({ success: true }); },
    });

    const revoked = await revokeEmbeddedSession(null, impl);

    expect(revoked).toBe(true);
    expect(requests).toHaveLength(4);
    expect(requests[0]?.url).toEndWith('/api/auth/session-token');
    expect(requests[0]?.init?.credentials).toBe('include');
    expect(requests[1]?.url).toEndWith('/api/auth/get-session?disableRefresh=true');
    expect(requests[1]?.init?.credentials).toBe('omit');
    expect(requests[1]?.init?.headers).toEqual({ Authorization: 'Bearer cookie-session.sig' });
    expect(requests[2]?.url).toEndWith('/api/auth/sign-out');
    expect(requests[2]?.init?.headers).toEqual({ Authorization: 'Bearer cookie-session.sig' });
    expect(requests[3]?.url).toEndWith('/api/auth/get-session?disableRefresh=true');
    expect(requests[3]?.init?.credentials).toBe('omit');
    expect(requests[3]?.init?.headers).toEqual({ Authorization: 'Bearer cookie-session.sig' });
  });

  test('does not claim cookie-session revocation when the captured token survives', async () => {
    installSessionStorage();
    const { impl, requests } = routedFetch({
      '/api/auth/session-token': () => Response.json({ token: 'cookie-session.sig' }),
      '/api/auth/get-session': () => Response.json({ session: {}, user: { id: 'user-1' } }),
      '/api/auth/sign-out': () => Response.json({ success: true }),
    });

    const revoked = await revokeEmbeddedSession(null, impl);

    expect(revoked).toBe(false);
    expect(requests.filter((r) => r.url.includes('/get-session'))).toHaveLength(2);
  });

  test('still attempts cookie sign-out when the session-token preflight fails', async () => {
    installSessionStorage();
    let requestCount = 0;

    const revoked = await revokeEmbeddedSession(null, async () => {
      requestCount += 1;
      if (requestCount === 1) throw new Error('preflight unavailable');
      return Response.json({ success: true });
    });

    expect(revoked).toBe(false);
    expect(requestCount).toBe(2);
  });

  test('does not treat a cookie-less null preflight as verified revocation', async () => {
    installSessionStorage();
    let requestCount = 0;

    const revoked = await revokeEmbeddedSession(null, async () => {
      requestCount += 1;
      return requestCount === 1
        ? Response.json(null)
        : Response.json({ success: true });
    });

    expect(revoked).toBe(false);
    expect(requestCount).toBe(2);
  });

  test('does not claim revocation while the old bearer still authenticates', async () => {
    installSessionStorage();
    setSessionToken('active-session');
    const { impl, requests } = routedFetch({
      '/api/auth/get-session': () => Response.json({ session: { token: 'active-session' }, user: { id: 'user-1' } }),
      '/api/auth/sign-out': () => Response.json({ success: true }),
    });

    const revoked = await revokeEmbeddedSession(undefined, impl);

    expect(revoked).toBe(false);
    expect(requests.filter((r) => r.url.includes('/get-session'))).toHaveLength(2);
    expect(getSessionToken()).toBeNull();
  });

  test('still clears embedded state when session revocation is unavailable', async () => {
    installSessionStorage();
    setSessionToken('active-session');

    const revoked = await revokeEmbeddedSession(undefined, async () => {
      throw new Error('offline');
    });

    expect(revoked).toBe(false);
    expect(getSessionToken()).toBeNull();
  });
});

type Route = (init?: RequestInit) => Response;

function routedFetch(routes: Record<string, Route>) {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    requests.push({ url: String(url), init });
    const path = new URL(String(url), 'https://api.example').pathname;
    const route = routes[path];
    if (!route) throw new Error(`unexpected request ${path}`);
    return route(init);
  }) as typeof fetch;
  return { impl, requests };
}

describe('readSignedSessionToken', () => {
  test('uses the signed token the API returns and reads nothing else', async () => {
    const { impl, requests } = routedFetch({
      '/api/auth/session-token': () => Response.json({ token: 'session-1.sig' }),
    });
    expect(await readSignedSessionToken(impl)).toBe('session-1.sig');
    expect(requests).toHaveLength(1);
    expect(requests[0]?.init?.credentials).toBe('include');
  });

  test('no session is no token, without reading the session another way', async () => {
    const { impl, requests } = routedFetch({
      '/api/auth/session-token': () => Response.json({ error: 'Unauthorized' }, { status: 401 }),
    });
    expect(await readSignedSessionToken(impl)).toBeNull();
    expect(requests).toHaveLength(1);
  });

  test('an API without the route is read through get-session', async () => {
    const { impl, requests } = routedFetch({
      '/api/auth/session-token': () => new Response('Not Found', { status: 404 }),
      '/api/auth/get-session': () => Response.json({ session: { token: 'session-1' }, user: { id: 'user-1' } }),
    });
    expect(await readSignedSessionToken(impl)).toBe('session-1');
    expect(requests.map((r) => new URL(r.url, 'https://api.example').pathname))
      .toEqual(['/api/auth/session-token', '/api/auth/get-session']);
  });
});

describe('revokeEmbeddedSession with a token the API does not accept', () => {
  test('signs out without it and does not claim revocation', async () => {
    installSessionStorage();
    setSessionToken('unaccepted-session');
    const { impl, requests } = routedFetch({
      '/api/auth/get-session': () => Response.json(null),
      '/api/auth/sign-out': () => Response.json({ success: true }),
    });

    const revoked = await revokeEmbeddedSession(undefined, impl);

    expect(revoked).toBe(false);
    const signOut = requests.find((r) => r.url.endsWith('/api/auth/sign-out'));
    expect(signOut?.init?.headers).toBeUndefined();
    expect(getSessionToken()).toBeNull();
  });
});
