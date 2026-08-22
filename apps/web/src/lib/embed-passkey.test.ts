// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, describe, expect, test } from 'bun:test';
import {
  getSessionToken,
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
    const requests: Array<{ url: string; init?: RequestInit }> = [];

    const revoked = await revokeEmbeddedSession(undefined, async (url, init) => {
      requests.push({ url: String(url), init });
      return requests.length === 1
        ? new Response(null, { status: 200 })
        : Response.json(null);
    });

    expect(revoked).toBe(true);
    expect(requests).toHaveLength(2);
    expect(requests[0]?.url).toEndWith('/api/auth/sign-out');
    expect(requests[0]?.init?.method).toBe('POST');
    expect(requests[0]?.init?.headers).toEqual({ Authorization: 'Bearer active-session' });
    expect(requests[1]?.url).toEndWith('/api/auth/get-session?disableRefresh=true');
    expect(requests[1]?.init?.credentials).toBe('omit');
    expect(requests[1]?.init?.headers).toEqual({ Authorization: 'Bearer active-session' });
    expect(getSessionToken()).toBeNull();
  });

  test('captures and verifies the cookie session token before signing out', async () => {
    installSessionStorage();
    const requests: Array<{ url: string; init?: RequestInit }> = [];

    const revoked = await revokeEmbeddedSession(null, async (url, init) => {
      requests.push({ url: String(url), init });
      if (requests.length === 1) {
        return Response.json({ session: { token: 'cookie-session' }, user: { id: 'user-1' } });
      }
      return requests.length === 2
        ? Response.json({ success: true })
        : Response.json(null);
    });

    expect(revoked).toBe(true);
    expect(requests).toHaveLength(3);
    expect(requests[0]?.url).toEndWith('/api/auth/get-session?disableRefresh=true');
    expect(requests[0]?.init?.credentials).toBe('include');
    expect(requests[1]?.url).toEndWith('/api/auth/sign-out');
    expect(requests[1]?.init?.headers).toEqual({ Authorization: 'Bearer cookie-session' });
    expect(requests[2]?.url).toEndWith('/api/auth/get-session?disableRefresh=true');
    expect(requests[2]?.init?.credentials).toBe('omit');
    expect(requests[2]?.init?.headers).toEqual({ Authorization: 'Bearer cookie-session' });
  });

  test('does not claim cookie-session revocation when the captured token survives', async () => {
    installSessionStorage();
    let requestCount = 0;

    const revoked = await revokeEmbeddedSession(null, async () => {
      requestCount += 1;
      if (requestCount === 1) {
        return Response.json({ session: { token: 'cookie-session' }, user: { id: 'user-1' } });
      }
      return requestCount === 2
        ? Response.json({ success: true })
        : Response.json({ session: { token: 'cookie-session' }, user: { id: 'user-1' } });
    });

    expect(revoked).toBe(false);
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
    let requestCount = 0;

    const revoked = await revokeEmbeddedSession(undefined, async () => {
      requestCount += 1;
      return requestCount === 1
        ? Response.json({ success: true })
        : Response.json({ session: { token: 'active-session' }, user: { id: 'user-1' } });
    });

    expect(revoked).toBe(false);
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
