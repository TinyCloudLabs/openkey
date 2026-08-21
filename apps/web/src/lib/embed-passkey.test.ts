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
    let request: RequestInit | undefined;

    const revoked = await revokeEmbeddedSession(undefined, async (_url, init) => {
      request = init;
      return new Response(null, { status: 200 });
    });

    expect(revoked).toBe(true);
    expect(request?.method).toBe('POST');
    expect(request?.headers).toEqual({ Authorization: 'Bearer active-session' });
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
