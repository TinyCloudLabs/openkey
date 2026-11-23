// The login page marks an autofill sign-in as "being verified" with an `onRequest` hook in the `fetchOptions` it gives
// better-auth's `signIn.passkey`. The client forwards `fetchOptions` to the verify request only, so the hook runs
// after the browser ceremony returned an assertion and before the server is asked to verify it, never for the
// options request and never when the ceremony ends without an assertion.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, mock, test } from 'bun:test';

const events: string[] = [];
let ceremony: () => Promise<unknown> = async () => ({});

// Only the browser ceremony is replaced; every other export stays the real one for the files that share this process.
const real = await import('@simplewebauthn/browser');
mock.module('@simplewebauthn/browser', () => ({
  ...real,
  startAuthentication: async () => {
    events.push('ceremony');
    return ceremony();
  },
}));
afterAll(() => {
  mock.module('@simplewebauthn/browser', () => real);
});

const { createAuthClient } = await import('better-auth/client');
const { passkeyClient } = await import('@better-auth/passkey/client');

const assertion = async () => ({ id: 'credential', rawId: 'credential', type: 'public-key', response: {}, clientExtensionResults: {} });

const authClient = createAuthClient({
  baseURL: 'https://api.example.test',
  plugins: [passkeyClient()],
  fetchOptions: {
    customFetchImpl: async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
      const path = url.pathname.replace(/^\/api\/auth/, '');
      events.push(`${init?.method ?? 'GET'} ${path}`);
      const body = path === '/passkey/generate-authenticate-options' ? { challenge: 'c', rpId: 'example.test' } : { session: { id: 's' }, user: { id: 'u' } };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  },
});

describe('signIn.passkey with an onRequest hook in fetchOptions', () => {
  test('the hook runs once, after the ceremony and before the verify request, and not for the options request', async () => {
    events.length = 0;
    ceremony = assertion;
    const result = await authClient.signIn.passkey({
      autoFill: true,
      fetchOptions: { headers: { 'x-openkey-passkey-flow': 'flow' }, onRequest: () => { events.push('hook'); } },
    });
    expect(result.error).toBeNull();
    expect(events).toEqual(['GET /passkey/generate-authenticate-options', 'ceremony', 'hook', 'POST /passkey/verify-authentication']);
  });

  test('the hook does not run when the ceremony ends without an assertion', async () => {
    events.length = 0;
    ceremony = async () => { throw new Error('aborted'); };
    const result = await authClient.signIn.passkey({ autoFill: true, fetchOptions: { onRequest: () => { events.push('hook'); } } });
    expect(result.error).not.toBeNull();
    expect(events).toEqual(['GET /passkey/generate-authenticate-options', 'ceremony']);
  });
});
