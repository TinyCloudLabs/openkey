// The login page marks an autofill sign-in as "being verified" with an `onRequest` hook in the `fetchOptions` it gives
// better-auth's `signIn.passkey`. The client forwards `fetchOptions` to the verify request only, so the hook runs
// after the browser ceremony returned an assertion and before the server is asked to verify it, never for the
// options request and never when the ceremony ends without an assertion.
//
// The ceremony is `navigator.credentials.get`, which `startAuthentication` calls; it is stubbed on the globals for the
// duration of this file and restored afterwards, because other files in the same process import the same modules.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createAuthClient } from 'better-auth/client';
import { passkeyClient } from '@better-auth/passkey/client';

const events: string[] = [];
let ceremony: () => Promise<unknown> = async () => ({});

const buffer = (text: string) => new TextEncoder().encode(text).buffer;
const assertion = async () => ({
  id: 'credential',
  rawId: buffer('credential'),
  type: 'public-key',
  response: { authenticatorData: buffer('data'), clientDataJSON: buffer('client'), signature: buffer('signature'), userHandle: null },
  authenticatorAttachment: 'platform',
  getClientExtensionResults: () => ({}),
});

const globals = globalThis as unknown as { PublicKeyCredential?: unknown };
const originalPublicKeyCredential = Object.getOwnPropertyDescriptor(globals, 'PublicKeyCredential');
const originalCredentials = Object.getOwnPropertyDescriptor(globalThis.navigator, 'credentials');

beforeAll(() => {
  Object.defineProperty(globals, 'PublicKeyCredential', { value: function PublicKeyCredential() {}, configurable: true, writable: true });
  Object.defineProperty(globalThis.navigator, 'credentials', {
    value: { get: async () => { events.push('ceremony'); return ceremony(); } },
    configurable: true,
  });
});

afterAll(() => {
  if (originalPublicKeyCredential) Object.defineProperty(globals, 'PublicKeyCredential', originalPublicKeyCredential);
  else delete globals.PublicKeyCredential;
  if (originalCredentials) Object.defineProperty(globalThis.navigator, 'credentials', originalCredentials);
  else delete (globalThis.navigator as { credentials?: unknown }).credentials;
});

const authClient = createAuthClient({
  baseURL: 'https://api.example.test',
  plugins: [passkeyClient()],
  fetchOptions: {
    customFetchImpl: async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
      const path = url.pathname.replace(/^\/api\/auth/, '');
      events.push(`${init?.method ?? 'GET'} ${path}`);
      const body = path === '/passkey/generate-authenticate-options' ? { challenge: 'Yw', rpId: 'example.test' } : { session: { id: 's' }, user: { id: 'u' } };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    },
  },
});

describe('signIn.passkey with an onRequest hook in fetchOptions', () => {
  test('the hook runs once, after the ceremony and before the verify request, and not for the options request', async () => {
    events.length = 0;
    ceremony = assertion;
    const result = await authClient.signIn.passkey({
      fetchOptions: { headers: { 'x-openkey-passkey-flow': 'flow' }, onRequest: () => { events.push('hook'); } },
    });
    expect(result.error).toBeNull();
    expect(events).toEqual(['GET /passkey/generate-authenticate-options', 'ceremony', 'hook', 'POST /passkey/verify-authentication']);
  });

  test('the hook does not run when the ceremony ends without an assertion', async () => {
    events.length = 0;
    ceremony = async () => { throw new Error('aborted'); };
    const result = await authClient.signIn.passkey({ fetchOptions: { onRequest: () => { events.push('hook'); } } });
    expect(result.error).not.toBeNull();
    expect(events).toEqual(['GET /passkey/generate-authenticate-options', 'ceremony']);
  });
});
