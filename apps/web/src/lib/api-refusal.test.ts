// TC-2291: the legacy sign path (POST /api/keys/:id/sign) carries the same definite refusals as authorize-sign:
// api.signMessage must surface them as a ServerRefusalError so the widget can tell the app.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, afterEach, describe, expect, test } from 'bun:test';
import { api } from './api';
import { ServerRefusalError } from './server-reply';

// No session token: the legacy sign call goes out with cookies, as in a popup.
const globals = globalThis as unknown as { sessionStorage?: unknown };
const realStorage = globals.sessionStorage;
globals.sessionStorage = { getItem: () => null };
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
afterAll(() => { globals.sessionStorage = realStorage; });
const answer = (status: number, body: unknown) => {
  globalThis.fetch = (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch;
};

describe('api.signMessage', () => {
  test('a 403 with a refusal code throws a ServerRefusalError with the server\'s words', async () => {
    answer(403, { error: 'server words', code: 'app_key_grant_refused' });
    const error = await api.signMessage('k', 'm', 'https://app.example').then(() => null, (cause: unknown) => cause);
    expect(error).toBeInstanceOf(ServerRefusalError);
    expect(error).toMatchObject({ message: 'server words', status: 403, code: 'app_key_grant_refused' });
  });

  test.each([
    ['a server error that carries the code', 503, { error: 'server words', code: 'app_key_grant_refused' }],
    ['a 403 with another code', 403, { error: 'server words', code: 'siwe_origin_refused' }],
    ['a 403 with no code', 403, { error: 'server words' }],
  ])('%s stays a plain Error', async (_label: string, status: number, body: unknown) => {
    answer(status, body);
    const error = await api.signMessage('k', 'm').then(() => null, (cause: unknown) => cause);
    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ServerRefusalError);
  });
});
