// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, describe, expect, test } from 'bun:test';
import { embedSignInPasskey, PASSKEY_NOT_KNOWN_TEXT, PASSKEY_REQUEST_EXPIRED_TEXT, passkeyFailureText } from './embed-passkey';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('passkeyFailureText', () => {
  test('says a passkey the account does not have is not known', () => {
    expect(passkeyFailureText({ code: 'PASSKEY_NOT_FOUND', message: 'Passkey not found' }, 401)).toBe(PASSKEY_NOT_KNOWN_TEXT);
  });

  test('says a passkey request that expired or was used has ended', () => {
    expect(passkeyFailureText({ error: 'Challenge token not found or expired' }, 400)).toBe(PASSKEY_REQUEST_EXPIRED_TEXT);
    expect(passkeyFailureText({ error: 'Challenge token expired' }, 400)).toBe(PASSKEY_REQUEST_EXPIRED_TEXT);
    expect(passkeyFailureText({ code: 'CHALLENGE_NOT_FOUND', message: 'Challenge not found' }, 400)).toBe(PASSKEY_REQUEST_EXPIRED_TEXT);
  });

  test("uses the API's own words for any other error", () => {
    expect(passkeyFailureText({ error: 'Too many attempts' }, 429)).toBe('Too many attempts');
  });

  test("uses Better Auth's message when the reply has no error", () => {
    expect(passkeyFailureText({ code: 'AUTHENTICATION_FAILED', message: 'Authentication failed' }, 400)).toBe('Authentication failed');
  });

  test('names the reply code when there are no words', () => {
    expect(passkeyFailureText({ code: 'AUTHENTICATION_FAILED' }, 400)).toBe('HTTP 400 · AUTHENTICATION_FAILED');
  });

  test('is the status alone for a reply with neither words nor a code', () => {
    expect(passkeyFailureText({}, 400)).toBe('HTTP 400');
    expect(passkeyFailureText(null, 502)).toBe('HTTP 502');
    expect(passkeyFailureText({ error: '', message: 7, code: 3 }, 400)).toBe('HTTP 400');
  });
});

describe('embedSignInPasskey when the API refuses the options', () => {
  test('shows the reply code, not the bare status', async () => {
    globalThis.fetch = (async () => new Response(JSON.stringify({ code: 'RATE_LIMITED' }), { status: 400 })) as typeof fetch;
    await expect(embedSignInPasskey()).rejects.toThrow('HTTP 400 · RATE_LIMITED');
  });
});
