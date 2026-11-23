// The embedded sheet's passkey sign-in says it in plain words when the passkey prompt ends with no passkey used: no
// passkey matched, the browser refused the prompt here or the person dismissed it. The browser raises all three as a
// `NotAllowedError`; `@simplewebauthn/browser` wraps it in a WebAuthnError (code ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY)
// that keeps the DOMException as `cause` and copies its message. Every other error keeps its own message.
//
// The ceremony is `navigator.credentials.get`, which `startAuthentication` calls; it is stubbed on the globals for the
// duration of this file and restored afterwards, because other files in the same process import the same modules.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'bun:test';
import { embedSignInPasskey } from './embed-passkey';
import { embedPasskeySignInErrorText, isPasskeyNotAllowed, PASSKEY_NOT_USABLE_NEW_ACCOUNT_TEXT, PASSKEY_NOT_USABLE_TEXT } from './embed-passkey-not-allowed';

const RAW = 'The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.';

let ceremony: () => Promise<unknown> = async () => ({});
const originalFetch = globalThis.fetch;
const globals = globalThis as unknown as { PublicKeyCredential?: unknown };
const originalPublicKeyCredential = Object.getOwnPropertyDescriptor(globals, 'PublicKeyCredential');
const originalCredentials = Object.getOwnPropertyDescriptor(globalThis.navigator, 'credentials');

beforeAll(() => {
  Object.defineProperty(globals, 'PublicKeyCredential', { value: function PublicKeyCredential() {}, configurable: true, writable: true });
  Object.defineProperty(globalThis.navigator, 'credentials', { value: { get: () => ceremony() }, configurable: true });
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

afterAll(() => {
  if (originalPublicKeyCredential) Object.defineProperty(globals, 'PublicKeyCredential', originalPublicKeyCredential);
  else delete globals.PublicKeyCredential;
  if (originalCredentials) Object.defineProperty(globalThis.navigator, 'credentials', originalCredentials);
  else delete (globalThis.navigator as { credentials?: unknown }).credentials;
});

/** What the sheet's catch receives when the passkey prompt rejects with `rejection` after the API has given its options. */
async function thrownBy(rejection: unknown): Promise<unknown> {
  globalThis.fetch = (async () => new Response(JSON.stringify({ challengeToken: 'c', challenge: 'Yw', rpId: 'example.test' }), { status: 200 })) as typeof fetch;
  ceremony = async () => { throw rejection; };
  return embedSignInPasskey().then(() => undefined, (cause: unknown) => cause);
}

describe('the embedded passkey sign-in when the passkey prompt ends with no passkey used', () => {
  test("the browser's NotAllowedError arrives wrapped, with its raw text as the message", async () => {
    const thrown = await thrownBy(new DOMException(RAW, 'NotAllowedError')) as Error & { code?: string; cause?: { name?: string } };
    expect(thrown.code).toBe('ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY');
    expect(thrown.cause?.name).toBe('NotAllowedError');
    expect(thrown.message).toBe(RAW);
  });

  test('the sheet says the passkey could not be used, not the browser text', async () => {
    const text = embedPasskeySignInErrorText(await thrownBy(new DOMException(RAW, 'NotAllowedError')), 'choices');
    expect(text).toBe(PASSKEY_NOT_USABLE_TEXT);
    expect(text).not.toContain('timed out');
  });

  test('a person dismissing the prompt gets the same words', async () => {
    expect(embedPasskeySignInErrorText(await thrownBy(new DOMException('The user aborted a request.', 'NotAllowedError')), 'choices')).toBe(PASSKEY_NOT_USABLE_TEXT);
  });

  test('a plain DOMException named NotAllowedError, not wrapped, gets the same words', () => {
    expect(embedPasskeySignInErrorText(new DOMException(RAW, 'NotAllowedError'), 'choices')).toBe(PASSKEY_NOT_USABLE_TEXT);
  });

  test('the new-account step names its own way out, for the wrapped and the plain error alike', async () => {
    const wrapped = embedPasskeySignInErrorText(await thrownBy(new DOMException(RAW, 'NotAllowedError')), 'new-account');
    expect(wrapped).toBe(PASSKEY_NOT_USABLE_NEW_ACCOUNT_TEXT);
    expect(wrapped).toContain('Use a different email');
    expect(wrapped).not.toContain('Continue with email');
    expect(embedPasskeySignInErrorText(new DOMException(RAW, 'NotAllowedError'), 'new-account')).toBe(PASSKEY_NOT_USABLE_NEW_ACCOUNT_TEXT);
  });
});

describe('every other error keeps its own words', () => {
  test("a different browser error keeps the library's message", async () => {
    const thrown = await thrownBy(new DOMException('The operation was aborted.', 'AbortError'));
    expect(isPasskeyNotAllowed(thrown)).toBe(false);
    expect(embedPasskeySignInErrorText(thrown, 'choices')).not.toBe(PASSKEY_NOT_USABLE_TEXT);
    expect(embedPasskeySignInErrorText(thrown, 'choices')).toBe((thrown as Error).message);
    expect(embedPasskeySignInErrorText(thrown, 'new-account')).toBe((thrown as Error).message);
  });

  test("the API's refusal keeps its words", () => {
    expect(embedPasskeySignInErrorText(new Error('OpenKey doesn\'t know this passkey. Choose another way to sign in.'), 'new-account')).toBe("OpenKey doesn't know this passkey. Choose another way to sign in.");
  });

  test('an error with no message says the passkey sign-in failed', () => {
    expect(embedPasskeySignInErrorText(new Error(''), 'choices')).toBe('Passkey sign-in failed');
    expect(embedPasskeySignInErrorText(undefined, 'new-account')).toBe('Passkey sign-in failed');
  });

  test('a message that merely mentions NotAllowedError is not the error', () => {
    expect(isPasskeyNotAllowed(new Error('NotAllowedError'))).toBe(false);
    expect(isPasskeyNotAllowed({ code: 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY' })).toBe(false);
    expect(isPasskeyNotAllowed(null)).toBe(false);
  });
});
