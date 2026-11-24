// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { sendCodeErrorMessage } from './send-code-error';

const failed = { code: 'EMAIL_DELIVERY_FAILED', message: 'server text that is not shown' };

describe('sendCodeErrorMessage', () => {
  test('names the address when the code could not be sent', () => {
    expect(sendCodeErrorMessage(failed, { email: 'ada@example.test', passkey: false, fallback: 'Failed to send code' }))
      .toBe("We couldn't send the code to ada@example.test. Please try again in a few minutes.");
  });

  test('uses the address-free wording when no address is at hand', () => {
    expect(sendCodeErrorMessage(failed, { email: '  ', passkey: false, fallback: 'Failed to send code' }))
      .toBe("We couldn't send your code. Please try again in a few minutes.");
  });

  test('adds the passkey line where the screen offers a passkey', () => {
    expect(sendCodeErrorMessage(failed, { email: 'ada@example.test', passkey: true, fallback: 'Failed to send code' }))
      .toBe("We couldn't send the code to ada@example.test. Please try again in a few minutes. You can also sign in with a passkey.");
    expect(sendCodeErrorMessage(failed, { email: '', passkey: true, fallback: 'Failed to send code' }))
      .toBe("We couldn't send your code. Please try again in a few minutes. You can also sign in with a passkey.");
  });

  test('other failures keep the API message, then the fallback', () => {
    const options = { email: 'ada@example.test', passkey: true, fallback: 'Failed to send code' };
    expect(sendCodeErrorMessage({ code: 'INVALID_EMAIL', message: 'Invalid email' }, options)).toBe('Invalid email');
    expect(sendCodeErrorMessage({ message: '' }, options)).toBe('Failed to send code');
    expect(sendCodeErrorMessage(null, options)).toBe('Failed to send code');
  });
});
