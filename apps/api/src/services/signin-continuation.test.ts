import { describe, expect, test } from 'bun:test';
import { SignInContinuations, type SignInIdentity } from './signin-continuation';

const owner: SignInIdentity = {
  userId: 'user', sessionId: 'session', requestId: 'request', origin: 'https://app.example',
  keyId: 'key', keyType: 'MANAGED', address: '0xowner', chainId: 1,
};

describe('request-bound sign-in continuation', () => {
  test('requires fresh assertion and consumes once with authorization', () => {
    const store = new SignInContinuations();
    const { token, challenge } = store.issue(owner, 0);
    expect(() => store.identity(token, owner, 1)).toThrow('fresh passkey');
    store.verified(token, owner, challenge, 1);
    expect(store.identity(token, owner, 2)).toEqual(owner);
    expect(() => store.consume(token, owner, () => false, 2)).toThrow('refused');
    store.consume(token, owner, () => true, 3);
    expect(() => store.consume(token, owner, () => true, 4)).toThrow('consumed');
  });

  for (const [field, value] of Object.entries({
    userId: 'other', sessionId: 'other', requestId: 'other', origin: 'https://evil.example',
    keyId: 'other', keyType: 'EXTERNAL', address: '0xother', chainId: 2,
  })) {
    test(`refuses changed ${field} during preparation`, () => {
      const store = new SignInContinuations();
      const { token, challenge } = store.issue(owner, 0);
      store.verified(token, owner, challenge, 1);
      expect(() => store.identity(token, { ...owner, [field]: value }, 2)).toThrow('identity changed');
    });
  }

  test('assertions cannot cross requests or be reused', () => {
    const store = new SignInContinuations();
    const first = store.issue(owner, 0);
    const second = store.issue(owner, 0);
    expect(first.challenge).not.toBe(second.challenge);
    expect(() => store.verified(second.token, owner, first.challenge, 1)).toThrow('Invalid');
    store.verified(first.token, owner, first.challenge, 1);
    expect(() => store.verified(first.token, owner, first.challenge, 2)).toThrow('Invalid');
  });

  test('cancel and five-minute expiry refuse resume', () => {
    const store = new SignInContinuations();
    const first = store.issue(owner, 0);
    store.cancel(first.token, owner, 1);
    expect(() => store.challenge(first.token, owner, 2)).toThrow('consumed');
    const second = store.issue(owner, 0);
    store.verified(second.token, owner, second.challenge, 1);
    expect(() => store.consume(second.token, owner, () => true, 300_000)).toThrow('expired');
  });
});
