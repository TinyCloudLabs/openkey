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
    expect(() => store.consume(token, owner, () => true, 1)).toThrow("not resumed");
    store.resume(token, owner, 1);
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


test('one account cannot fill shared capacity, even across sessions; cancellation does not refund rate quota', () => {
  const store = new SignInContinuations();
  const first = store.issue(owner, 0);
  for (let i = 1; i < 5; i++) store.issue({ ...owner, sessionId: `s${i}` }, 0);
  expect(() => store.issue({ ...owner, sessionId: 's6' }, 1)).toThrow('issuance limit');
  expect(() => store.issue({ ...owner, userId: 'another-account' }, 1)).not.toThrow();
  store.cancel(first.token, owner, 1);
  expect(() => store.issue(owner, 1)).not.toThrow();
  const limited = new SignInContinuations();
  for (let i = 0; i < 5; i++) {
    const issued = limited.issue(owner, 0);
    limited.cancel(issued.token, owner, 1);
  }
  expect(() => limited.issue(owner, 2)).toThrow('issuance limit');
  expect(() => limited.issue(owner, 60_000)).not.toThrow();
});


test('resume shortens the remaining lifetime to at most sixty seconds and is single-use', () => {
  const store = new SignInContinuations();
  const issued = store.issue(owner, 0);
  store.verified(issued.token, owner, issued.challenge, 1);
  store.resume(issued.token, owner, 2);
  expect(() => store.resume(issued.token, owner, 3)).toThrow('unavailable');
  expect(store.resumedIdentity(issued.token, owner, 60_001)).toEqual(owner);
  expect(() => store.resumedIdentity(issued.token, owner, 60_002)).toThrow('expired');
  const late = store.issue(owner, 100_000);
  store.verified(late.token, owner, late.challenge, 100_001);
  store.resume(late.token, owner, 399_999);
  expect(() => store.resumedIdentity(late.token, owner, 400_000)).toThrow('expired');
});
