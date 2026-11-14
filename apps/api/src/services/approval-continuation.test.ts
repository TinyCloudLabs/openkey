import { expect, test } from 'bun:test';
import { ApprovalContinuations, type ApprovalIdentity } from './approval-continuation';
import { SignInContinuations } from './signin-continuation';
const base = { userId: 'owner', sessionId: 'session', requestId: 'request', origin: 'https://app.example',
  keyId: 'key', keyType: 'MANAGED' as const, address: '0x1111111111111111111111111111111111111111', chainId: 1 };
const share: ApprovalIdentity = { ...base, purpose: 'share-create', serverIntentDigest: 'a'.repeat(64) };
test('purpose and frozen intent are required and cannot be changed at challenge or consumption', () => {
  const store = new ApprovalContinuations();
  expect(() => store.issue(base as ApprovalIdentity, 0)).toThrow();
  const issued = store.issue(share, 0);
  for (const other of [{ ...share, purpose: 'tinycloud-signin' as const }, { ...share, serverIntentDigest: 'b'.repeat(64) }]) {
    expect(() => store.challenge(issued.token, other, 1)).toThrow();
    expect(() => store.consume(issued.token, other, () => true, 1)).toThrow();
  }
  store.verified(issued.token, share, issued.challenge, 1);
  expect(() => store.consume(issued.token, share, () => true, 2)).toThrow('resumed');
  store.resume(issued.token, share, 2);
  expect(() => store.resume(issued.token, share, 3)).toThrow();
  expect(() => store.resumedIdentity(issued.token, share, 60_002)).toThrow();
});
test('sign-in facade keeps exactly the public eight frozen fields and ignores extra caller fields', () => {
  const store = new SignInContinuations();
  const caller = { ...base, purpose: 'share-create', serverIntentDigest: 'forged', extra: 'not part of identity' };
  const issued = store.issue(caller, 0);
  store.verified(issued.token, base, issued.challenge, 1);
  const identity = store.identity(issued.token, base, 2);
  expect(identity).toEqual(base);
  expect(Object.keys(identity).sort()).toEqual(Object.keys(base).sort());
  expect(Object.isFrozen(identity)).toBe(true);
});
