import { expect, test } from 'bun:test';
import { ShareApprovals } from './share-approval';
const binding = {
  userId: 'owner', keyId: 'key',
  ownerDid: 'did:pkh:eip155:1:0xd559CCd9EB87c530A9a349262669386dE93cf412',
  sessionDid: 'did:key:zSession', origin: 'https://thirdparty.example', sessionExpiresAt: 200_000,
};
test('minted approval binds one exact key and is single use', () => {
  const store = new ShareApprovals(() => 100_000);
  const record = store.issue(binding);
  expect(record.shareId).toMatch(/^[0-9a-f]{32}$/);
  expect(record.expiresAt).toBe(160_000);
  const grant = [{ resource: record.resource, action: record.action }];
  for (const other of [
    { ...binding, ownerDid: `${binding.ownerDid}0` }, { ...binding, sessionDid: 'did:key:zOther' },
    { ...binding, origin: 'https://other.example' }, { ...binding, userId: 'other' },
  ]) expect(() => store.consume(record.requestId, other, record.nonce, grant)).toThrow();
  for (const bad of [[], [...grant, ...grant], [{ ...grant[0]!, resource: record.resource.replace(/[^/]+$/, '') }],
    [{ ...grant[0]!, resource: record.resource.split('/')[0]! }], [{ ...grant[0]!, action: 'tinycloud.encryption/key.create' }]]) {
    expect(() => store.consume(record.requestId, binding, record.nonce, bad)).toThrow();
  }
  expect(store.consume(record.requestId, binding, record.nonce, grant)).toEqual(record);
  expect(() => store.consume(record.requestId, binding, record.nonce, grant)).toThrow();
});
test('expired contexts and insecure origins cannot approve', () => {
  let now = 100_000;
  const store = new ShareApprovals(() => now);
  expect(() => store.issue({ ...binding, origin: 'http://thirdparty.example' })).toThrow();
  const record = store.issue(binding);
  now = record.expiresAt;
  expect(() => store.consume(record.requestId, binding, record.nonce, [{ resource: record.resource, action: record.action }])).toThrow();
});
