import { expect, test } from 'bun:test';
import { encodeOpenKeyDbSnapshot, openKeyDbSnapshotHash } from '../services/escrow-db-encoding';
const row = { id: 'e', userId: null, address: 'address', publicKey: 'public', sealedBlob: 'sealed', sealingContext: 'context', keyType: 'MANAGED', isCanonicalTinyCloud: false, keyIndex: 0, label: null, archivedAt: null, createdAt: new Date('2026-11-11T00:00:00.000Z') };
test('database snapshot encodes all columns with fixed types/order independently of driver objects', () => {
  const snapshot = { ethereum: [row], nostr: [], legacy: [] };
  expect(new TextDecoder().decode(encodeOpenKeyDbSnapshot(snapshot))).toBe(JSON.stringify(['tinycloud/escrow/db-snapshot', 1, [['ethereum_keys', [['e', null, 'address', 'public', 'sealed', 'context', 'MANAGED', false, 0, null, null, '2026-11-11T00:00:00.000Z']]], ['nostr_keys', []], ['user_encryption_key', []]]]));
  const reversed = Object.fromEntries(Object.entries(row).reverse());
  expect(openKeyDbSnapshotHash({ ...snapshot, ethereum: [reversed] })).toBe(openKeyDbSnapshotHash(snapshot));
  expect(openKeyDbSnapshotHash({ ...snapshot, ethereum: [{ ...row, label: 'changed' }] })).not.toBe(openKeyDbSnapshotHash(snapshot));
  expect(() => encodeOpenKeyDbSnapshot({ ...snapshot, legacy: undefined })).toThrow();
  expect(() => encodeOpenKeyDbSnapshot({ ...snapshot, ethereum: [row, row] })).toThrow();
  expect(() => encodeOpenKeyDbSnapshot({ ...snapshot, ethereum: [{ ...row, isCanonicalTinyCloud: 0 }] })).toThrow();
});
