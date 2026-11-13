import { expect, test } from 'bun:test';
import { buildOpenKeyInventory, type OpenKeySnapshotRows } from '../services/escrow-inventory';

const blob = Buffer.alloc(32, 7).toString('base64');
const eth = { id: 'e', userId: null, sealingContext: Buffer.alloc(32, 1).toString('base64url'), keyType: 'MANAGED', sealedBlob: blob, address: '0x' + 'a'.repeat(40) };
const nostr = { id: 'n', userId: 'u', sealingContext: Buffer.alloc(32, 2).toString('base64url'), sealedSecret: blob, pubkeyHex: 'b'.repeat(64) };
const legacy = { id: 'l', userId: 'old-user', sealedPrivateKey: blob, publicKey: 'synthetic-SPKI' };

test('complete OpenKey inventory always declares legacy and includes orphan-owned managed rows', () => {
  const inventory = buildOpenKeyInventory({ ethereum: [eth], nostr: [nostr], legacy: [] });
  expect(inventory.records.length).toBe(2);
  expect(inventory.records[0]!.owner).toBe(null);
  expect(inventory.paths.find(p => p.purpose === 'legacy-user-encryption-empty')).toEqual({ path: 'openkey/user/{userId}/encryption', purpose: 'legacy-user-encryption-empty', version: 0, transform: 'sha256-getkey', expectedCount: 0 });
  const positive = buildOpenKeyInventory({ ethereum: [], nostr: [], legacy: [legacy] });
  expect(positive.paths).toEqual([{ path: 'openkey/user/old-user/encryption', purpose: 'legacy-user-encryption', version: 0, transform: 'sha256-getkey', expectedCount: 1 }]);
  expect(positive.paths.some(p => p.purpose === 'legacy-user-encryption-empty')).toBe(false);
  expect(buildOpenKeyInventory({ ethereum: [], nostr: [], legacy: [] }).paths.length).toBe(1);
  const external = { ...eth, keyType: 'EXTERNAL', sealedBlob: null };
  expect(buildOpenKeyInventory({ ethereum: [external], nostr: [], legacy: [] }).records).toEqual([]);
});

test('missing tables, unsupported rows and ambiguous legacy identities fail closed', () => {
  expect(() => buildOpenKeyInventory({ ethereum: [], nostr: [] } as unknown as OpenKeySnapshotRows)).toThrow();
  for (const ethereum of [[{ ...eth, sealedBlob: null }], [{ ...eth, keyType: 'EXTERNAL' }], [{ ...eth, sealingContext: null }], [eth, eth]]) {
    expect(() => buildOpenKeyInventory({ ethereum, nostr: [], legacy: [] })).toThrow();
  }
  expect(() => buildOpenKeyInventory({ ethereum: [], nostr: [], legacy: [legacy, legacy] })).toThrow();
  expect(() => buildOpenKeyInventory({ ethereum: [], nostr: [], legacy: [{ ...legacy, userId: '{userId}' }] })).toThrow();
  expect(() => buildOpenKeyInventory({ ethereum: [], nostr: [{ ...nostr, pubkeyHex: 'invalid' }], legacy: [] })).toThrow();
});
