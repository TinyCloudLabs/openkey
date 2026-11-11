import { expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { seal, deriveNostrPubkey } from '@openkey/tee';
import { privateKeyToAddress } from 'viem/accounts';
import { buildOpenKeyInventory } from '../services/escrow-inventory';
import { validateOpenKeySnapshot } from '../services/escrow-validate';

test('every persisted Ethereum, Nostr and legacy RSA identity is validated in memory', async () => {
  const key = new Uint8Array(randomBytes(32));
  const secret = '0x' + '01'.padStart(64, '0');
  const nostr = '02'.padStart(64, '0');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
  const inventory = buildOpenKeyInventory({
    ethereum: [{ id: 'e', userId: 'u', sealingContext: null, keyType: 'MANAGED', address: privateKeyToAddress(secret as `0x${string}`), sealedBlob: await seal(secret, key) }],
    nostr: [{ id: 'n', userId: 'u', sealingContext: Buffer.alloc(32, 1).toString('base64url'), pubkeyHex: deriveNostrPubkey(nostr), sealedSecret: await seal(nostr, key) }],
    legacy: [{ id: 'l', userId: 'u', publicKey: rsa.publicKey, sealedPrivateKey: await seal(rsa.privateKey, key) }],
  });
  const material = inventory.paths.map(p => ({ ...p, key }));
  expect(validateOpenKeySnapshot(inventory.records, inventory.paths, material).map(p => p.validatedCount)).toEqual([1, 1, 1]);
  for (let i = 0; i < inventory.records.length; i++) {
    const altered = inventory.records.map((r, j) => j === i ? { ...r, expectedIdentity: i === 2 ? generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' } }).publicKey : '0'.repeat(64) } : r);
    expect(() => validateOpenKeySnapshot(altered, inventory.paths, material)).toThrow();
  }
  expect(() => validateOpenKeySnapshot(inventory.records.slice(1), inventory.paths, material)).toThrow();
  expect(() => validateOpenKeySnapshot([...inventory.records, inventory.records[0]!], inventory.paths, material)).toThrow();
  expect(() => validateOpenKeySnapshot(inventory.records, inventory.paths, material.slice(1))).toThrow();
  const empty = buildOpenKeyInventory({ ethereum: [], nostr: [], legacy: [] });
  expect(validateOpenKeySnapshot(empty.records, empty.paths, [])).toEqual([{ path: 'openkey/user/{userId}/encryption', purpose: 'legacy-user-encryption-empty', version: 0, validatedCount: 0 }]);
});
