// TC-3353: the owner digest and the receipt write, without a database.
import { describe, expect, test } from 'bun:test';
import { ownerDigestFor, recordAccountDeletionReceipt } from '../services/account-deletion-receipt';

// Computed independently: printf %s 'did:pkh:eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' | sha256sum
const CHECKSUM_ADDRESS = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const CHECKSUM_DIGEST = '3ddb4996960256d28059a5e2d332bc2de767ad0d85b107f37dea23986d491530';
const OTHER_ADDRESS = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';

describe('ownerDigestFor', () => {
  test('is the SHA-256 of the did:pkh built from the EIP-55 address', () => {
    expect(ownerDigestFor(CHECKSUM_ADDRESS)).toBe(CHECKSUM_DIGEST);
  });

  test('a lowercase stored address gives the same digest as its EIP-55 form', () => {
    expect(ownerDigestFor(CHECKSUM_ADDRESS.toLowerCase())).toBe(CHECKSUM_DIGEST);
  });
});

function fakeTransaction() {
  const created: { data: { ownerDigests: string[] } }[] = [];
  const transaction = { accountDeletionReceipt: { create: async (args: { data: { ownerDigests: string[] } }) => { created.push(args); return {}; } } };
  return { transaction: transaction as unknown as Parameters<typeof recordAccountDeletionReceipt>[0], created };
}

describe('recordAccountDeletionReceipt', () => {
  test('writes no receipt when the account had no keys', async () => {
    const { transaction, created } = fakeTransaction();
    expect(await recordAccountDeletionReceipt(transaction, [])).toBe(false);
    expect(created).toHaveLength(0);
  });

  test('writes one receipt with sorted, deduplicated digests', async () => {
    const { transaction, created } = fakeTransaction();
    const keys = [{ address: OTHER_ADDRESS }, { address: CHECKSUM_ADDRESS.toLowerCase() }, { address: CHECKSUM_ADDRESS }];
    expect(await recordAccountDeletionReceipt(transaction, keys)).toBe(true);
    expect(created).toHaveLength(1);
    expect(created[0]!.data.ownerDigests).toEqual([ownerDigestFor(CHECKSUM_ADDRESS), ownerDigestFor(OTHER_ADDRESS)].sort());
    expect(Object.keys(created[0]!.data)).toEqual(['ownerDigests']);
  });
});
