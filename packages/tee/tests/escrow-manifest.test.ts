import { expect, test } from 'bun:test';
import { encodeRecordManifest, recordManifestHash } from '../src/escrow-manifest';
import vector from './fixtures/escrow-header-v1.json';
import type { EscrowHeader } from '../src/escrow-header';
const paths = (vector.header as EscrowHeader).paths;
const entry = { table: 'test_table', rowId: 'row', owner: 'owner', path: paths[0]!.path, purpose: paths[0]!.purpose, version: 0, transform: 'sha256-getkey' as const, expectedIdentity: 'synthetic-public-identity', ciphertextChecksum: 'a'.repeat(64) };
test('record manifest binds exact identities, ciphertext checksums and per-path counts', () => {
  expect(new TextDecoder().decode(encodeRecordManifest([entry], paths))).toBe(JSON.stringify(['tinycloud/escrow/record-manifest', 1, [[entry.table, entry.rowId, entry.owner, entry.path, entry.purpose, entry.version, entry.transform, entry.expectedIdentity, entry.ciphertextChecksum]]]));
  expect(recordManifestHash([{ ...entry, expectedIdentity: 'different' }], paths)).not.toBe(recordManifestHash([entry], paths));
  expect(() => encodeRecordManifest([], paths)).toThrow();
  expect(() => encodeRecordManifest([entry, entry], paths)).toThrow();
  expect(() => encodeRecordManifest([{ ...entry, path: 'unexpected' }], paths)).toThrow();
  const two = [{ ...paths[0]!, expectedCount: 2 }];
  const another = { ...entry, rowId: 'another' };
  expect(encodeRecordManifest([entry, another], two)).toEqual(encodeRecordManifest([another, entry], two));
});
