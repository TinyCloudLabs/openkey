import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import * as service from '../services/key-sealing';
import { seal, unseal, type TeeClient } from '../../../../packages/tee/src/index';

const context = Buffer.alloc(32, 9).toString('base64url');
const record = { id: 'ethereum-record', userId: 'test-user', sealingContext: context };
const tee: TeeClient = {
  deriveKey: async (path) => createHash('sha256').update('TEST ONLY provider').update(path).digest(),
  getQuote: async () => { throw new Error('Not used'); },
  isInTee: () => false,
};

describe('versioned sealing and re-seal maintenance production wiring', () => {

  test('default writes remain readable by the previous headerless primitive', async () => {
    const sealed = await service.sealKeyForRecord(tee, record, 'TEST ONLY payload');
    const key = await tee.deriveKey(service.resolveSealingContext(record));
    expect(await unseal(sealed, key)).toBe('TEST ONLY payload');
    expect(service.createRecordKeyring(tee).writeKid).toBe(0);
  });

  test('reads legacy user-path rows through the same derivation', async () => {
    const legacy = { id: 'legacy-record', userId: 'test-user', sealingContext: null };
    const blob = await seal('TEST ONLY legacy payload', await tee.deriveKey('openkey/user/test-user/keys'));
    expect(await service.unsealKeyForRecord(tee, legacy, blob)).toBe('TEST ONLY legacy payload');
    expect(service.recordSealingBinding(legacy)).toEqual({ recordId: legacy.id, sealingContext: 'openkey/user/test-user/keys' });
  });
});
