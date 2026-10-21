import { beforeAll, describe, expect, test } from 'bun:test';
import type { signManagedKey as SignManagedKey } from '../services/managed-key-signing';
import { ISSUER_STATEMENT_TYPE } from '../services/org-issuer-statement';
import { orgSpaceMessageText } from './org-space-fixtures';

// The sealed blob is deliberately not a valid sealed record. If the refusal ran
// after unseal, the error would be an unseal failure, not the refusal code. A
// matching refusal therefore proves no key material was touched (K1 D3).
const key = { userId: 'user_1', sealingContext: null };
const garbageBlob = 'not-a-sealed-record';

let signManagedKey: typeof SignManagedKey;

beforeAll(async () => {
  // managed-key-signing.ts calls createTeeClient() at import time, which reads
  // TEE_MODE. It must be set before the module loads, so the import is dynamic.
  process.env.TEE_MODE ??= 'development';
  ({ signManagedKey } = await import('../services/managed-key-signing'));
});

describe('personal managed-key signing refuses issuer statements (K1 D3)', () => {
  test('refuses statement text before unseal', async () => {
    const text = `${ISSUER_STATEMENT_TYPE}\nStatement body`;
    await expect(signManagedKey(key, garbageBlob, text)).rejects.toThrow(
      'message_rejected:issuer_statement_not_personal',
    );
  });

  test('refuses a statement embedded inside a larger message', async () => {
    const text = `prefix ${ISSUER_STATEMENT_TYPE} suffix`;
    await expect(signManagedKey(key, garbageBlob, text)).rejects.toThrow(
      'message_rejected:issuer_statement_not_personal',
    );
  });

  test('refuses an org-space message before unseal', async () => {
    await expect(signManagedKey(key, garbageBlob, orgSpaceMessageText())).rejects.toThrow(
      'message_rejected:org_space_not_personal',
    );
  });

  test('refuses an org-space message embedded inside a larger message', async () => {
    await expect(signManagedKey(key, garbageBlob, `prefix ${orgSpaceMessageText()} suffix`)).rejects.toThrow(
      'message_rejected:org_space_not_personal',
    );
  });
});
