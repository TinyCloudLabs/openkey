import { afterAll, beforeEach, expect, test } from 'bun:test';
import { createHash, randomBytes } from 'node:crypto';
import { EncryptJWT } from 'jose';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';

// TC-2775: only a refused deletion (bad intent, account, code or confirmation) adds to the reviewer
// backoff. A database or transient failure is answered with the same refusal but is not a wrong code.
let failures = 0;
await mockModules({
  '../services/reviewer-accounts': () => ({
    reviewerFailure: async () => { failures += 1; },
  }),
});
// Imported after the mock, under a file-specific query (TC-928), so it binds the mocked reviewer module.
const { reviewerDeleteEndpoints } = await import('../services/reviewer-delete?reviewer-delete-backoff-test' as string);

const origin = 'https://openkey.test';
const secret = 'reviewer-delete-backoff-secret';
const binding = { store: 'apple', userId: 'reviewer', installEpoch: 3, email: 'appreview@tinycloud.xyz', user: null };
const previous = process.env.APPLE_REVIEW_ENABLED;
process.env.APPLE_REVIEW_ENABLED = 'true';
afterAll(() => {
  if (previous === undefined) delete process.env.APPLE_REVIEW_ENABLED;
  else process.env.APPLE_REVIEW_ENABLED = previous;
});
beforeEach(() => { failures = 0; });

async function attempt(database: unknown, cookie?: string) {
  const headers = new Headers({ 'content-type': 'application/json', origin });
  if (cookie) headers.set('cookie', `__Secure-openkey-review-delete=${cookie}`);
  const body = { email: binding.email, code: randomBytes(32).toString('base64url'), confirmation: 'DELETE MY ACCOUNT' };
  const { reviewerDelete } = reviewerDeleteEndpoints(database as PrismaClient, origin);
  return reviewerDelete({ body, headers, request: new Request(`${origin}/api/review-account/delete`, { method: 'POST', headers }), context: { secret } })
    .then(() => 'deleted', (error: { body?: { code?: string } }) => error.body?.code);
}

const intent = () => new EncryptJWT({ store: 'apple', userId: binding.userId, epoch: binding.installEpoch,
  nonce: randomBytes(32).toString('base64url'), expiresAt: Date.now() + 60_000 })
  .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).setExpirationTime('5m')
  .encrypt(createHash('sha256').update(secret).digest());

test('a refused deletion counts toward the backoff', async () => {
  const database = { reviewerAccount: { findUnique: async () => binding } };
  expect(await attempt(database)).toBe('REVIEWER_DELETE_REFUSED');
  expect(failures).toBe(1);
});

test('a database failure is refused without counting toward the backoff', async () => {
  const database = {
    reviewerAccount: { findUnique: async () => binding },
    $transaction: async () => { throw new Error('Connection terminated unexpectedly'); },
  };
  expect(await attempt(database, await intent())).toBe('REVIEWER_DELETE_REFUSED');
  expect(failures).toBe(0);
});
