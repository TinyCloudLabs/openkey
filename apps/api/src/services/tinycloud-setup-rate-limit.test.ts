// TC-3657 Bobbie C5/N3 + Naomi 15:12:55Z: the in-memory limiter is what tests exercise.
// Production uses the Prisma limiter (replica-safe); the unit assertions cover the shared
// invariants: thresholds, per-owner isolation, case-insensitive subjects, bucket
// independence (mint vs publish), and hourly window reset.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createInMemoryTinyCloudSetupLimiter } from './tinycloud-setup-rate-limit';

const SUBJECT = 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Aa';

test('per-owner publish limit refuses after threshold and reports retry-after seconds', async () => {
  const retryAfter = createInMemoryTinyCloudSetupLimiter({ mint: 10, publish: 3 });
  const now = 1_700_000_000_000;
  assert.equal(await retryAfter(SUBJECT, 'publish', now), 0);
  assert.equal(await retryAfter(SUBJECT, 'publish', now), 0);
  assert.equal(await retryAfter(SUBJECT, 'publish', now), 0);
  const refused = await retryAfter(SUBJECT, 'publish', now);
  assert.ok(refused > 0 && refused <= 3600);
});

test('subjects are isolated — one owner over-limit does not block another', async () => {
  const retryAfter = createInMemoryTinyCloudSetupLimiter({ mint: 10, publish: 1 });
  const now = 1_700_000_000_000;
  const other = 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Bb';
  assert.equal(await retryAfter(SUBJECT, 'publish', now), 0);
  assert.ok((await retryAfter(SUBJECT, 'publish', now)) > 0);
  assert.equal(await retryAfter(other, 'publish', now), 0);
});

test('case-insensitive subject key (two casings of the same address collapse)', async () => {
  const retryAfter = createInMemoryTinyCloudSetupLimiter({ mint: 10, publish: 1 });
  const now = 1_700_000_000_000;
  assert.equal(await retryAfter(SUBJECT, 'publish', now), 0);
  assert.ok((await retryAfter(SUBJECT.toUpperCase(), 'publish', now)) > 0);
});

test('mint and publish buckets are independent', async () => {
  const retryAfter = createInMemoryTinyCloudSetupLimiter({ mint: 1, publish: 1 });
  const now = 1_700_000_000_000;
  assert.equal(await retryAfter(SUBJECT, 'mint', now), 0);
  assert.equal(await retryAfter(SUBJECT, 'publish', now), 0);
  assert.ok((await retryAfter(SUBJECT, 'mint', now)) > 0);
  assert.ok((await retryAfter(SUBJECT, 'publish', now)) > 0);
});

test('window reset: after the hour elapses, admissions resume', async () => {
  const retryAfter = createInMemoryTinyCloudSetupLimiter({ mint: 10, publish: 1 });
  const start = 1_700_000_000_000;
  assert.equal(await retryAfter(SUBJECT, 'publish', start), 0);
  assert.ok((await retryAfter(SUBJECT, 'publish', start)) > 0);
  const afterWindow = start + 60 * 60_000 + 1;
  assert.equal(await retryAfter(SUBJECT, 'publish', afterWindow), 0);
});
