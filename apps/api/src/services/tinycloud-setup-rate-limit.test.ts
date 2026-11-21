import test from 'node:test';
import assert from 'node:assert/strict';
import { createTinyCloudSetupLimiter } from './tinycloud-setup-rate-limit';

const SUBJECT = 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Aa';

test('per-owner publish limit refuses after threshold and reports retry-after seconds', () => {
  const retryAfter = createTinyCloudSetupLimiter({ mint: 10, publish: 3 });
  const now = 1_700_000_000_000;
  assert.equal(retryAfter(SUBJECT, 'publish', now), 0);
  assert.equal(retryAfter(SUBJECT, 'publish', now), 0);
  assert.equal(retryAfter(SUBJECT, 'publish', now), 0);
  const refused = retryAfter(SUBJECT, 'publish', now);
  assert.ok(refused > 0 && refused <= 3600);
});

test('subjects are isolated — one owner over-limit does not block another', () => {
  const retryAfter = createTinyCloudSetupLimiter({ mint: 10, publish: 1 });
  const now = 1_700_000_000_000;
  const other = 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Bb';
  assert.equal(retryAfter(SUBJECT, 'publish', now), 0);
  assert.ok(retryAfter(SUBJECT, 'publish', now) > 0);
  assert.equal(retryAfter(other, 'publish', now), 0);
});

test('case-insensitive subject key (two casings of the same address collapse)', () => {
  const retryAfter = createTinyCloudSetupLimiter({ mint: 10, publish: 1 });
  const now = 1_700_000_000_000;
  assert.equal(retryAfter(SUBJECT, 'publish', now), 0);
  assert.ok(retryAfter(SUBJECT.toUpperCase(), 'publish', now) > 0);
});

test('mint and publish buckets are independent', () => {
  const retryAfter = createTinyCloudSetupLimiter({ mint: 1, publish: 1 });
  const now = 1_700_000_000_000;
  assert.equal(retryAfter(SUBJECT, 'mint', now), 0);
  assert.equal(retryAfter(SUBJECT, 'publish', now), 0);
  // Both buckets at threshold; both refuse.
  assert.ok(retryAfter(SUBJECT, 'mint', now) > 0);
  assert.ok(retryAfter(SUBJECT, 'publish', now) > 0);
});

test('window reset: after the hour elapses, admissions resume', () => {
  const retryAfter = createTinyCloudSetupLimiter({ mint: 10, publish: 1 });
  const start = 1_700_000_000_000;
  assert.equal(retryAfter(SUBJECT, 'publish', start), 0);
  assert.ok(retryAfter(SUBJECT, 'publish', start) > 0);
  const afterWindow = start + 60 * 60_000 + 1;
  assert.equal(retryAfter(SUBJECT, 'publish', afterWindow), 0);
});
