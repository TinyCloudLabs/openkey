import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide } from './require-green.mjs';

const sha = 'a'.repeat(40);
const names = ['API test suite', 'gitleaks'];
const run = (id, name, conclusion, overrides = {}) => ({
  id, name, head_sha: sha, app: { id: 15368 },
  status: conclusion ? 'completed' : 'in_progress', conclusion, ...overrides,
});
const page = (check_runs, total_count = check_runs.length) => ({ check_runs, total_count });

test('every required check green on the exact sha passes', () => {
  assert.equal(decide([page([run(1, 'API test suite', 'success'), run(2, 'gitleaks', 'success')])], sha, names).state, 'success');
});

test('a missing, running or non-Actions check is pending, never success', () => {
  assert.equal(decide([page([run(1, 'API test suite', 'success')])], sha, names).state, 'pending');
  assert.equal(decide([page([run(1, 'API test suite', 'success'), run(2, 'gitleaks', null)])], sha, names).state, 'pending');
  const impostor = run(2, 'gitleaks', 'success', { app: { id: 85455 } });
  assert.equal(decide([page([run(1, 'API test suite', 'success'), impostor])], sha, names).state, 'pending');
  const otherSha = run(2, 'gitleaks', 'success', { head_sha: 'b'.repeat(40) });
  assert.equal(decide([page([run(1, 'API test suite', 'success'), otherSha])], sha, names).state, 'pending');
});

test('skipped, cancelled or failed fails; the newest attempt decides', () => {
  for (const conclusion of ['failure', 'skipped', 'cancelled', 'neutral', 'timed_out']) {
    assert.equal(decide([page([run(1, 'API test suite', 'success'), run(2, 'gitleaks', conclusion)])], sha, names).state, 'failure');
  }
  const retried = [run(1, 'API test suite', 'success'), run(2, 'gitleaks', 'failure'), run(3, 'gitleaks', 'success')];
  assert.equal(decide([page(retried)], sha, names).state, 'success');
  assert.equal(decide([page([...retried, run(4, 'gitleaks', 'failure')])], sha, names).state, 'failure');
});

test('an incomplete or malformed API response throws', () => {
  assert.throws(() => decide([], sha, names), /incomplete/);
  assert.throws(() => decide([page([run(1, 'gitleaks', 'success')], 2)], sha, names), /incomplete/);
  assert.throws(() => decide([{ check_runs: [] }], sha, names), /incomplete/);
});

const stale = (id, name, conclusion, completed_at = '2026-11-27T21:56:48Z') =>
  run(id, name, conclusion, { status: 'in_progress', completed_at });

test('a check-run stuck at in_progress with a success conclusion and a completed_at passes', () => {
  assert.equal(decide([page([run(1, 'API test suite', 'success'), stale(2, 'gitleaks', 'success')])], sha, names).state, 'success');
});

test('an in_progress check-run with no conclusion is pending, with or without a completed_at', () => {
  assert.equal(decide([page([run(1, 'API test suite', 'success'), stale(2, 'gitleaks', null)])], sha, names).state, 'pending');
  assert.equal(decide([page([run(1, 'API test suite', 'success'), stale(2, 'gitleaks', null, null)])], sha, names).state, 'pending');
});

test('an in_progress check-run with a conclusion but no completed_at is pending', () => {
  assert.equal(decide([page([run(1, 'API test suite', 'success'), stale(2, 'gitleaks', 'success', null)])], sha, names).state, 'pending');
});

test('a stale in_progress check-run with a failing conclusion is red', () => {
  for (const conclusion of ['failure', 'skipped', 'cancelled', 'neutral', 'timed_out']) {
    assert.equal(decide([page([run(1, 'API test suite', 'success'), stale(2, 'gitleaks', conclusion)])], sha, names).state, 'failure');
  }
});

test('the newest attempt still decides when an older one is stale', () => {
  assert.equal(decide([page([run(1, 'API test suite', 'success'), stale(2, 'gitleaks', 'success'), run(3, 'gitleaks', 'failure')])], sha, names).state, 'failure');
  assert.equal(decide([page([run(1, 'API test suite', 'success'), run(2, 'gitleaks', 'failure'), stale(3, 'gitleaks', 'success')])], sha, names).state, 'success');
});
