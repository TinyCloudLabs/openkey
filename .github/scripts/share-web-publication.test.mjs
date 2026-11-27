import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('./share-web-publication.mjs', import.meta.url));
const sha = 'a'.repeat(40);
const attempt = (id, conclusion, overrides = {}) => ({
  id, conclusion, status: 'completed', head_sha: sha,
  name: 'Cloudflare Pages: openkey', app: { id: 85455 }, ...overrides,
});
const page = (check_runs, total_count = check_runs.length) => ({ check_runs, total_count });
const run = (pages) => spawnSync(process.execPath, [script, sha], {
  input: JSON.stringify(pages), encoding: 'utf8',
});
function state(pages) {
  const result = run(pages);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test('a successful retry supersedes failure, including a late older failure event', () => {
  const failure = attempt(10, 'failure', { completed_at: '2026-11-21T16:00:00Z' });
  const retry = attempt(20, 'success', { completed_at: '2026-11-21T15:00:00Z' });
  for (const checks of [[failure, retry], [retry, failure]]) {
    assert.equal(state([page(checks)]), 'published');
  }
  assert.equal(state([page([failure], 2), page([retry], 2)]), 'published');
});

test('newest completed failure refuses despite older success or newer unfinished retry', () => {
  const checks = [attempt(10, 'success'), attempt(20, 'failure')];
  assert.equal(state([page(checks)]), 'failure');
  assert.equal(state([page([...checks, attempt(30, null, { status: 'in_progress' })])]), 'failure');
});

test('cancelled attempts cannot supersede a completed decision', () => {
  for (const [conclusion, expected] of [['success', 'published'], ['failure', 'failure']]) {
    assert.equal(state([page([attempt(10, conclusion), attempt(20, 'cancelled')])]), expected);
  }
  assert.equal(state([page([attempt(10, 'cancelled')])]), 'unpublished');
});

test('another SHA, app, project or branch preview cannot authorize or veto publication', () => {
  const unrelated = [
    { head_sha: 'b'.repeat(40) }, { app: { id: 1 } },
    { name: 'Cloudflare Pages: openkey-demo' },
    { output: { summary: 'Branch Preview URL: https://branch.pages.dev' } },
  ];
  for (const overrides of unrelated) {
    assert.equal(state([page([attempt(20, 'success', overrides)])]), 'unpublished');
    assert.equal(state([page([attempt(10, 'success'), attempt(20, 'failure', overrides)])]), 'published');
    assert.equal(state([page([attempt(10, 'failure'), attempt(20, 'success', overrides)])]), 'failure');
  }
});

test('unpublished, skipped and neutral web attempts do not run smoke', () => {
  assert.equal(state([page([])]), 'unpublished');
  assert.equal(state([page([attempt(10, null, { status: 'queued' })])]), 'unpublished');
  for (const conclusion of ['skipped', 'neutral']) {
    assert.equal(state([page([attempt(10, 'success'), attempt(20, conclusion)])]), 'unpublished');
  }
});

test('failed and unknown deployment conclusions refuse publication', () => {
  for (const conclusion of ['failure', 'timed_out', 'action_required', 'startup_failure', 'stale', null, 'unknown']) {
    assert.equal(state([page([attempt(10, conclusion)])]), 'failure');
  }
});

test('missing, invalid and tied matching IDs refuse, including across pages', () => {
  for (const id of [undefined, null, 0, -1, 1.5, '10', Number.MAX_SAFE_INTEGER + 1]) {
    const result = run([page([attempt(id, 'success')])]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Invalid check-run id/);
  }
  for (const pages of [
    [page([attempt(10, 'success'), attempt(10, 'failure')])],
    [page([attempt(10, 'success')], 2), page([attempt(10, 'failure')], 2)],
  ]) {
    const result = run(pages);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Duplicate check-run id/);
  }
});

test('malformed or incomplete API responses refuse instead of hiding an attempt', () => {
  for (const pages of [[], {}, [page([attempt(10, 'success')], 2)], [{ check_runs: [] }]]) {
    const result = run(pages);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Incomplete check-run response/);
  }
});
