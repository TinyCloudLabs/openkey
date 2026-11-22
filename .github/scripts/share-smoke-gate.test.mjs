import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';

const script = fileURLToPath(new URL('./share-smoke-gate.mjs', import.meta.url));
let repo;
let shas;

function git(...args) {
  const result = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', ...args], { cwd: repo, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

before(() => {
  repo = mkdtempSync(join(tmpdir(), 'share-smoke-gate-'));
  git('init', '-q');
  const commit = (name) => {
    writeFileSync(join(repo, name), name);
    git('add', name);
    git('commit', '-q', '-m', name);
    return git('rev-parse', 'HEAD');
  };
  const older = commit('older');
  const serving = commit('serving');
  const newer = commit('newer');
  git('checkout', '-q', '-b', 'side', older);
  const side = commit('side');
  shas = { older, serving, newer, side };
});
after(() => rmSync(repo, { recursive: true, force: true }));

const deployedAt = '2026-11-22T09:50:22Z';
const deployRun = (completed_at = deployedAt, name = 'deploy', conclusion = 'success') => ({
  jobs: [{ name, conclusion, completed_at }],
});
const smokeRun = (id, overrides = {}) => ({
  id, status: 'completed', conclusion: 'success', head_sha: shas.newer,
  run_started_at: '2026-11-22T10:00:00Z', html_url: `https://example.test/${id}`,
  ...overrides,
});
function gate(deployRuns, smokeRuns, serving = shas.serving) {
  const result = spawnSync(process.execPath, [script], {
    cwd: repo, input: JSON.stringify({ serving, deployRuns, smokeRuns }), encoding: 'utf8',
  });
  return { status: result.status, text: `${result.stdout}${result.stderr}` };
}

test('a green smoke on a later commit, started after the deploy job finished, passes', () => {
  const result = gate([deployRun()], [smokeRun(7)]);
  assert.equal(result.status, 0, result.text);
});

test('a green smoke on the serving commit itself passes', () => {
  const result = gate([deployRun()], [smokeRun(7, { head_sha: shas.serving })]);
  assert.equal(result.status, 0, result.text);
});

test('a green smoke that started before the deploy job finished is blocked', () => {
  const result = gate([deployRun()], [smokeRun(7, { run_started_at: '2026-11-22T09:44:00Z' })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /before the serving API was deployed/);
});

test('a smoke on a commit before the serving one is blocked', () => {
  const result = gate([deployRun()], [smokeRun(7, { head_sha: shas.older })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /not the serving API's or later/);
});

test('a smoke on a commit outside the serving history is blocked', () => {
  const result = gate([deployRun()], [smokeRun(7, { head_sha: shas.side })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /not the serving API's or later/);
});

test('the newest smoke that ran decides: a red one blocks', () => {
  const result = gate([deployRun()], [
    smokeRun(7),
    smokeRun(8, { conclusion: 'failure', run_started_at: '2026-11-22T10:30:00Z' }),
  ]);
  assert.equal(result.status, 1);
  assert.match(result.text, /latest smoke is failure/);
});

test('a cancelled newest run counts as the latest and blocks', () => {
  const result = gate([deployRun()], [
    smokeRun(7),
    smokeRun(8, { conclusion: 'cancelled', run_started_at: '2026-11-22T10:30:00Z' }),
  ]);
  assert.equal(result.status, 1);
  assert.match(result.text, /latest smoke is cancelled/);
});

test('skipped and unfinished runs carry no verdict', () => {
  const result = gate([deployRun()], [
    smokeRun(7),
    smokeRun(8, { conclusion: 'skipped', run_started_at: '2026-11-22T10:10:00Z' }),
    smokeRun(9, { status: 'in_progress', conclusion: null, run_started_at: '2026-11-22T10:30:00Z' }),
  ]);
  assert.equal(result.status, 0, result.text);
});

test('no run that ran asks to dispatch the smoke', () => {
  const result = gate([deployRun()], [smokeRun(7, { conclusion: 'skipped' })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /dispatch the smoke first/);
});

test('a preflight run has no deploy job, so the serving commit has no deploy time', () => {
  const result = gate([deployRun(deployedAt, 'preflight')], [smokeRun(7)]);
  assert.equal(result.status, 1);
  assert.match(result.text, /no successful deploy job/);
});

test('the latest deploy job time counts when the commit deployed more than once', () => {
  const result = gate([deployRun('2026-11-22T09:00:00Z'), deployRun('2026-11-22T10:15:00Z')], [smokeRun(7)]);
  assert.equal(result.status, 1);
  assert.match(result.text, /before the serving API was deployed/);
});
