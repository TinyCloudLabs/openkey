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
  const deployed = commit('deployed');
  const newer = commit('newer');
  git('checkout', '-q', '-b', 'side', older);
  const side = commit('side');
  shas = { older, deployed, newer, side };
});
after(() => rmSync(repo, { recursive: true, force: true }));

const deployRun = (head_sha, updated_at, jobName = 'deploy', conclusion = 'success') => ({
  id: 1, head_sha, updated_at, jobs: [{ name: jobName, conclusion }],
});
const smokeRun = (id, overrides = {}) => ({
  id, status: 'completed', conclusion: 'success', head_sha: shas.newer,
  created_at: '2026-11-22T10:00:00Z', run_started_at: '2026-11-22T10:00:00Z', html_url: `https://example.test/${id}`,
  ...overrides,
});
function gate(deployRuns, smokeRuns) {
  const result = spawnSync(process.execPath, [script], {
    cwd: repo, input: JSON.stringify({ deployRuns, smokeRuns }), encoding: 'utf8',
  });
  return { status: result.status, text: `${result.stdout}${result.stderr}` };
}
const deployedAt = '2026-11-22T09:50:22Z';

test('a green smoke on a later commit, started after the deploy finished, passes', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [smokeRun(7)]);
  assert.equal(result.status, 0, result.text);
});

test('a green smoke on the deployed commit itself passes', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [smokeRun(7, { head_sha: shas.deployed })]);
  assert.equal(result.status, 0, result.text);
});

test('a green smoke that started before the deploy finished asks to dispatch the smoke', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [smokeRun(7, { run_started_at: '2026-11-22T09:44:00Z' })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /dispatch the smoke first/);
});

test('a smoke on a commit before the deployed one asks to dispatch the smoke', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [smokeRun(7, { head_sha: shas.older })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /dispatch the smoke first/);
});

test('a smoke on a commit outside the deployed history asks to dispatch the smoke', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [smokeRun(7, { head_sha: shas.side })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /dispatch the smoke first/);
});

test('the newest completed smoke decides, and a red one fails the gate', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [
    smokeRun(7),
    smokeRun(8, { conclusion: 'failure', created_at: '2026-11-22T10:30:00Z' }),
  ]);
  assert.equal(result.status, 1);
  assert.match(result.text, /failure \(run 8/);
});

test('skipped, cancelled and unfinished smokes carry no verdict', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [
    smokeRun(7),
    smokeRun(8, { conclusion: 'skipped', created_at: '2026-11-22T10:10:00Z' }),
    smokeRun(9, { conclusion: 'cancelled', created_at: '2026-11-22T10:20:00Z' }),
    smokeRun(10, { status: 'in_progress', conclusion: null, created_at: '2026-11-22T10:30:00Z' }),
  ]);
  assert.equal(result.status, 0, result.text);
});

test('no completed smoke asks to dispatch the smoke', () => {
  const result = gate([deployRun(shas.deployed, deployedAt)], [smokeRun(7, { conclusion: 'skipped' })]);
  assert.equal(result.status, 1);
  assert.match(result.text, /dispatch the smoke first/);
});

test('a preflight-only run is not a deploy', () => {
  const preflight = deployRun(shas.newer, '2026-11-22T10:05:00Z', 'preflight');
  const deploy = deployRun(shas.deployed, deployedAt);
  const result = gate([preflight, deploy], [smokeRun(7, { run_started_at: '2026-11-22T10:00:00Z' })]);
  assert.equal(result.status, 0, result.text);
});
