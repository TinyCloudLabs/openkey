import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// Input on stdin: { serving, deployRuns, smokeRuns }.
//   serving: the commit the production API reports at /health.
//   deployRuns: "Deploy API to Phala Cloud" runs on main that succeeded for that commit, each { jobs: [{ name, conclusion, completed_at }] }.
//   smokeRuns: "Share sender sign-in smoke" runs on main, each { id, status, conclusion, head_sha, run_started_at, html_url }.
// The working directory is a checkout with full history, used for the ancestry test.
// Exit 0 only when the latest smoke that ran (not skipped) is green, started after the serving API's deploy job finished
// and ran on the serving commit or a later one. The OpenKey web publish check applies the same rule.

const input = JSON.parse(readFileSync(0, 'utf8'));
if (!/^[0-9a-f]{40}$/.test(input.serving ?? '') || !Array.isArray(input.deployRuns) || !Array.isArray(input.smokeRuns)) {
  throw new Error('Expected { serving, deployRuns, smokeRuns }');
}

function blocked(message) {
  console.error(`Blocked: ${message}`);
  process.exit(1);
}

// A preflight run of the same workflow has no deploy job.
const finished = input.deployRuns
  .flatMap((run) => run.jobs ?? [])
  .filter((job) => job.name === 'deploy' && job.conclusion === 'success')
  .map((job) => job.completed_at)
  .sort();
const deployedAt = finished[finished.length - 1];
if (!deployedAt) blocked(`no successful deploy job found for the serving API commit ${input.serving.slice(0, 8)}; dispatch the smoke first.`);

// Most runs of this workflow are skipped check_run events and carry no verdict.
const ran = input.smokeRuns
  .filter((run) => run.status === 'completed' && ['success', 'failure', 'cancelled', 'timed_out'].includes(run.conclusion))
  .sort((a, b) => (a.run_started_at < b.run_started_at ? -1 : a.run_started_at > b.run_started_at ? 1 : a.id - b.id));
const latest = ran[ran.length - 1];
if (!latest) blocked('no Share sender smoke run found on main; dispatch the smoke first.');

const facts = `API ${input.serving.slice(0, 8)} deployed ${deployedAt}; latest smoke ${latest.id} ${latest.conclusion}, started ${latest.run_started_at} on ${latest.head_sha.slice(0, 8)} (${latest.html_url})`;

// Timestamps are UTC in one format, so they compare as text.
if (!(latest.run_started_at > deployedAt)) {
  blocked(`the latest smoke ran before the serving API was deployed, so nothing has tested it yet; dispatch the smoke first. ${facts}`);
}
const ancestor = spawnSync('git', ['merge-base', '--is-ancestor', input.serving, latest.head_sha], { encoding: 'utf8' });
if (ancestor.status !== 0) {
  blocked(`the latest smoke ran on a commit that is not the serving API's or later; dispatch the smoke first. ${facts}`);
}
if (latest.conclusion !== 'success') blocked(`the latest smoke is ${latest.conclusion}. ${facts}`);

console.log(`OK: ${facts}`);
