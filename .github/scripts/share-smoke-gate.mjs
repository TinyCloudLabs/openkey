import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

// Input on stdin: { deployRuns, smokeRuns }.
//   deployRuns: "Deploy API to Phala Cloud" runs on main, newest first, each with { id, head_sha, updated_at, jobs: [{ name, conclusion }] }.
//   smokeRuns: "Share sender sign-in smoke" runs on main, each with { id, status, conclusion, head_sha, run_started_at, created_at, html_url }.
// The working directory is a checkout with full history, used for the ancestry test.
// Exit 0 when the latest completed smoke is green and ran on the deployed API commit or later, after that deploy finished.

const input = JSON.parse(readFileSync(0, 'utf8'));
if (!Array.isArray(input.deployRuns) || !Array.isArray(input.smokeRuns)) {
  throw new Error('Expected { deployRuns, smokeRuns }');
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

const deployed = input.deployRuns.find((run) =>
  run.jobs?.some((job) => job.name === 'deploy' && job.conclusion === 'success')
);
if (!deployed) fail('No successful API deploy found on main, so the deployed commit is unknown; dispatch the smoke first.');

// Skipped and cancelled runs carry no verdict; an unfinished run has none yet.
const verdicts = input.smokeRuns
  .filter((run) => run.status === 'completed' && ['success', 'failure', 'timed_out'].includes(run.conclusion))
  .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id);
const latest = verdicts[0];
if (!latest) fail(`No completed Share sender smoke on main for the deployed API commit ${deployed.head_sha}; dispatch the smoke first.`);

if (latest.conclusion !== 'success') {
  fail(`The latest Share sender smoke on main is ${latest.conclusion} (run ${latest.id}, ${latest.html_url}). Fix production or use override_reason.`);
}

const ancestor = spawnSync('git', ['merge-base', '--is-ancestor', deployed.head_sha, latest.head_sha], { encoding: 'utf8' });
if (ancestor.status !== 0) {
  fail(`The latest green Share sender smoke (run ${latest.id}) ran on ${latest.head_sha}, which does not include the deployed API commit ${deployed.head_sha}; dispatch the smoke first.`);
}
if (Date.parse(latest.run_started_at) < Date.parse(deployed.updated_at)) {
  fail(`The latest green Share sender smoke (run ${latest.id}) started before the deploy of ${deployed.head_sha} finished; dispatch the smoke first.`);
}

console.log(`Share sender smoke run ${latest.id} is green on ${latest.head_sha}, after the API deploy of ${deployed.head_sha}.`);
