import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';

const workflow = Bun.YAML.parse(await Bun.file(
  new URL('../.github/workflows/tc-492-production-cutover.yml', import.meta.url),
).text()) as { jobs: { cutover: { steps: Array<{ name?: string; run?: string }> } } };
const steps = workflow.jobs.cutover.steps;
const verification = steps.find((step) => step.name === 'Verify the preflight run')?.run;
if (!verification) throw new Error('Missing preflight run verification');

const repository = 'TinyCloudLabs/openkey';
const successfulPreflight = {
  workflow_id: 123,
  head_repository: { full_name: repository },
  event: 'workflow_dispatch',
  head_branch: 'main',
  status: 'completed',
  conclusion: 'success',
};

function verify(run: Record<string, unknown>) {
  return spawnSync('bash', ['-c', `
    gh() {
      case "$2" in
        repos/TinyCloudLabs/openkey/actions/workflows/tc-492-production-cutover.yml) echo 123 ;;
        repos/TinyCloudLabs/openkey/actions/runs/456) printf '%s\\n' "$PREFLIGHT_RESPONSE" ;;
        *) return 1 ;;
      esac
    }
    ${verification}
  `], {
    env: {
      PATH: process.env.PATH,
      GITHUB_REPOSITORY: repository,
      PREFLIGHT_RUN_ID: '456',
      PREFLIGHT_RESPONSE: JSON.stringify(run),
    },
    encoding: 'utf8',
  });
}

test('the cutover verifies a successful TC-492 dispatch before downloading its artifacts', () => {
  const guard = steps.findIndex((step) => step.name === 'Verify the preflight run');
  expect(steps.findIndex((step) => step.name === 'Download preflight evidence')).toBeGreaterThan(guard);
  expect(steps.findIndex((step) => step.name === 'Download encrypted rehearsal backup')).toBeGreaterThan(guard);
  expect(verify(successfulPreflight).status).toBe(0);
});

test.each([
  ['another workflow', { workflow_id: 124 }],
  ['another repository', { head_repository: { full_name: 'fork/openkey' } }],
  ['a push', { event: 'push' }],
  ['a different branch', { head_branch: 'branch' }],
  ['an in-progress run', { status: 'in_progress' }],
  ['a failing run', { conclusion: 'failure' }],
] satisfies Array<[string, Record<string, unknown>]>)('the cutover rejects evidence from %s', (_name, change) => {
  const result = verify({ ...successfulPreflight, ...change });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('The preflight run must be a successful TC-492 dispatch');
});
