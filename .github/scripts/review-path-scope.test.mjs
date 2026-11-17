import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { decideRelevance, releaseNote, touchesSignInApproval } from './review-path-scope.mjs';

const script = fileURLToPath(new URL('./review-path-scope.mjs', import.meta.url));

function cli(command, files) {
  const result = spawnSync('node', [script, command, '--stdin'], { input: files.map((file) => `${file}\0`).join(''), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

for (const [path, relevant] of [
  ['apps/api/src/routes/delegate.ts', true],
  ['apps/web/src/routes/oauth/consent/+page.svelte', true],
  ['packages/db/prisma/migrations/20260901_0001_x/migration.sql', true],
  ['packages/capability-review/src/classify.ts', true],
  ['Dockerfile', true],
  ['bun.lock', true],
  ['scripts/review-path/seed.ts', true],
  ['.github/workflows/review-path.yml', true],
  ['.github/scripts/review-path-scope.mjs', true],
  ['docs/deployment.md', false],
  ['.changeset/a.md', false],
  ['.github/workflows/web-browser-tests.yml', false],
  ['apps/webhook/src/index.ts', false],
  ['docker-compose.prod.yml', false],
]) {
  test(`${path} is ${relevant ? 'relevant' : 'not relevant'} to the Review path`, () => {
    assert.equal(decideRelevance([path]).relevant, relevant);
  });
}

test('an empty file list runs the check, and one relevant path among others names itself', () => {
  assert.equal(decideRelevance([]).relevant, true);
  const decision = decideRelevance(['docs/a.md', 'apps/api/src/index.ts']);
  assert.equal(decision.relevant, true);
  assert.match(decision.reason, /apps\/api\/src\/index\.ts/);
});

for (const [path, touches] of [
  ['apps/api/src/auth.ts', true],
  ['apps/api/src/oauth-config.ts', true],
  ['apps/api/src/routes/delegate.ts', true],
  ['apps/api/src/routes/approval-requests.ts', true],
  ['apps/api/src/services/reviewer-auth.ts', true],
  ['apps/api/src/services/mcp-grants.ts', true],
  ['apps/web/src/routes/delegate/+page.svelte', true],
  ['apps/web/src/routes/auth/login/+page.svelte', true],
  ['apps/web/src/lib/delegate-link-policy.ts', true],
  ['packages/capability-review/src/classify.ts', true],
  ['packages/db/prisma/migrations/20260901_0001_x/migration.sql', true],
  ['apps/api/src/services/reviewer-auth.test.ts', false],
  ['apps/web/tests/browser/delegate-primary-key.spec.ts', false],
  ['apps/api/src/__tests__/reviewer-accounts.integration.test.ts', false],
  ['apps/web/src/routes/dashboard/settings/+page.svelte', false],
  ['apps/api/src/routes/internal-metrics.ts', false],
  ['docs/deployment.md', false],
  ['packages/capability-review/README.md', false],
]) {
  test(`${path} ${touches ? 'touches' : 'does not touch'} sign-in/approval`, () => {
    assert.equal(touchesSignInApproval(path), touches);
  });
}

test('the note names the PRs of the commits that touch sign-in/approval, and a commit without a PR by its sha', () => {
  const commits = [
    { sha: 'a'.repeat(40), subject: 'Fix delegate prepare (#611)', files: ['apps/api/src/routes/delegate.ts'] },
    { sha: 'b'.repeat(40), subject: 'Docs (#612)', files: ['docs/a.md'] },
    { sha: 'c'.repeat(40), subject: 'direct push to auth', files: ['apps/api/src/auth.ts'] },
    { sha: 'd'.repeat(40), subject: 'Again (#611)', files: ['apps/api/src/routes/delegate.ts'] },
    { sha: 'e'.repeat(40), subject: 'Merge pull request #613 from TinyCloudLabs/fix/x', files: ['apps/web/src/routes/oauth/consent/+page.svelte'] },
  ];
  const files = commits.flatMap((commit) => commit.files);
  assert.equal(releaseNote(files, commits), 'touches sign-in/approval: yes (#611, ccccccc, #613)');
});

test('a diff with nothing on a sign-in/approval path says no', () => {
  assert.equal(releaseNote(['docs/a.md', 'apps/api/src/routes/internal-metrics.ts'], []), 'touches sign-in/approval: no');
});

test('an unreadable or empty diff fails open to yes', () => {
  assert.match(releaseNote(null, []), /^touches sign-in\/approval: yes/);
  assert.match(releaseNote([], []), /^touches sign-in\/approval: yes/);
});

test('the command line prints the decision for $GITHUB_OUTPUT and the note line', () => {
  assert.equal(cli('relevance', ['docs/a.md']), 'relevant=false\nreason=no API, web app, package, image build or Review path file changed in this pull request');
  assert.equal(cli('note', ['apps/api/src/auth.ts']), 'touches sign-in/approval: yes');
  assert.equal(cli('note', ['docs/a.md']), 'touches sign-in/approval: no');
});

test('without --stdin an unreadable diff fails open on the command line', () => {
  for (const command of ['relevance', 'note']) {
    const result = spawnSync('node', [script, command], { env: { PATH: process.env.PATH, EVENT: 'pull_request', BASE: 'not-a-commit', HEAD: 'not-a-commit' }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, command === 'relevance' ? /relevant=true/ : /yes/);
  }
});
