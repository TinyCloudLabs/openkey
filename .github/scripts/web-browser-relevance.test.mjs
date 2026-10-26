import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('./web-browser-relevance.sh', import.meta.url));

function decide(files) {
  const result = spawnSync('bash', [script, '--stdin'], { input: files.join('\n'), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const [relevant, reason] = result.stdout.trim().split('\n');
  return { relevant: relevant.replace('relevant=', ''), reason: reason.replace('reason=', '') };
}

for (const [path, relevant] of [
  ['apps/web/src/routes/delegate/+page.svelte', 'true'],
  ['apps/web/tests/browser/signing-approval-parity.spec.ts', 'true'],
  ['packages/capability-review/src/classify.ts', 'true'],
  ['packages/sdk/src/index.ts', 'true'],
  ['packages/core/src/index.ts', 'true'],
  ['packages/types/src/index.ts', 'true'],
  ['bun.lock', 'true'],
  ['package.json', 'true'],
  ['turbo.json', 'true'],
  ['.github/workflows/web-browser-tests.yml', 'true'],
  ['.github/scripts/web-browser-summary.mjs', 'true'],
  ['.github/web-browser-known-reds.json', 'true'],
  ['apps/api/src/index.ts', 'false'],
  ['packages/db/prisma/schema.prisma', 'false'],
  ['packages/tee/src/index.ts', 'false'],
  ['docs/deployment.md', 'false'],
  ['.changeset/some-change.md', 'false'],
  ['.github/workflows/api-tests.yml', 'false'],
  ['scripts/deploy-production-migrations.ts', 'false'],
  // Near misses: a prefix of a relevant path is not that path.
  ['apps/webhook/src/index.ts', 'false'],
  ['apps/web-old/README.md', 'false'],
  ['bun.lockb', 'false'],
  ['packages/core-extra/index.ts', 'false'],
]) {
  test(`${path} is ${relevant === 'true' ? 'relevant' : 'not relevant'} on its own`, () => {
    assert.equal(decide([path]).relevant, relevant);
  });
}

test('one relevant path among irrelevant ones makes the change relevant, and the reason names it', () => {
  const result = decide(['docs/a.md', 'apps/api/src/index.ts', 'packages/capability-review/src/copy.ts', 'README.md']);
  assert.equal(result.relevant, 'true');
  assert.match(result.reason, /packages\/capability-review\/src\/copy\.ts/);
});

test('only irrelevant paths skip the specs', () => {
  assert.equal(decide(['docs/a.md', 'apps/api/src/index.ts']).relevant, 'false');
});

test('an empty list of changed files fails open', () => {
  assert.equal(decide([]).relevant, 'true');
  assert.equal(decide(['', '']).relevant, 'true');
});

function viaGit(env) {
  const cwd = mkdtempSync(`${tmpdir()}/web-browser-relevance-`);
  try {
    const result = spawnSync('bash', [script], { cwd, env: { ...process.env, ...env }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

test('a push or a manual run always runs the specs', () => {
  for (const event of ['push', 'workflow_dispatch', 'schedule', '']) {
    assert.match(viaGit({ EVENT: event, BASE: '', HEAD: '' }), /^relevant=true\n/);
  }
});

test('a pull request whose diff cannot be computed fails open', () => {
  const output = viaGit({ EVENT: 'pull_request', BASE: '0000000000000000000000000000000000000001', HEAD: '0000000000000000000000000000000000000002' });
  assert.match(output, /^relevant=true\nreason=git diff failed/);
});
