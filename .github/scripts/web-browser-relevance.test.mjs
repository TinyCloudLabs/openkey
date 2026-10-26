import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('./web-browser-relevance.sh', import.meta.url));

// Names go in NUL-delimited, as `git diff -z` prints them.
function decide(files) {
  const result = spawnSync('bash', [script, '--stdin'], { input: files.map((file) => `${file}\0`).join(''), encoding: 'utf8' });
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
  ['tsconfig.json', 'true'],
  ['bunfig.toml', 'true'],
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
  ['tsconfig.base.json', 'false'],
  ['docs/tsconfig.json', 'false'],
  ['apps/api/tsconfig.json', 'false'],
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

test('a name with a newline or a quote under apps/web is matched as it is', () => {
  assert.equal(decide(['apps/web/with\nnewline.spec.ts']).relevant, 'true');
  assert.equal(decide(['apps/web/with"quote.spec.ts']).relevant, 'true');
  assert.equal(decide(['docs/with\nnewline.md', 'apps/web/tests/b\u00e9.spec.ts']).relevant, 'true');
  // The same name as Git's C-quoted form (what raw `--name-only` prints) is not under apps/web: the
  // script must not be fed that form.
  assert.equal(decide(['"apps/web/with\\nnewline.spec.ts"']).relevant, 'false');
  assert.equal(decide(['docs/with\nnewline.md']).relevant, 'false');
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

function git(cwd, ...args) {
  const result = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.test', '-c', 'core.quotepath=true', ...args], { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function pullRequest(changed) {
  const cwd = mkdtempSync(`${tmpdir()}/web-browser-relevance-git-`);
  try {
    git(cwd, 'init', '-q');
    mkdirSync(`${cwd}/docs`, { recursive: true });
    writeFileSync(`${cwd}/docs/readme.md`, 'a');
    git(cwd, 'add', '.');
    git(cwd, 'commit', '-q', '-m', 'base');
    const base = git(cwd, 'rev-parse', 'HEAD');
    for (const name of changed) {
      mkdirSync(dirname(`${cwd}/${name}`), { recursive: true });
      writeFileSync(`${cwd}/${name}`, 'b');
    }
    git(cwd, 'add', '-A');
    git(cwd, 'commit', '-q', '-m', 'change');
    const result = spawnSync('bash', [script], { cwd, env: { ...process.env, EVENT: 'pull_request', BASE: base, HEAD: git(cwd, 'rev-parse', 'HEAD') }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
}

test('a real pull request: a relevant file is found, including one whose name Git would C-quote', () => {
  assert.match(pullRequest(['apps/web/src/a.ts']), /^relevant=true\nreason=a relevant path changed: apps\/web\/src\/a\.ts/);
  assert.match(pullRequest(['apps/web/we"ird\nname.spec.ts']), /^relevant=true\n/);
  assert.match(pullRequest(['apps/web/t\u00e9st.spec.ts']), /^relevant=true\n/);
  assert.match(pullRequest(['tsconfig.json']), /^relevant=true\n/);
});

test('a real pull request that changes only other paths skips the specs', () => {
  assert.match(pullRequest(['docs/new.md', 'apps/api/src/x.ts']), /^relevant=false\n/);
});
