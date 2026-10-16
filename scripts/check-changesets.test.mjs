import { afterEach, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repo = resolve(import.meta.dir, '..');
const cli = join(repo, 'node_modules/.bin/changeset');
const directories = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function status(cwd, output = false) {
  return spawnSync(process.execPath, [cli, 'status', ...(output ? ['--output=release-plan.json'] : [])], {
    cwd,
    encoding: 'utf8',
  });
}

function fixture(changesets) {
  const directory = mkdtempSync(join(tmpdir(), 'openkey-changeset-'));
  directories.push(directory);
  mkdirSync(join(directory, '.changeset'));
  mkdirSync(join(directory, 'packages/sdk'), { recursive: true });
  mkdirSync(join(directory, 'packages/web'), { recursive: true });
  symlinkSync(join(repo, 'node_modules'), join(directory, 'node_modules'), 'dir');
  writeFileSync(join(directory, 'package.json'), JSON.stringify({ private: true, workspaces: ['packages/*'] }));
  writeFileSync(join(directory, 'packages/sdk/package.json'), JSON.stringify({ name: '@openkey/sdk', version: '0.12.0' }));
  writeFileSync(join(directory, 'packages/web/package.json'), JSON.stringify({ name: '@openkey/web', version: '0.0.2' }));
  writeFileSync(join(directory, '.changeset/config.json'), JSON.stringify({ baseBranch: 'main', ignore: ['@openkey/web'] }));
  for (const [name, contents] of Object.entries(changesets)) {
    writeFileSync(join(directory, '.changeset', `${name}.md`), contents);
  }
  for (const args of [['init', '-b', 'main'], ['add', '.changeset', 'package.json', 'packages'], ['-c', 'user.name=CI', '-c', 'user.email=ci@example.test', 'commit', '-m', 'fixture']]) {
    const git = spawnSync('git', args, { cwd: directory, encoding: 'utf8' });
    if (git.status !== 0) throw new Error(git.stderr);
  }
  return directory;
}

const sdk = '---\n"@openkey/sdk": patch\n---\n\nSDK fix.\n';
const web = '---\n"@openkey/web": patch\n---\n\nWeb fix.\n';

test('the release plan rejects a changeset mixing ignored web and publishable SDK', () => {
  const directory = fixture({ mixed: '---\n"@openkey/sdk": patch\n"@openkey/web": patch\n---\n\nBoth.\n' });
  const result = status(directory);
  expect(result.status).not.toBe(0);
  expect(result.stderr + result.stdout).toContain('Mixed changesets that contain both ignored and not ignored packages are not allowed');
});

test('separate SDK and ignored web changesets plan only an SDK bump', () => {
  const directory = fixture({ sdk, web });
  const result = status(directory, true);
  expect(result.status, result.stderr + result.stdout).toBe(0);
  const plan = JSON.parse(readFileSync(join(directory, 'release-plan.json'), 'utf8'));
  expect(plan.releases.filter((release) => release.type !== 'none').map(({ name, newVersion }) => ({ name, newVersion })))
    .toEqual([{ name: '@openkey/sdk', newVersion: '0.12.1' }]);
});

test('the PR checkout has a valid release plan', () => {
  const result = status(repo);
  expect(result.status, result.stderr + result.stdout).toBe(0);
});
