import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, writeFile, readFile, copyFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sha = 'a'.repeat(40);
const deploymentId = '11111111-1111-1111-1111-111111111111';
const project = (envVars: Record<string, { type: string; value?: string }>) => JSON.stringify({
  success: true,
  result: {
    build_config: { build_command: 'bun install && bun run build --filter @openkey/web' },
    source: { config: { production_branch: 'main' } },
    canonical_deployment: { id: '22222222-2222-2222-2222-222222222222' },
    deployment_configs: { production: { env_vars: envVars } },
  },
});

async function fixture(response: string) {
  const root = await mkdtemp(join(tmpdir(), 'openkey-upload-test-'));
  const bin = join(root, 'bin');
  const release = join(root, 'scripts/release');
  await mkdir(bin, { recursive: true });
  await mkdir(release, { recursive: true });
  await copyFile(join(import.meta.dir, 'openkey-web-direct-upload.sh'), join(release, 'openkey-web-direct-upload.sh'));
  const command = async (name: string, content: string) => {
    const path = join(bin, name);
    await writeFile(path, `#!/usr/bin/env bash\nset -euo pipefail\n${content}\n`);
    await chmod(path, 0o755);
  };
  await command('git', `if [[ "$1" == rev-parse ]]; then echo '${sha}'; else exit 0; fi`);
  await command('curl', `if [[ "$*" == *pages/projects/openkey* ]]; then
  [[ "$*" != *'Bearer token'* && "$*" == *'-H @-'* && -z "${'${CLOUDFLARE_API_TOKEN:-}'}" ]] || exit 91
  IFS= read -r header
  [[ "$header" == 'Authorization: Bearer token' ]] || exit 92
fi
if [[ "$*" == *pages/projects/openkey/deployments/* ]]; then
  printf '%s\\n' '{"success":true,"result":{"environment":"preview","deployment_trigger":{"metadata":{"commit_hash":"${sha}"}},"latest_stage":{"status":"success"}}}'
elif [[ "$*" == *pages/projects/openkey* ]]; then
  if [[ -f '${join(root, 'uploaded')}' ]]; then
    printf '%s\\n' '{"success":true,"result":{"canonical_deployment":{"id":"${deploymentId}","deployment_trigger":{"metadata":{"commit_hash":"${sha}"}},"latest_stage":{"status":"success"}}}}'
  else
    cat '${join(root, 'project.json')}'
  fi
else
  printf '%s\\n' "$*" >> '${join(root, 'commands.log')}'
  printf '200'
fi`);
  await command('bun', `printf '%s\\n' "$*" >> '${join(root, 'commands.log')}'
printf '%s\\n' "$HOME" >> '${join(root, 'build-homes.log')}'
[[ -d "$HOME" && "$HOME" != '${process.env.HOME}' ]] || exit 93
if [[ "${'${CLOUDFLARE_API_TOKEN+x}'}" ]]; then echo 'build received CF token' >&2; exit 81; fi
if [[ "$*" == *'audit:web:prod'* && -f '${join(root, 'fail-audit')}' ]]; then exit 1; fi
if [[ "$*" == *'run build'* ]]; then
  mkdir -p apps/web/.svelte-kit/cloudflare
  printf '%s\\n' "built for ${'${VITE_API_URL}'}" > apps/web/.svelte-kit/cloudflare/index.js
fi`);
  await command('wrangler', `[[ "${'${CLOUDFLARE_API_TOKEN:-}'}" == token && "${'${CLOUDFLARE_ACCOUNT_ID:-}'}" == account && "$*" != *token* ]] || exit 94
printf '%s\\n' "$*" >> '${join(root, 'commands.log')}'
touch '${join(root, 'uploaded')}'
printf '%s\\n' 'https://12345678.openkey.pages.dev'`);
  const responsePath = join(root, 'project.json');
  await writeFile(responsePath, response);
  const run = (args: string[], extraEnv: Record<string, string> = {}) => Bun.spawnSync(['bash', join(release, 'openkey-web-direct-upload.sh'), ...args], {
    cwd: root,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, CLOUDFLARE_API_TOKEN: 'token', CLOUDFLARE_ACCOUNT_ID: 'account', ...extraEnv },
    stdout: 'pipe', stderr: 'pipe',
  });
  return { root, run };
}

const vars = { VITE_API_URL: { type: 'plain_text', value: 'https://api.openkey.so' }, VITE_CONSOLE_ORIGIN: { type: 'plain_text', value: 'https://console.openkey.so' } };

test('rejects unreadable production variables before building or uploading', async () => {
  const f = await fixture(project({ ...vars, PRIVATE: { type: 'secret_text' } }));
  try {
    const result = f.run([sha, 'preview']);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout.toString()).not.toContain('https://12345678.openkey.pages.dev');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('preview builds with production API URL and probes its unique URL', async () => {
  const f = await fixture(project(vars));
  try {
    const result = f.run([sha, 'preview']);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain('https://12345678.openkey.pages.dev');
    const log = await readFile(join(f.root, 'commands.log'), 'utf8');
    expect(log).toContain('https://12345678.openkey.pages.dev/auth/register');
    expect(log).toContain('https://12345678.openkey.pages.dev/auth/login');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('production refuses upload without a preview deployment id', async () => {
  const f = await fixture(project(vars));
  try {
    const result = f.run([sha, 'production']);
    expect(result.exitCode).not.toBe(0);
    expect(result.stdout.toString()).not.toContain('https://12345678.openkey.pages.dev');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('audit failure prevents the preview upload', async () => {
  const f = await fixture(project(vars));
  try {
    await writeFile(join(f.root, 'fail-audit'), '');
    const result = f.run([sha, 'preview']);
    expect(result.exitCode).not.toBe(0);
    const log = await readFile(join(f.root, 'commands.log'), 'utf8').catch(() => '');
    expect(log).toContain('audit:web:prod');
    expect(log).not.toContain('pages deploy');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('production verifies preview SHA and reports the new canonical deployment', async () => {
  const f = await fixture(project(vars));
  try {
    const result = f.run([sha, 'production', '--preview-verified', deploymentId]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString()).toContain('22222222-2222-2222-2222-222222222222');
    expect(result.stdout.toString()).toContain(deploymentId);
    const log = await readFile(join(f.root, 'commands.log'), 'utf8');
    expect(log).toContain('--branch main --commit-hash ' + sha);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('rejects a project variable that can change script control flow', async () => {
  const f = await fixture(project({ ...vars, mode: { type: 'plain_text', value: 'preview' } }));
  try {
    const result = f.run([sha, 'preview']);
    expect(result.exitCode).not.toBe(0);
    const log = await readFile(join(f.root, 'commands.log'), 'utf8').catch(() => '');
    expect(log).toBe('');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('build cannot read Cloudflare token, and install uses a frozen lockfile', async () => {
  const f = await fixture(project(vars));
  try {
    const result = f.run([sha, 'preview']);
    expect(result.exitCode).toBe(0);
    const log = await readFile(join(f.root, 'commands.log'), 'utf8');
    expect(log).toContain('install --frozen-lockfile');
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('curl receives the token on stdin, never in argv or environment', async () => {
  const f = await fixture(project(vars));
  try {
    const result = f.run([sha, 'preview']);
    expect(result.exitCode).toBe(0);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});

test('install, build and audit use one temporary HOME removed on exit', async () => {
  const f = await fixture(project(vars));
  try {
    const result = f.run([sha, 'preview']);
    expect(result.exitCode).toBe(0);
    const homes = (await readFile(join(f.root, 'build-homes.log'), 'utf8')).trim().split('\n');
    expect(homes).toHaveLength(3);
    expect(new Set(homes).size).toBe(1);
    expect(await Bun.file(homes[0]).exists()).toBe(false);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
