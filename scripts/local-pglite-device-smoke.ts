#!/usr/bin/env bun

/**
 * Fresh local acceptance check: PGlite-backed API, published TinyCloud CLI,
 * real device transaction, OTP session, approval, and Share upload.
 */
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repoRoot = resolve(import.meta.dir, '..');
const cliFlag = process.argv.indexOf('--cli');
const requestedCli = cliFlag < 0 ? undefined : process.argv[cliFlag + 1];
if (cliFlag >= 0 && !requestedCli) throw new Error('--cli requires an artifact path');
const root = await mkdtemp(join(tmpdir(), 'openkey-local-pglite-smoke-'));
const databaseDir = join(root, 'database');
const artifactDir = join(root, 'cli');
const port = 31_000 + Math.floor(Math.random() * 1_000);
const api = `http://127.0.0.1:${port}`;
const env = {
  ...process.env,
  DATABASE_URL: `pglite:${databaseDir}`,
  API_PORT: String(port),
  BETTER_AUTH_SECRET: 'openkey-local-pglite-device-smoke-secret-0123456789',
  DEV_SEALING_KEY: '0123456789abcdef0123456789abcdef',
  TEE_MODE: 'development',
  WEBAUTHN_ORIGIN: 'http://localhost:5173',
  WEBAUTHN_RP_ID: 'localhost',
  BETTER_AUTH_URL: api,
  CORS_ORIGIN: 'http://localhost:5173',
};

async function run(command: string[], options: { cwd?: string; quiet?: boolean } = {}) {
  const child = Bun.spawn(command, { cwd: options.cwd ?? repoRoot, env, stdout: options.quiet ? 'pipe' : 'inherit', stderr: options.quiet ? 'pipe' : 'inherit' });
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error(`${command.join(' ')} exited ${exitCode}`);
}

async function waitForApi() {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (await fetch(`${api}/health`).then((response) => response.ok).catch(() => false)) return;
    await Bun.sleep(100);
  }
  throw new Error('local PGlite API did not become healthy');
}

let server: ReturnType<typeof Bun.spawn> | undefined;
try {
  await run(['bun', 'run', 'db:push']);
  const cliPath = requestedCli
    ? resolve(requestedCli)
    : join(artifactDir, 'node_modules/@tinycloud/cli/dist/index.js');
  if (!requestedCli) {
    await run(['npm', 'install', '--prefix', artifactDir, '--no-package-lock', '--ignore-scripts', '@tinycloud/cli@0.9.1-beta.7']);
  }
  const artifact = await stat(cliPath).catch(() => undefined);
  if (!artifact?.isFile()) throw new Error(`TinyCloud CLI artifact is not an executable file: ${cliPath}`);
  const packageJsonPath = requestedCli
    ? undefined
    : join(artifactDir, 'node_modules/@tinycloud/cli/package.json');
  const packageVersion = packageJsonPath
    ? (JSON.parse(await readFile(packageJsonPath, 'utf8')) as { version?: string }).version
    : 'custom artifact';
  if (!packageVersion) throw new Error(`TinyCloud CLI artifact has no package version: ${cliPath}`);
  console.log(`TinyCloud CLI artifact: ${cliPath} (${packageVersion})`);
  server = Bun.spawn(['bun', 'run', 'apps/api/src/index.ts'], { cwd: repoRoot, env, stdout: 'inherit', stderr: 'inherit' });
  await waitForApi();
  await run(['bun', 'scripts/candidate-device-authorization-smoke.ts', api, '--cli', cliPath]);
} finally {
  server?.kill(9);
  await server?.exited.catch(() => undefined);
  await rm(root, { recursive: true, force: true });
}
