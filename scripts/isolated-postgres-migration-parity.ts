#!/usr/bin/env bun

/**
 * The one PostgreSQL check: a disposable cluster owned and stopped by the
 * invoking user. It exercises Prisma's production migration engine only.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repoRoot = resolve(import.meta.dir, '..');
const root = await mkdtemp(join(tmpdir(), 'openkey-postgres-parity-'));
const port = 32_000 + Math.floor(Math.random() * 1_000);
const bindir = (await new Response(Bun.spawn(['pg_config', '--bindir'], { stdout: 'pipe' }).stdout).text()).trim();
if (!bindir) throw new Error('pg_config is required for the isolated PostgreSQL parity check');
const bin = (name: string) => join(bindir, name);
const databaseUrl = `postgresql://openkey@127.0.0.1:${port}/openkey`;

async function run(command: string[], env = process.env) {
  const child = Bun.spawn(command, { cwd: repoRoot, env, stdout: 'inherit', stderr: 'inherit' });
  const exitCode = await child.exited;
  if (exitCode !== 0) throw new Error(`${command.join(' ')} exited ${exitCode}`);
}

try {
  await run([bin('initdb'), '--no-locale', '--encoding=UTF8', '--auth-local=trust', '--auth-host=trust', '--username=openkey', '--pgdata', join(root, 'data')]);
  await run([bin('pg_ctl'), '--pgdata', join(root, 'data'), '--options', `-p ${port} -h 127.0.0.1 -k ${root}`, '--wait', 'start']);
  await run([bin('createdb'), '--host', '127.0.0.1', '--port', String(port), '--username', 'openkey', 'openkey']);
  await run(['bun', 'run', 'db:migrate:apply'], { ...process.env, DATABASE_URL: databaseUrl });
  // A second deploy must be a no-op. Schema drift is tracked separately from
  // this narrow production-engine parity check.
  await run(['bun', 'run', 'db:migrate:apply'], { ...process.env, DATABASE_URL: databaseUrl });
  console.log('Isolated PostgreSQL migration-deploy parity passed as the invoking user.');
} finally {
  await Bun.spawn([bin('pg_ctl'), '--pgdata', join(root, 'data'), '--wait', 'stop', '--mode', 'immediate'], { stdout: 'ignore', stderr: 'ignore' }).exited.catch(() => undefined);
  await rm(root, { recursive: true, force: true });
}
