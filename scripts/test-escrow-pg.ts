import { mkdtemp, mkdir, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// This harness creates and owns its server; no caller DSN or existing server.
const pgConfig = Bun.which('pg_config');
if (!pgConfig) throw new Error('PostgreSQL development tools are required');
const config = Bun.spawn([pgConfig, '--bindir'], { stdout: 'pipe', stderr: 'inherit' });
const bin = (await new Response(config.stdout).text()).trim();
if (await config.exited !== 0 || !bin.startsWith('/')) throw new Error('Cannot locate PostgreSQL tools');
const base = await mkdtemp(join(tmpdir(), 'openkey-escrow-'));
const data = join(base, 'data'), socket = join(base, 'socket'), log = join(base, 'postgres.log');
await mkdir(socket, { mode: 0o700 });
async function run(args: string[], env?: Record<string, string | undefined>) {
  const child = Bun.spawn(args, { env, stdout: 'inherit', stderr: 'inherit' });
  if (await child.exited !== 0) throw new Error('Escrow PG test command failed: ' + args[0]);
}
let started = false;
try {
  await run([join(bin, 'initdb'), '-D', data, '-U', 'tinycloud', '--auth=trust', '--no-locale']);
  await run([join(bin, 'pg_ctl'), '-D', data, '-l', log, '-o', `-k ${socket} -p 55483 -c listen_addresses=''`, '-w', 'start']);
  started = true;
  await run([process.execPath, 'test',
    'apps/api/src/__tests__/escrow-snapshot.integration.test.ts',
    'apps/api/src/__tests__/escrow-service.integration.test.ts',
    'apps/api/src/__tests__/escrow-approval-store.integration.test.ts',
    'apps/api/src/__tests__/escrow-preflight-store.integration.test.ts',
    'apps/api/src/__tests__/escrow-restore-drill.integration.test.ts',
  ], { ...process.env, OPENKEY_ESCROW_TEST_PG: '1', OPENKEY_ESCROW_TEST_SOCKET: socket });
} catch (error) {
  try { process.stderr.write(await readFile(log, 'utf8')); } catch {}
  throw error;
} finally {
  if (started) await run([join(bin, 'pg_ctl'), '-D', data, '-m', 'fast', '-w', 'stop']);
  await rm(base, { recursive: true, force: true });
}
