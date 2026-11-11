// Operator-only bridge to the pinned Home seeder. No owner key is read here.
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const PIN = 'faad27f73b8408e6bdc14027e4897579460416fc';
async function main() {
  const [checkoutArg, mode] = process.argv.slice(2);
  if (!checkoutArg || !['--dry-run', '--confirm'].includes(mode ?? '')) throw new Error('usage');
  const checkout = resolve(checkoutArg);
  const origin = process.env.OPENKEY_ADMIN_ORIGIN;
  const adminKey = process.env.ADMIN_API_KEY;
  if (!origin || !adminKey || new URL(origin).origin !== origin || !origin.startsWith('https://')) throw new Error('configuration');
  const env: Record<string, string> = {};
  for (const key of ['PATH', 'HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'BUN_INSTALL_CACHE_DIR']) {
    if (process.env[key]) env[key] = process.env[key]!;
  }
  const git = async (...args: string[]) => {
    const child = Bun.spawn(['git', '-C', checkout, ...args], { env, stdout: 'pipe', stderr: 'ignore' });
    const output = await new Response(child.stdout).text();
    if (await child.exited !== 0) throw new Error('checkout');
    return output.trim();
  };
  if (await git('rev-parse', 'HEAD') !== PIN || await git('status', '--porcelain')) throw new Error('checkout');
  const api = async (path: string, body?: unknown) => {
    const response = await fetch(origin + '/api/admin/review-accounts/apple/' + path, {
      method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(30_000),
      headers: { authorization: 'Bearer ' + adminKey, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) throw new Error('admin');
    return response.json();
  };
  const target = await api('seed-target') as { spaceId: string; ownerDid: string; nodeHost: string };
  const directory = await mkdtemp(join(tmpdir(), 'openkey-reviewer-seed-'));
  let child: ReturnType<typeof Bun.spawn> | undefined;
  try {
    const requestOut = join(directory, 'request.json');
    // Do not pass the parent's admin credentials or any other API keys to Home.
    env.HOME = join(directory, 'home');
    env.XDG_CONFIG_HOME = join(env.HOME, 'config');
    env.XDG_DATA_HOME = join(env.HOME, 'data');
    env.XDG_CACHE_HOME = join(env.HOME, 'cache');
    env.BUN_INSTALL_CACHE_DIR = join(env.HOME, 'bun-cache');
    await mkdir(env.HOME, { mode: 0o700 });
    child = Bun.spawn([process.execPath, '--no-env-file', 'frontend/scripts/reviewer-seed/cli.ts',
      '--space', target.spaceId, '--owner', target.ownerDid, '--allow-owner', target.ownerDid,
      '--host', target.nodeHost, '--request-out', requestOut, ...(mode === '--dry-run' ? ['--dry-run'] : ['--confirm', target.spaceId])],
    { cwd: checkout, env, stdin: 'pipe', stdout: 'pipe', stderr: 'ignore' });
    const output = new Response(child.stdout).text();
    let request: unknown;
    for (let attempt = 0; attempt < 500; attempt++) {
      try { request = JSON.parse(await readFile(requestOut, 'utf8')); break; }
      catch { if (child.exitCode !== null) throw new Error('seed'); await Bun.sleep(20); }
    }
    if (!request) throw new Error('seed');
    const grant = await api('seed-grant', { request, dryRun: mode === '--dry-run' });
    if (!child.stdin || typeof child.stdin === 'number') throw new Error('seed');
    child.stdin.write(JSON.stringify(grant));
    child.stdin.end();
    if (await child.exited !== 0) throw new Error('seed');
    const report = JSON.parse(await output);
    if (mode !== '--dry-run') {
      const summary = Object.fromEntries(['status', 'seed', 'revision', 'spaceId', 'ownerDid', 'seededAt', 'readBack'].map(key => [key, report[key]]));
      await api('seed-verify', { report: summary });
    }
    process.stdout.write(JSON.stringify({ status: mode === '--dry-run' ? 'planned' : 'verified', revision: 1 }) + '\n');
  } finally {
    if (child && child.exitCode === null) { child.kill(); await child.exited; }
    await rm(directory, { recursive: true, force: true });
  }
}
main().catch(() => { process.stderr.write('Reviewer seed did not complete. Check the admin status; do not retry an expired run without an explicit reset.\n'); process.exitCode = 1; });
