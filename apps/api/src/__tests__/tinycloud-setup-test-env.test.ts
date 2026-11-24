import { expect, test } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// The setup route tests import the route tree, which imports the database package. With no
// DATABASE_URL that package opens ~/.local/share/openkey/dev.pglite, and the open fails with
// ENOENT when the home directory has no .local/share. The failure is an unhandled rejection
// that lands on whichever test runs at that moment (CI runners start with an empty home).
test('the setup route tests pass when the home directory is empty', async () => {
  const home = await mkdtemp(join(tmpdir(), 'openkey-empty-home-'));
  try {
    const { DATABASE_URL: _databaseUrl, ...inherited } = process.env;
    const child = Bun.spawn(
      [process.execPath, 'test', join(import.meta.dir, '../routes/tinycloud-setup-routes.test.ts')],
      {
        cwd: resolve(import.meta.dir, '../../../..'),
        env: { ...inherited, HOME: home },
        stdout: 'pipe',
        stderr: 'pipe',
      },
    );
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    const output = stdout + stderr;
    expect(output).not.toContain('ENOENT');
    expect(output).toMatch(/\b[1-9]\d* pass\b/);
    expect(code, output).toBe(0);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}, 30_000);
