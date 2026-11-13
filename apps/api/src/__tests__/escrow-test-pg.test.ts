import { expect, test } from 'bun:test';

test('PG test configuration has no missing-env, URL or TCP fallback', async () => {
  const script = `import { escrowTestPostgres } from ${JSON.stringify(new URL('./escrow-test-pg.ts', import.meta.url).pathname)};
process.env.OPENKEY_ESCROW_TEST_PG = '1';
for (const host of [undefined, 'postgresql://production/db', '127.0.0.1', 'relative/socket']) {
  if(host === undefined) delete process.env.OPENKEY_ESCROW_TEST_SOCKET; else process.env.OPENKEY_ESCROW_TEST_SOCKET = host;
  try { escrowTestPostgres(); process.exit(2); } catch {}
}`;
  const child = Bun.spawn([process.execPath, '-e', script], { env: {}, stdout: 'pipe', stderr: 'pipe' });
  expect(await child.exited, await new Response(child.stderr).text()).toBe(0);
});
