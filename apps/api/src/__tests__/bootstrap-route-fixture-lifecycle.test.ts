import { expect, test } from 'bun:test';

// These route fixtures test signing and delegation contracts, not bootstrap.
// Run them in their own process so the guard sees their timers after teardown,
// before the rest of the API suite can incidentally consume a leaked retry.
// The process starts in this directory, not the repository root, so it does not load bunfig.toml's
// preload: that ends every test's background work and would hide a fixture's own leak (TC-2969).
test('delegation route fixtures leave no bootstrap timers after teardown', async () => {
  const fixtures = [
    'delegate-managed-approval-routes',
    'delegate-primary-flag-routes',
    'delegate-raw-encryption-routes',
    'delegate-device-window-routes',
    'delegate-wallet-session-proof',
    'delegate-device-default-decrypt-routes',
  ].map((name) => `${import.meta.dir}/${name}.test.ts`);
  const child = Bun.spawn([
    process.execPath, 'test', '--preload', `${import.meta.dir}/fixtures/bootstrap-retry-guard.mjs`, ...fixtures,
  ], {
    cwd: import.meta.dir,
    env: { ...process.env, TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: '5000,15000,45000' },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  expect(exitCode, stdout + stderr).toBe(0);
}, 30_000);
