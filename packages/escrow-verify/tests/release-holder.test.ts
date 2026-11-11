import { test, expect } from 'bun:test';

test('holder devices verify both attestations and rewrap directly to an enclave session', async () => {
  const child = Bun.spawn([process.execPath, new URL('./fixtures/release-holder.ts', import.meta.url).pathname], { stdout: 'pipe', stderr: 'pipe' });
  const stderr = await new Response(child.stderr).text();
  expect(await child.exited, stderr).toBe(0);
});
