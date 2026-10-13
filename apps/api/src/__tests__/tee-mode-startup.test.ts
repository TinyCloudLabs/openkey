// TC-966: the production API must refuse to start unless TEE_MODE=production,
// instead of silently sealing keys with the mock TEE client.
//
// Spawns the real entry point (apps/api/src/index.ts) with a clean environment.
// It loads @openkey/tee from its built dist, as the image does, so build it
// first: `bun run build --filter @openkey/tee`.
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ENTRY = join(import.meta.dir, '..', 'index.ts');
// An empty cwd, so Bun loads no .env file into the child.
const cwd = mkdtempSync(join(tmpdir(), 'openkey-tee-mode-'));
afterAll(() => rmSync(cwd, { recursive: true, force: true }));

async function startApi(teeMode: string | undefined): Promise<{ exitCode: number | null; output: string }> {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    HOME: process.env.HOME ?? '',
    NODE_ENV: 'production',
    // Unreachable placeholders: startup must stop before anything connects.
    DATABASE_URL: 'postgresql://openkey@127.0.0.1:1/openkey',
    BETTER_AUTH_SECRET: 'tee-mode-startup-test-secret-not-a-real-secret',
    API_PORT: '0',
  };
  if (teeMode !== undefined) env.TEE_MODE = teeMode;
  // `timeout` is only a backstop for a hung child; a healthy start is stopped
  // as soon as it logs past the TEE check.
  const child = Bun.spawn([process.execPath, 'run', ENTRY], {
    cwd,
    env,
    stdout: 'pipe',
    stderr: 'pipe',
    timeout: 20_000,
  });
  const readStdout = async () => {
    let text = '';
    const decoder = new TextDecoder();
    for await (const chunk of child.stdout) {
      text += decoder.decode(chunk, { stream: true });
      if (text.includes('TEE Mode:')) child.kill();
    }
    return text;
  };
  const [stdout, stderr] = await Promise.all([readStdout(), new Response(child.stderr).text(), child.exited]);
  return { exitCode: child.exitCode, output: stdout + stderr };
}

describe('API startup with NODE_ENV=production (TC-966)', () => {
  for (const teeMode of [undefined, '', 'prod', 'Production', 'development']) {
    test(`TEE_MODE=${JSON.stringify(teeMode)} stops startup`, async () => {
      const { exitCode, output } = await startApi(teeMode);
      expect(exitCode).not.toBe(0);
      expect(output).toMatch(/TEE_MODE must be "production" or "development"|TEE_MODE=development is not allowed/);
      expect(output).not.toContain('OpenKey API starting');
    }, 30_000);
  }

  test('TEE_MODE=production gets past the TEE check', async () => {
    const { output } = await startApi('production');
    expect(output).toContain('TEE Mode: production');
    expect(output).not.toContain('refusing to fall back to mock sealing keys');
  }, 30_000);
});
