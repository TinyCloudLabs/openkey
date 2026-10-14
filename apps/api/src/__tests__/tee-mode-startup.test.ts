// TC-966: a deployed API must refuse to start unless TEE_MODE=production,
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

async function startApi(
  nodeEnv: string,
  teeMode: string | undefined,
  betterAuthUrl = 'http://localhost:3001',
): Promise<{ exitCode: number | null; output: string }> {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    HOME: process.env.HOME ?? '',
    NODE_ENV: nodeEnv,
    // Unreachable placeholders: startup must stop before anything connects.
    DATABASE_URL: 'postgresql://openkey@127.0.0.1:1/openkey',
    BETTER_AUTH_SECRET: 'tee-mode-startup-test-secret-not-a-real-secret',
    BETTER_AUTH_URL: betterAuthUrl,
    API_PORT: '0',
  };
  if (teeMode !== undefined) env.TEE_MODE = teeMode;
  // `timeout` is only a backstop for a hung child; a healthy start is stopped
  // as soon as it logs the structured startup event.
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
      if (text.includes('"event":"api_starting"')) child.kill();
    }
    return text;
  };
  const [stdout, stderr] = await Promise.all([readStdout(), new Response(child.stderr).text(), child.exited]);
  return { exitCode: child.exitCode, output: stdout + stderr };
}

describe('API startup in a deployment (TC-966)', () => {
  const cases: Array<[string, string | undefined]> = [
    ['production', undefined],
    ['production', ''],
    ['production', 'prod'],
    ['production', 'Production'],
    ['production', 'development'],
    ['staging', 'development'],
    ['staging', undefined],
  ];
  for (const [nodeEnv, teeMode] of cases) {
    test(`NODE_ENV=${nodeEnv} TEE_MODE=${JSON.stringify(teeMode)} stops startup`, async () => {
      const { exitCode, output } = await startApi(nodeEnv, teeMode);
      expect(exitCode).not.toBe(0);
      const lines = output.split('\n').filter(Boolean).map((line) => JSON.parse(line));
      const startupError = lines.find((line) => line.event === 'uncaught_exception');
      expect(startupError).toMatchObject({ request_id: 'startup', error_name: 'Error' });
      expect(Object.keys(startupError).sort()).toEqual(['error_name', 'event', 'level', 'request_id', 'ts']);
      expect(output).not.toContain('OpenKey API starting');
    }, 30_000);
  }

  test('NODE_ENV=production TEE_MODE=production gets past the TEE check', async () => {
    const { output } = await startApi('production', 'production');
    expect(output).toContain('"event":"api_starting"');
    expect(output).not.toContain('refusing to fall back to mock sealing keys');
  }, 30_000);
  test('reports the invalid startup config key without its value', async () => {
    const invalidValue = 'not-a-url-canary';
    const { exitCode, output } = await startApi('production', 'production', invalidValue);
    const lines = output.split('\n').filter(Boolean).map((line) => JSON.parse(line));
    expect(exitCode).not.toBe(0);
    expect(lines.find((line) => line.event === 'config_invalid')).toMatchObject({
      event: 'config_invalid',
      error_code: 'BETTER_AUTH_URL',
      request_id: 'startup',
    });
    expect(output).not.toContain(invalidValue);
  }, 30_000);
});
