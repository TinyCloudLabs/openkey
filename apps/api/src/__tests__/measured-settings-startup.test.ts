// TC-3840: in the TEE, the API refuses to start when a measured setting differs from the compose it was
// measured with, and the refusal names the setting without printing either value.
//
// Spawns the real entry point with TEE_MODE=production against a stand-in dstack guest agent
// (DSTACK_SIMULATOR_ENDPOINT) that reports the repo's docker-compose.prod.yml as the measured app-compose.
// It loads @openkey/tee from its built dist, as the image does: `bun run build --filter @openkey/tee`.
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ENTRY = join(import.meta.dir, '..', 'index.ts');
const prodCompose = readFileSync(resolve(import.meta.dir, '../../../../docker-compose.prod.yml'), 'utf8');
// An empty cwd, so Bun loads no .env file into the child.
const cwd = mkdtempSync(join(tmpdir(), 'openkey-measured-settings-'));

let measuredCompose = prodCompose;
const guestAgent = Bun.serve({
  port: 0,
  fetch: () => Response.json({
    app_id: '00', instance_id: '00', app_cert: '', device_id: '', app_name: 'openkey',
    tcb_info: JSON.stringify({ app_compose: JSON.stringify({ docker_compose_file: measuredCompose }) }),
  }),
});
afterAll(() => {
  guestAgent.stop(true);
  rmSync(cwd, { recursive: true, force: true });
});

function literalEnv(dockerCompose: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const line of dockerCompose.split('\n')) {
    const match = /^ {6}- ([A-Z0-9_]+)=([^$\n]*)$/.exec(line);
    if (match) env[match[1]!] = match[2]!;
  }
  return env;
}

/** Starts the API; a run that passes the check is stopped once it logs `measured_settings_verified`. */
async function startApi(overrides: Record<string, string>) {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    HOME: process.env.HOME ?? '',
    ...literalEnv(prodCompose),
    // Unreachable placeholders: nothing here may connect.
    DATABASE_URL: 'postgresql://openkey@127.0.0.1:1/openkey',
    BETTER_AUTH_SECRET: 'measured-settings-test-secret-not-a-real-secret',
    API_PORT: '0',
    DSTACK_SIMULATOR_ENDPOINT: `http://127.0.0.1:${guestAgent.port}`,
    ...overrides,
  };
  const child = Bun.spawn([process.execPath, 'run', ENTRY], { cwd, env, stdout: 'pipe', stderr: 'pipe', timeout: 20_000 });
  const readStdout = async () => {
    let text = '';
    const decoder = new TextDecoder();
    for await (const chunk of child.stdout) {
      text += decoder.decode(chunk, { stream: true });
      if (text.includes('"event":"measured_settings_verified"')) child.kill();
    }
    return text;
  };
  const [stdout, stderr] = await Promise.all([readStdout(), new Response(child.stderr).text(), child.exited]);
  return { exitCode: child.exitCode, output: stdout + stderr };
}

function configInvalidCodes(output: string): string[] {
  return output.split('\n').flatMap((line) => {
    try {
      const event: unknown = JSON.parse(line);
      if (typeof event !== 'object' || event === null || !('event' in event) || event.event !== 'config_invalid') return [];
      return 'error_code' in event && typeof event.error_code === 'string' ? [event.error_code] : [];
    } catch {
      return [];
    }
  });
}

describe('API startup against the measured compose (TC-3840)', () => {
  test('a process whose settings match the measured compose starts', async () => {
    measuredCompose = prodCompose;
    const { output } = await startApi({});
    expect(output).toContain('"event":"measured_settings_verified"');
    expect(configInvalidCodes(output)).toEqual([]);
  }, 30_000);

  test('a differing setting stops startup, named without either value', async () => {
    measuredCompose = prodCompose;
    const injected = 'injected-client-id.apps.googleusercontent.com';
    const { exitCode, output } = await startApi({ GOOGLE_CLIENT_ID: injected });
    expect(exitCode).toBe(1);
    expect(configInvalidCodes(output)).toEqual(['GOOGLE_CLIENT_ID']);
    expect(output).not.toContain(injected);
    expect(output).not.toContain(literalEnv(prodCompose).GOOGLE_CLIENT_ID!);
  }, 30_000);

  test('a setting the measured compose takes from the env stops startup', async () => {
    measuredCompose = prodCompose.replace('- BETTER_AUTH_URL=https://api.openkey.so', '- BETTER_AUTH_URL=${BETTER_AUTH_URL}');
    const { exitCode, output } = await startApi({});
    expect(exitCode).toBe(1);
    expect(configInvalidCodes(output)).toEqual(['BETTER_AUTH_URL']);
  }, 30_000);

  test('an unreadable measured compose stops startup', async () => {
    measuredCompose = 'services: [';
    const { exitCode, output } = await startApi({});
    expect(exitCode).toBe(1);
    expect(configInvalidCodes(output)).toEqual(['measured_app_compose']);
  }, 30_000);
});
