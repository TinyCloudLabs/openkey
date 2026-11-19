// The browser specs name their dev-server port in one place, tests/browser/e2e-port.ts (TC-2124):
// the default is 5779 (what CI uses), OPENKEY_E2E_PORT changes it, and no other file under the
// web app's tests or sources spells the port out.

// @ts-expect-error bun:test is supplied by the web test runner
import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const portFile = join(webRoot, 'tests/browser/e2e-port.ts');
const configFile = join(webRoot, 'tests/browser/playwright.config.ts');

function files(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    if (name === 'node_modules' || name === '.svelte-kit' || name === 'test-results' || name === 'build') return [];
    const path = join(directory, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
}

/** Evaluates `expression` over the module's exports in a fresh process, with OPENKEY_E2E_PORT as given. */
function inFreshProcess(module: string, expression: string, port: string | undefined) {
  const env: Record<string, string> = Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined));
  delete env.OPENKEY_E2E_PORT;
  if (port !== undefined) env.OPENKEY_E2E_PORT = port;
  const result = spawnSync(process.execPath, ['-e', `const m = await import(${JSON.stringify(module)}); console.log(JSON.stringify(${expression}));`], { env, encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout.trim(), stderr: result.stderr };
}

describe('the browser specs\' dev-server port', () => {
  test('no file under the web app\'s tests or sources spells out 5779 except e2e-port.ts', () => {
    const offenders = [...files(join(webRoot, 'tests')), ...files(join(webRoot, 'src'))]
      .filter((path) => path !== portFile && path !== join(webRoot, 'src/lib/e2e-port.test.ts'))
      .filter((path) => readFileSync(path, 'utf8').includes('5779'))
      .map((path) => relative(webRoot, path));
    expect(offenders).toEqual([]);
  });

  test('the default is 5779: host, origin and loopback origin follow it', () => {
    const result = inFreshProcess(portFile, 'm', undefined);
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      DEFAULT_E2E_PORT: 5779,
      E2E_PORT: 5779,
      HOST: 'localhost:5779',
      ORIGIN: 'http://localhost:5779',
      LOOPBACK_ORIGIN: 'http://127.0.0.1:5779',
    });
  });

  test('OPENKEY_E2E_PORT changes every derived value, and an empty value is the default', () => {
    const changed = inFreshProcess(portFile, '[m.E2E_PORT, m.HOST, m.ORIGIN, m.LOOPBACK_ORIGIN]', '5791');
    expect(changed.status, changed.stderr).toBe(0);
    expect(JSON.parse(changed.stdout)).toEqual([5791, 'localhost:5791', 'http://localhost:5791', 'http://127.0.0.1:5791']);
    expect(JSON.parse(inFreshProcess(portFile, 'm.E2E_PORT', '').stdout)).toBe(5779);
  });

  test.each(['abc', '80', '70000', '5791.5', '-1'])('a value that is not a port from 1024 to 65535 (%s) is refused', (value: string) => {
    const result = inFreshProcess(portFile, 'm.E2E_PORT', value);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain('OPENKEY_E2E_PORT must be an integer from 1024 to 65535');
  });

  test('the Playwright config starts the dev server on that port and points its baseURL there', () => {
    const at = (port: string | undefined) => JSON.parse(inFreshProcess(configFile, '{ baseURL: m.default.use.baseURL, command: m.default.webServer.command, url: m.default.webServer.url }', port).stdout);
    expect(at(undefined)).toEqual({ baseURL: 'http://localhost:5779', command: 'vite dev --port 5779 --strictPort', url: 'http://localhost:5779/__parity_harness' });
    expect(at('5791')).toEqual({ baseURL: 'http://localhost:5791', command: 'vite dev --port 5791 --strictPort', url: 'http://localhost:5791/__parity_harness' });
  });
});
