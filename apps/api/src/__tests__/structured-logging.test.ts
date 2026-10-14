import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { apiErrorHandler, requestLogger, type ApiEnv } from '../log';

const originalLog = globalThis['console']['log'];
afterEach(() => {
  globalThis['console']['log'] = originalLog;
});

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : entry.isFile() ? [path] : [];
  });
}

describe('API structured logging', () => {
  test('logs API errors without serializing error content', async () => {
    const output: string[] = [];
    globalThis['console']['log'] = (...args: unknown[]) => output.push(args.join(' '));
    const app = new Hono<ApiEnv>();
    app.use('*', requestLogger);
    app.get('/canary', () => {
      const error = new Error('canary@example.test did:pkh:eip155:1:0x1234567890123456789012345678901234567890 Bearer canary-token Sign in to OpenKey with Ethereum account 0x1234567890123456789012345678901234567890');
      error.cause = 'cause-canary@example.test';
      Object.assign(error, { token: 'property-canary', wallet: '0x1234567890123456789012345678901234567890' });
      throw error;
    });
    app.onError(apiErrorHandler);

    const response = await app.request('/canary');
    const errorLine = output.map((line) => JSON.parse(line)).find((line) => line.event === 'api_error');

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: 'Internal server error' });
    expect(errorLine).toMatchObject({ event: 'api_error', error_name: 'Error', route: '/canary' });
    expect(Object.keys(errorLine).sort()).toEqual(['error_name', 'event', 'level', 'request_id', 'route', 'ts']);
    for (const canary of ['canary@example.test', 'did:pkh:eip155:1:0x1234567890123456789012345678901234567890', 'Bearer canary-token', 'Sign in to OpenKey with Ethereum account', 'property-canary']) {
      expect(output.join('\n')).not.toContain(canary);
    }
  });

  test('logs the registered route template rather than the requested path', async () => {
    const output: string[] = [];
    globalThis['console']['log'] = (...args: unknown[]) => output.push(args.join(' '));
    const app = new Hono();
    app.use('*', requestLogger);
    app.get('/api/keys/:id', (c) => c.json({ ok: true }));

    const response = await app.request('/api/keys/key-secret');
    const requestLine = output.map((line) => JSON.parse(line)).find((line) => line.event === 'request');

    expect(response.status).toBe(200);
    expect(response.headers.get('X-Request-Id')).toBe(requestLine.request_id);
    expect(Object.keys(requestLine).sort()).toEqual(['event', 'level', 'method', 'ms', 'request_id', 'route', 'status', 'ts']);
    expect(requestLine.route).toBe('/api/keys/:id');
    expect(output.join('\n')).not.toContain('key-secret');
  });

  test('contains no direct console calls in API source outside the logger', () => {
    const src = join(import.meta.dir, '..');
    const consoleCall = /console\s*\.\s*(log|info|warn|error|debug)\s*\(/;
    const remaining = sourceFiles(src)
      .filter((path) => !path.startsWith(join(src, '__tests__')))
      .filter((path) => path !== join(src, 'log.ts'))
      .filter((path) => consoleCall.test(readFileSync(path, 'utf8')));

    expect(remaining).toEqual([]);
  });
});
