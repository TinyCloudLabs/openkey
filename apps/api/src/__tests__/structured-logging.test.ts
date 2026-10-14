import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { logger as betterAuthGlobalLogger } from '@better-auth/core/env';
import { apiErrorHandler, betterAuthLog, log, logError, requestLogger, withScheduledLogContext, type ApiEnv } from '../log';

const output: string[] = [];
const stdoutWrite = process.stdout.write;
const stderrWrite = process.stderr.write;

function assertAllowlistedJsonLines(): void {
  for (const raw of output) {
    const line = JSON.parse(raw);
    expect(Object.keys(line).every((key) => ['ts', 'level', 'event', 'method', 'route', 'status', 'ms', 'request_id', 'error_name', 'error_code'].includes(key))).toBe(true);
  }
}

beforeEach(() => {
  output.length = 0;
  process.stdout.write = ((chunk: string | Uint8Array) => { output.push(String(chunk)); return true; }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => { output.push(String(chunk)); return true; }) as typeof process.stderr.write;
});

afterEach(() => {
  process.stdout.write = stdoutWrite;
  process.stderr.write = stderrWrite;
});

describe('API structured logging', () => {
  test('logs API errors without serializing error content', async () => {
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
    const lines = output.map((line) => JSON.parse(line));
    const errorLine = lines.find((line) => line.event === 'api_error');

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: 'Internal server error' });
    expect(errorLine).toMatchObject({ event: 'api_error', error_name: 'Error', route: '/canary' });
    expect(Object.keys(errorLine).sort()).toEqual(['error_name', 'event', 'level', 'request_id', 'route', 'ts']);
    for (const canary of ['canary@example.test', 'did:pkh:eip155:1:0x1234567890123456789012345678901234567890', 'Bearer canary-token', 'Sign in to OpenKey with Ethereum account', 'property-canary']) {
      expect(output.join('\n')).not.toContain(canary);
    }
  });

  test('logs the registered route template and replaces untrusted request IDs', async () => {
    const app = new Hono<ApiEnv>();
    app.use('*', requestLogger);
    app.get('/api/keys/:id', (c) => c.json({ ok: true }));

    const canary = 'owner-address-canary-123456';
    const response = await app.request('/api/keys/key-secret', { headers: { 'X-Request-Id': canary } });
    const requestLine = output.map((line) => JSON.parse(line)).find((line) => line.event === 'request');

    expect(response.status).toBe(200);
    expect(response.headers.get('X-Request-Id')).toBe(requestLine.request_id);
    expect(requestLine.route).toBe('/api/keys/:id');
    expect(response.headers.get('X-Request-Id')).not.toBe(canary);
    expect(output.join('\n')).not.toContain('key-secret');
    expect(output.join('\n')).not.toContain(canary);
  });

  test('isolates concurrent request IDs and keeps IDs in post-response work', async () => {
    const app = new Hono<ApiEnv>();
    const { promise, resolve } = Promise.withResolvers<void>();
    app.use('*', requestLogger);
    app.get('/work/:name', (c) => {
      betterAuthLog('error', 'auth error message', new Error('auth canary'));
      void Promise.reject(new Error('analytics canary')).catch((error) => logError('error', 'analytics_token_tracking_failed', error));
      void promise.then(() => log('info', 'primary_key_changed'));
      return c.json({ ok: true });
    });

    await Promise.all([app.request('/work/first'), app.request('/work/second')]);
    resolve();
    await Promise.resolve();
    const lines = output.map((line) => JSON.parse(line));
    const requestIds = lines.filter((line) => line.event === 'request').map((line) => line.request_id);
    const requestScopedIds = lines.filter((line) => ['better_auth', 'analytics_token_tracking_failed', 'primary_key_changed'].includes(line.event)).map((line) => line.request_id);
    expect(new Set(requestIds).size).toBe(2);
    expect(requestScopedIds).toHaveLength(6);
    expect(requestScopedIds.every((id) => requestIds.includes(id))).toBe(true);
  });

  test('uses <unmatched> for requests without a matching route', async () => {
    const app = new Hono<ApiEnv>();
    app.use('*', requestLogger);
    await app.request('/not-registered');
    const requestLine = output.map((line) => JSON.parse(line)).find((line) => line.event === 'request');
    expect(requestLine.route).toBe('<unmatched>');
  });

  test('drops malicious direct logger fields and error codes', () => {
    const canary = 'CanaryTokenValue owner-address-canary@example.test SELECT_SECRET';
    log('info', 'request', {
      route: { toJSON: () => canary },
      status: { token: canary },
      request_id: { email: canary },
      error_name: 'name=CanaryTokenValue',
      error_code: '203.0.113.42',
    } as never);
    expect(output.join('\n')).not.toContain(canary);
    const line = JSON.parse(output[0]!);
    expect(line).not.toHaveProperty('route');
    expect(line).not.toHaveProperty('error_code');
  });


  test('maps arbitrary error names and codes to safe values', () => {
    const error = Object.assign(new Error('name-canary'), { code: '203.0.113.42', name: 'name=CanaryTokenValue' });
    logError('error', 'api_error', error);
    const line = JSON.parse(output[0]!);
    expect(line).toMatchObject({ event: 'api_error', error_name: 'Error', request_id: 'startup' });
    expect(line).not.toHaveProperty('error_code');
    expect(output.join('\n')).not.toContain('CanaryTokenValue');
    expect(output.join('\n')).not.toContain('203.0.113.42');
  });

  test('labels startup and scheduled logs distinctly', () => {
    log('info', 'api_starting');
    withScheduledLogContext(() => log('info', 'native_par_valid_request_volume_threshold_reached'));
    expect(output.map((line) => JSON.parse(line).request_id)).toEqual(['startup', 'scheduled']);
  });
  test('logs uncaught exceptions and unhandled rejections through the safe classifier', async () => {
    const loggerModule = new URL('../log.ts', import.meta.url).href;
    const child = Bun.spawn([process.execPath, '-e', `
      const logger = await import(${JSON.stringify(loggerModule)});
      logger.handleUncaughtException(new Error('uncaught canary@example.test Bearer SecretToken'));
      logger.handleUnhandledRejection(new Error('rejection canary@example.test Bearer SecretToken'));
    `], { cwd: import.meta.dir, stdout: 'pipe', stderr: 'pipe' });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    const lines = `${stdout}${stderr}`.split('\n').filter(Boolean).map((line) => JSON.parse(line));
    expect(exitCode).toBe(1);
    expect(lines.map((line) => line.event)).toEqual(['uncaught_exception', 'unhandled_rejection']);
    expect(lines.every((line) => line.error_name === 'Error')).toBe(true);
    expect(`${stdout}${stderr}`).not.toContain('canary@example.test');
    expect(`${stdout}${stderr}`).not.toContain('SecretToken');
  });
  test('routes console and Better Auth global logger output through the allowlist', () => {
    const canary = 'otp-canary@example.test Bearer SecretToken123';
    const consoleMethods = globalThis.console as unknown as Record<string, (...args: unknown[]) => void>;
    for (const method of ['log', 'info', 'warn', 'error', 'debug', 'trace']) consoleMethods[method]!(canary);
    consoleMethods.dir!({ email: canary, toJSON: () => canary });
    consoleMethods.table!([{ ticket: canary }]);
    betterAuthGlobalLogger.error(`oauth-provider error ${canary}`, new Error(canary));
    betterAuthLog('error', `auth callback ${canary}`, new Error(canary));

    expect(output.length).toBeGreaterThanOrEqual(4);
    assertAllowlistedJsonLines();
    expect(output.join('\n')).not.toContain(canary);
  });

  test('captures real Prisma validation and database errors at the process sinks', async () => {
    const email = 'prisma-canary@example.test';
    const ticket = 'signed-kv-ticket-canary';
    const loggerModule = new URL('../log.ts', import.meta.url).href;
    // A child process bypasses Bun's per-file mock.module registry and captures its real stdout/stderr.
    const script = `
      await import(${JSON.stringify(loggerModule)});
      const { createPrismaClient } = await import('@openkey/db');
      const prisma = createPrismaClient({ connectionString: 'pglite:memory://structured-logging-test', log: ['error', 'warn'] });
      let unexpectedSuccesses = 0;
      const expectFailure = async (operation) => {
        try { await operation; unexpectedSuccesses++; } catch {}
      };
      try {
        await expectFailure(prisma.user.create({ data: { email: ${JSON.stringify(email)}, signedKvTicket: ${JSON.stringify(ticket)} } }));
        await expectFailure(prisma.$queryRawUnsafe("SELECT '${email}' FROM intentionally_missing_table"));
      } finally {
        await prisma.$disconnect();
      }
      if (unexpectedSuccesses) process.exitCode = 2;
    `;
    const child = Bun.spawn([process.execPath, '-e', script], {
      cwd: import.meta.dir,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    const lines = `${stdout}${stderr}`.split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const raw of lines) {
      const line = JSON.parse(raw);
      expect(Object.keys(line).every((key) => ['ts', 'level', 'event', 'method', 'route', 'status', 'ms', 'request_id', 'error_name', 'error_code'].includes(key))).toBe(true);
    }
    expect(`${stdout}${stderr}`).not.toContain(email);
    expect(`${stdout}${stderr}`).not.toContain(ticket);
  });
});
