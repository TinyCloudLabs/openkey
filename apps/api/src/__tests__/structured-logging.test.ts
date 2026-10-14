import { createServer } from 'node:net';
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { apiErrorHandler, betterAuthLog, log, logConfigInvalid, logError, requestLogger, withScheduledLogContext, type ApiEnv } from '../log';

const output: string[] = [];
const stdoutWrite = process.stdout.write;
const stderrWrite = process.stderr.write;

async function unusedPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('Could not allocate a test port'));
        return;
      }
      server.close((error) => error ? reject(error) : resolve(address.port));
    });
  });
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

  test('keeps post-response work associated with its originating concurrent request', async () => {
    const app = new Hono<ApiEnv>();
    const { promise, resolve } = Promise.withResolvers<void>();
    app.use('*', requestLogger);
    app.get('/work/:name', (c) => {
      const name = c.req.param('name');
      betterAuthLog('error', 'auth error message', new Error('auth canary'));
      void Promise.reject(new Error('analytics canary')).catch((error) => logError('error', 'analytics_token_tracking_failed', error));
      const event = name === 'first' ? 'primary_key_changed' : 'tinycloud_bootstrap_background_completed';
      void promise.then(() => log('info', event));
      return c.json({ requestId: c.get('requestId') });
    });

    const [firstResponse, secondResponse] = await Promise.all([app.request('/work/first'), app.request('/work/second')]);
    const first = await firstResponse.json();
    const second = await secondResponse.json();
    resolve();
    await Promise.resolve();
    const lines = output.map((line) => JSON.parse(line));
    const firstBackground = lines.find((line) => line.event === 'primary_key_changed');
    const secondBackground = lines.find((line) => line.event === 'tinycloud_bootstrap_background_completed');
    expect(firstBackground.request_id).toBe(first.requestId);
    expect(secondBackground.request_id).toBe(second.requestId);
    expect(firstBackground.request_id).not.toBe(secondBackground.request_id);
    const immediate = lines.filter((line) => ['better_auth', 'analytics_token_tracking_failed'].includes(line.event));
    expect(immediate).toHaveLength(4);
    expect(immediate.every((line) => [first.requestId, second.requestId].includes(line.request_id))).toBe(true);
  });

  test('logs only known invalid configuration keys without values', () => {
    logConfigInvalid('BETTER_AUTH_URL');
    logConfigInvalid('canary-url-value');
    const line = JSON.parse(output[0]!);
    expect(output).toHaveLength(1);
    expect(line).toMatchObject({ event: 'config_invalid', error_code: 'BETTER_AUTH_URL', request_id: 'startup' });
    expect(output.join('\n')).not.toContain('canary-url-value');
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
  test('fatal exceptions and rejections terminate a child server after safe logging', async () => {
    const loggerModule = new URL('../log.ts', import.meta.url).href;
    for (const kind of ['uncaught', 'rejection']) {
      const port = await unusedPort();
      const child = Bun.spawn([process.execPath, '-e', `
        const logger = await import(${JSON.stringify(loggerModule)});
        logger.installFatalHandlers();
        const kind = ${JSON.stringify(kind)};
        Bun.serve({
          hostname: '127.0.0.1',
          port: ${port},
          fetch(request) {
            if (new URL(request.url).pathname === '/fatal') {
              setTimeout(() => {
                if (kind === 'uncaught') throw new Error('fatal canary@example.test Bearer SecretToken');
                void Promise.reject(new Error('fatal canary@example.test Bearer SecretToken'));
              }, 20);
              return new Response('armed');
            }
            return new Response('alive');
          },
        });
      `], { cwd: import.meta.dir, stdout: 'pipe', stderr: 'pipe' });
      const url = `http://127.0.0.1:${port}`;
      let ready = false;
      for (let attempt = 0; attempt < 50 && !ready; attempt++) {
        try {
          ready = (await fetch(`${url}/health`)).status === 200;
        } catch {
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      }
      expect(ready).toBe(true);
      expect(await (await fetch(`${url}/fatal`)).text()).toBe('armed');
      let timeout: NodeJS.Timeout;
      const exitCode = await Promise.race([
        child.exited,
        new Promise<null>((resolve) => { timeout = setTimeout(() => { child.kill(); resolve(null); }, 3_000); }),
      ]);
      clearTimeout(timeout!);
      const [stdout, stderr] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text()]);
      expect(exitCode).toBe(1);
      await expect(fetch(`${url}/health`, { signal: AbortSignal.timeout(200) })).rejects.toThrow();
      const lines = `${stdout}${stderr}`.split('\n').filter(Boolean).map((line) => JSON.parse(line));
      expect(lines.map((line) => line.event)).toEqual([kind === 'uncaught' ? 'uncaught_exception' : 'unhandled_rejection']);
      expect(lines.map((line) => line.error_name)).toEqual(['Error']);
      expect(lines.every((line) => Object.keys(line).every((key) => ['ts', 'level', 'event', 'method', 'route', 'status', 'ms', 'request_id', 'error_name', 'error_code'].includes(key)))).toBe(true);
      expect(`${stdout}${stderr}`).not.toContain('canary@example.test');
      expect(`${stdout}${stderr}`).not.toContain('SecretToken');
    }
  });

  test('routes every console output method and Better Auth logging through the real safe sinks', async () => {
    const canary = 'otp-canary@example.test Bearer SecretToken123';
    const loggerModule = new URL('../log.ts', import.meta.url).href;
    const script = `
      await import(${JSON.stringify(loggerModule)});
      const { logger } = await import('@better-auth/core/env');
      const methods = ['assert', 'count', 'countReset', 'time', 'timeLog', 'timeEnd', 'group', 'groupCollapsed', 'groupEnd', 'dirxml', 'table', 'log', 'info', 'warn', 'error', 'debug', 'trace', 'dir'];
      for (const method of methods) {
        if (typeof console[method] !== 'function') throw new Error('missing console method');
        if (method === 'assert') console[method](false, ${JSON.stringify(canary)});
        else if (method === 'dirxml') console[method]({ email: ${JSON.stringify(canary)} });
        else console[method](${JSON.stringify(canary)});
      }
      logger.error('Better Auth raw message ${canary}', new Error(${JSON.stringify(canary)}));
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
    const lines = `${stdout}${stderr}`.split('\n').filter(Boolean).map((raw) => JSON.parse(raw));
    expect(exitCode).toBe(0);
    expect(lines.length).toBe(19);
    expect(lines.every((line) => Object.keys(line).every((key) => ['ts', 'level', 'event', 'method', 'route', 'status', 'ms', 'request_id', 'error_name', 'error_code'].includes(key)))).toBe(true);
    expect(lines.every((line) => line.event === 'third_party_console' || line.event === 'better_auth')).toBe(true);
    expect(`${stdout}${stderr}`).not.toContain(canary);
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
    expect(exitCode).toBe(0);
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
