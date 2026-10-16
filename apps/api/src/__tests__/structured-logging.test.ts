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

  const uuid = 'a3b54a8d-9927-4c01-9a2e-5f4ec31e90b2';
  for (const incoming of [uuid, uuid.toUpperCase()]) {
    test(`accepts and canonicalizes UUID request ID ${incoming}`, async () => {
      const app = new Hono<ApiEnv>();
      app.use('*', requestLogger);
      app.get('/accepted', (c) => c.json({ requestId: c.get('requestId') }));
      const response = await app.request('/accepted', { headers: { 'X-Request-Id': incoming } });
      const expected = incoming.toLowerCase();
      expect(response.headers.get('X-Request-Id')).toBe(expected);
      expect(await response.json()).toEqual({ requestId: expected });
      expect(output.map((line) => JSON.parse(line))).toEqual([
        expect.objectContaining({ event: 'request', request_id: expected, route: '/accepted', status: 200 }),
      ]);
    });
  }

  for (const incoming of [
    undefined, '', 'owner-canary@example.test', 'Bearer token-canary', uuid.replaceAll('-', ''),
    `{${uuid}}`, `urn:uuid:${uuid}`, `${uuid}, ${uuid}`, `${uuid}suffix`, `${uuid.slice(0, 8)} ${uuid.slice(9)}`,
    '00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    'a3b54a8d-9927-0c01-9a2e-5f4ec31e90b2', 'a3b54a8d-9927-4c01-7a2e-5f4ec31e90b2',
    'a3b54a8d-9927-7c01-9a2e-5f4ec31e90b2',
  ]) {
    test(`mints a UUID for absent or malformed ID ${JSON.stringify(incoming)}`, async () => {
      const app = new Hono<ApiEnv>();
      app.use('*', requestLogger);
      app.get('/rejected', (c) => c.json({ requestId: c.get('requestId') }));
      const headers: Record<string, string> = incoming === undefined ? {} : { 'X-Request-Id': incoming };
      const response = await app.request('/rejected', { headers });
      const minted = response.headers.get('X-Request-Id');
      expect(minted).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      expect(minted).not.toBe(incoming);
      expect(await response.json()).toEqual({ requestId: minted });
      expect(JSON.parse(output[0]!).request_id).toBe(minted);
      if (incoming) expect(output.join('\n')).not.toContain(incoming);
    });
  }

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
  test('replaces an unknown runtime event with the fixed fallback', () => {
    const unlistedEvent = 'private-canary-event';
    log('info', unlistedEvent as never);
    const line = JSON.parse(output[0]!);
    expect(line.event).toBe('unlisted_event');
    expect(output.join('\n')).not.toContain(unlistedEvent);
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
  test('keeps real HTTP completion logs and process sinks correlated without raw authority or PII', async () => {
    const child = Bun.spawn([
      process.execPath, 'test', './delegate-complete-context-routes.test.ts', '-t', 'TC-959 correlates',
    ], { cwd: import.meta.dir, stdout: 'pipe', stderr: 'pipe' });
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
    ]);
    expect(exitCode).toBe(0);
    const lines = stdout.split('\n').filter((line) => line.startsWith('{')).map((line) => JSON.parse(line));
    const requests = lines.filter((line) => line.event === 'request');
    expect(requests.map((line) => line.status).sort()).toEqual([200, 200, 200, 200, 500]);
    expect(requests.every((line) => line.route === '/api/delegate/complete')).toBe(true);
    for (const requestId of [
      uuid, '64e09578-4ca5-4d12-b172-2ef8762d04cb', '34db1e5b-6a32-4f70-9611-fc1e1f737975',
    ]) expect(requests.filter((line) => line.request_id === requestId)).toHaveLength(1);
    expect(lines.find((line) => line.event === 'api_error')).toMatchObject({
      request_id: '34db1e5b-6a32-4f70-9611-fc1e1f737975', error_name: 'SyntaxError',
    });
    for (const canary of [
      'owner-canary@example.test', 'token-canary', 'alice@example.test', 'did:pkh:',
      '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      'authorizationContextToken', 'Authorization', 'JSON Parse error',
    ]) expect(`${stdout}${stderr}`).not.toContain(canary);
  });

  test('propagates only to node origins and preserves outbound Request and init semantics', async () => {
    const received: Array<{ id: string | null; authorization: string | null; body: string; path: string }> = [];
    const node = Bun.serve({
      hostname: '127.0.0.1', port: 0,
      async fetch(request) {
        received.push({
          id: request.headers.get('X-Request-Id'), authorization: request.headers.get('Authorization'),
          body: await request.text(), path: new URL(request.url).pathname,
        });
        return new Response('ok');
      },
    });
    const other = Bun.serve({
      hostname: '127.0.0.1', port: 0,
      fetch(request) { return Response.json({ id: request.headers.get('X-Request-Id') }); },
    });
    const nodeOrigin = `http://127.0.0.1:${node.port}`;
    const previousHost = process.env.TINYCLOUD_URL;
    process.env.TINYCLOUD_URL = nodeOrigin;
    const app = new Hono<ApiEnv>();
    app.use('*', requestLogger);
    const { promise, resolve } = Promise.withResolvers<void>();
    let background: Promise<void>;
    app.get('/outbound', async (c) => {
      await fetch(new Request(`${nodeOrigin}/request`, {
        method: 'POST', headers: { Authorization: 'Bearer outbound-canary', 'X-Request-Id': 'stale-id' }, body: 'signed-body',
      }));
      await fetch(new Request(`${nodeOrigin}/override`, {
        method: 'POST', headers: { Authorization: 'must-be-overridden' }, body: 'original-body',
      }), { headers: { Authorization: 'Bearer override-canary' }, body: 'override-body' });
      background = promise.then(async () => { await fetch(`${nodeOrigin}/background`); });
      const thirdParty = await fetch(`http://127.0.0.1:${other.port}/third-party`);
      await withScheduledLogContext(() => fetch(`${nodeOrigin}/scheduled`));
      return c.json(await thirdParty.json());
    });
    try {
      const response = await app.request('/outbound', { headers: { 'X-Request-Id': uuid } });
      expect(await response.json()).toEqual({ id: null });
      resolve();
      await background!;
      await fetch(`${nodeOrigin}/startup`);
      expect(received).toEqual([
        { id: uuid, authorization: 'Bearer outbound-canary', body: 'signed-body', path: '/request' },
        { id: uuid, authorization: 'Bearer override-canary', body: 'override-body', path: '/override' },
        { id: null, authorization: null, body: '', path: '/scheduled' },
        { id: uuid, authorization: null, body: '', path: '/background' },
        { id: null, authorization: null, body: '', path: '/startup' },
      ]);
      expect(output.join('\n')).not.toContain('outbound-canary');
      expect(output.join('\n')).not.toContain('override-canary');
    } finally {
      resolve();
      node.stop(true);
      other.stop(true);
      if (previousHost === undefined) delete process.env.TINYCLOUD_URL;
      else process.env.TINYCLOUD_URL = previousHost;
    }
  });

  for (const status of [302, 307]) {
    test(`blocks injected IDs from following ${status} redirects without replaying signed requests`, async () => {
      const untrusted: Array<{ id: string | null; path: string }> = [];
      const other = Bun.serve({
        hostname: '127.0.0.1', port: 0,
        fetch(request) {
          untrusted.push({ id: request.headers.get('X-Request-Id'), path: new URL(request.url).pathname });
          return new Response('untrusted');
        },
      });
      const received: Array<{ id: string | null; authorization: string | null; body: string; path: string }> = [];
      const node = Bun.serve({
        hostname: '127.0.0.1', port: 0,
        async fetch(request) {
          const path = new URL(request.url).pathname;
          received.push({
            id: request.headers.get('X-Request-Id'), authorization: request.headers.get('Authorization'),
            body: await request.text(), path,
          });
          if (path === '/same-origin-target') return new Response('same-origin');
          return new Response(null, {
            status,
            headers: { Location: path === '/same-origin' ? '/same-origin-target' : `http://127.0.0.1:${other.port}/untrusted-target` },
          });
        },
      });
      const nodeOrigin = `http://127.0.0.1:${node.port}`;
      const previousHost = process.env.TINYCLOUD_URL;
      process.env.TINYCLOUD_URL = nodeOrigin;
      const app = new Hono<ApiEnv>();
      app.use('*', requestLogger);
      const init = { method: 'POST', headers: { Authorization: 'Bearer redirect-canary' }, body: 'signed-request-body' };
      const outcome = async (request: Promise<Response>) => {
        try { return (await request).status; }
        catch { return 'rejected'; }
      };
      app.get('/redirect-check', async (c) => c.json({
        defaultFollow: await outcome(fetch(`${nodeOrigin}/default-follow`, init)),
        requestFollow: await outcome(fetch(new Request(`${nodeOrigin}/request-follow`, { ...init, redirect: 'follow' }))),
        overrideFollow: await outcome(fetch(new Request(`${nodeOrigin}/override-follow`, { ...init, redirect: 'manual' }), { redirect: 'follow' })),
        manual: await outcome(fetch(`${nodeOrigin}/manual`, { ...init, redirect: 'manual' })),
        requestManual: await outcome(fetch(new Request(`${nodeOrigin}/request-manual`, { ...init, redirect: 'manual' }))),
        overrideManual: await outcome(fetch(new Request(`${nodeOrigin}/override-manual`, init), { redirect: 'manual' })),
        explicitError: await outcome(fetch(`${nodeOrigin}/explicit-error`, { ...init, redirect: 'error' })),
        sameOriginFollow: await outcome(fetch(`${nodeOrigin}/same-origin`, init)),
      }));
      try {
        const response = await app.request('/redirect-check', { headers: { 'X-Request-Id': uuid } });
        const results = await response.json();
        expect(untrusted).toEqual([]);
        expect(results).toEqual({
          defaultFollow: 'rejected', requestFollow: 'rejected', overrideFollow: 'rejected',
          manual: status, requestManual: status, overrideManual: status, explicitError: 'rejected', sameOriginFollow: 'rejected',
        });
        expect(received).toEqual([
          '/default-follow', '/request-follow', '/override-follow', '/manual', '/request-manual', '/override-manual', '/explicit-error', '/same-origin',
        ].map((path) => ({ id: uuid, authorization: 'Bearer redirect-canary', body: 'signed-request-body', path })));
        // No injected ID outside request context: keep native redirect behavior.
        expect((await fetch(`${nodeOrigin}/cross-origin`)).status).toBe(200);
        expect((await fetch(`http://127.0.0.1:${other.port}/direct-untrusted`)).status).toBe(200);
        expect(untrusted).toEqual([
          { id: null, path: '/untrusted-target' }, { id: null, path: '/direct-untrusted' },
        ]);
        expect(output.join('\n')).not.toContain('redirect-canary');
        expect(output.join('\n')).not.toContain('signed-request-body');
      } finally {
        node.stop(true);
        other.stop(true);
        if (previousHost === undefined) delete process.env.TINYCLOUD_URL;
        else process.env.TINYCLOUD_URL = previousHost;
      }
    });
  }
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
    // Starting a process and an in-memory PGlite takes about 4 s on a busy host.
  }, 30_000);
});
