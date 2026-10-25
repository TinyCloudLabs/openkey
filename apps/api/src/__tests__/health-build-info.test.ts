import { expect, test } from 'bun:test';
import { Hono } from 'hono';

import { readBuildInfo } from '../build-info';
import { readinessHandler } from '../readiness';

function healthApp(ready: boolean) {
  const app = new Hono();
  app.get('/health', readinessHandler(async () => ({ ready }), () => readBuildInfo()));
  return app;
}

async function withGitSha<T>(value: string | undefined, run: () => Promise<T>): Promise<T> {
  const saved = process.env.GIT_SHA;
  if (value === undefined) delete process.env.GIT_SHA;
  else process.env.GIT_SHA = value;
  try {
    return await run();
  } finally {
    if (saved === undefined) delete process.env.GIT_SHA;
    else process.env.GIT_SHA = saved;
  }
}

for (const unset of [undefined, '', '  ']) {
  test(`health reports commit "unknown" when GIT_SHA is ${JSON.stringify(unset)}`, async () => {
    await withGitSha(unset, async () => {
      const response = await healthApp(true).request('/health');
      expect(response.status).toBe(200);
      const body = (await response.json()) as { version: unknown; commit: unknown };
      expect(typeof body.version).toBe('string');
      expect((body.version as string).length).toBeGreaterThan(0);
      expect(body.commit).toBe('unknown');
    });
  });
}

test('health reports the GIT_SHA value as commit', async () => {
  await withGitSha('0123456789abcdef0123456789abcdef01234567', async () => {
    const response = await healthApp(true).request('/health');
    expect(response.status).toBe(200);
    const body = (await response.json()) as { commit: unknown };
    expect(body.commit).toBe('0123456789abcdef0123456789abcdef01234567');
  });
});

test('health reports the apps/api/package.json version', async () => {
  const pkg = (await Bun.file(new URL('../../package.json', import.meta.url)).json()) as { version: string };
  const response = await healthApp(true).request('/health');
  expect(((await response.json()) as { version: string }).version).toBe(pkg.version);
});

test('not-ready response keeps its status and body', async () => {
  const response = await healthApp(false).request('/health');
  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ status: 'not_ready' });
});
