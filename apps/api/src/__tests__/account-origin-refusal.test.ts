import { afterEach, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { requireAccountOriginForBearer } from '../middleware/bearer-origin';
import { getAccountOriginRefusals, recordAccountOriginRefused } from '../log';

const accountOrigin = 'https://openkey.test';
const foreignOrigin = 'https://private-origin.example';
const previousWebauthnOrigin = process.env.WEBAUTHN_ORIGIN;
const originalWrite = process.stdout.write;
const lines: string[] = [];

function captureLogs() {
  lines.length = 0;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    lines.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
}

afterEach(() => {
  process.stdout.write = originalWrite;
  if (previousWebauthnOrigin === undefined) delete process.env.WEBAUTHN_ORIGIN;
  else process.env.WEBAUTHN_ORIGIN = previousWebauthnOrigin;
});

test('account-origin refusals preserve responses, log only the route and reason, and count missing origins', async () => {
  process.env.WEBAUTHN_ORIGIN = accountOrigin;
  const app = new Hono();
  app.use('*', requireAccountOriginForBearer);
  app.get('/api/account/:accountId', (c) => c.json({ ok: true }));

  captureLogs();
  const foreign = await app.request('/api/account/account_1', { headers: { origin: foreignOrigin } });
  expect(foreign.status).toBe(403);
  expect(await foreign.json()).toEqual({ error: 'Requests are accepted only from the OpenKey account origin' });
  expect(lines).toHaveLength(1);
  expect(lines[0]).toContain('account_origin_refused');
  expect(JSON.parse(lines[0]!)).toMatchObject({ route: '/api/account/:accountId', reason: 'foreign' });

  lines.length = 0;
  const missing = await app.request('/api/account/account_1', { headers: { authorization: 'Bearer test-token' } });
  expect(missing.status).toBe(403);
  expect(await missing.json()).toEqual({ error: 'Bearer session tokens are accepted only from OpenKey' });
  expect(JSON.parse(lines[0]!)).toMatchObject({ route: '/api/account/:accountId', reason: 'missing' });

  const beforeAllowed = getAccountOriginRefusals();
  lines.length = 0;
  const allowed = await app.request('/api/account/account_1', { headers: { origin: accountOrigin } });
  expect(allowed.status).toBe(200);
  expect(lines).toEqual([]);
  expect(getAccountOriginRefusals()).toEqual(beforeAllowed);
});

test('origin refusal counters bound distinct route keys and fold overflow into other', async () => {
  captureLogs();
  const { getAccountOriginRefusals: getIsolatedRefusals, recordAccountOriginRefused: recordIsolatedRefusal } =
    await import('../log?origin-refusal-cap-test' as string);
  for (let i = 0; i < 250; i++) recordIsolatedRefusal(`/api/test/${i}`, 'foreign');
  const { counts } = getIsolatedRefusals();
  expect(counts.length).toBeLessThanOrEqual(200);
  expect(counts.find((entry: { route: string; reason: string }) => entry.route === 'other' && entry.reason === 'other')?.count ?? 0).toBe(51);
});
