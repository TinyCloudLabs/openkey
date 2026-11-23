import { afterEach, beforeEach, expect, mock, spyOn, test } from 'bun:test';
import { promises as dns } from 'node:dns';
import { mockModules } from './mock-module';

const transport = mock(async () => Response.json({}));
await mockModules({ undici: () => ({ fetch: transport }) });
const { fetchAppKeysFile, fetchAndBindWellKnownManifest } = await import(
  '../services/manifest-origin-fetch?well-known-origin-guards' as string
) as typeof import('../services/manifest-origin-fetch');

let lookup: ReturnType<typeof spyOn<typeof dns, 'lookup'>>;
beforeEach(() => {
  lookup = spyOn(dns, 'lookup');
});
afterEach(() => {
  lookup.mockRestore();
  transport.mockClear();
});

test.each([
  '::5db8:d822',
  '0:0:0:0:0:0:5db8:d822',
  '2002::1',
  '2001:1ff::1',
  '64:ff9b:1::1',
  '100::1',
  'feff::1',
])('blocks reserved IPv6 address %s before opening a connection', async (address) => {
  lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }, { address, family: 6 }]);
  const result = await fetchAndBindWellKnownManifest({
    reportedOrigin: 'https://example.test',
    declaredDigest: 'a'.repeat(64),
  });
  expect(result).toEqual({ ok: false, reason: `reportedOrigin resolves to reserved address ${address}` });
  expect(transport).not.toHaveBeenCalled();
});

test('requires an explicit JSON media type on the app-keys file', async () => {
  lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
  transport.mockResolvedValueOnce(new Response('{"type":"openkey-app-keys","app_id":"test.example","keys":[]}'));
  await expect(fetchAppKeysFile('example.test')).resolves.toMatchObject({ ok: false, kind: 'invalid' });
});

test('a pending DNS lookup uses the same deadline as the request', async () => {
  lookup.mockImplementationOnce(() => new Promise(() => {}));
  await expect(fetchAppKeysFile('example.test')).resolves.toEqual({
    ok: false, kind: 'unavailable', reason: 'reportedOrigin DNS lookup threw',
  });
  expect(transport).not.toHaveBeenCalled();
}, 7_000);
