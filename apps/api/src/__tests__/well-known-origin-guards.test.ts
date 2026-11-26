import { afterAll, afterEach, beforeAll, beforeEach, expect, spyOn, test } from 'bun:test';
import { promises as dns, type LookupAddress } from 'node:dns';
import type { Server } from 'node:http';
import { fixture, fixtureConnect, resetFixture, startOrigin } from './pinned-transport-fixture';
import { mockModules } from './mock-module';

await mockModules({ 'node:tls': () => ({ connect: fixtureConnect }) });
const { fetchAppKeysFile, fetchAndBindWellKnownManifest } = await import(
  '../services/manifest-origin-fetch?well-known-origin-guards' as string
) as typeof import('../services/manifest-origin-fetch');

const allDns = dns as { lookup(host: string, options: { all: true }): Promise<LookupAddress[]> };
let lookup: ReturnType<typeof spyOn<typeof allDns, 'lookup'>>;
let origin: Server;
beforeAll(async () => {
  origin = await startOrigin();
});
afterAll(() => {
  origin.closeAllConnections();
  origin.close();
});
beforeEach(() => {
  resetFixture();
  lookup = spyOn(allDns, 'lookup');
});
afterEach(() => {
  lookup.mockRestore();
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
  expect(fixture.dialed).toEqual([]);
});

test('requires an explicit JSON media type on the app-keys file', async () => {
  lookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }]);
  fixture.handler = (_req, res) => res.end('{"type":"openkey-app-keys","app_id":"test.example","keys":[]}');
  await expect(fetchAppKeysFile('example.test')).resolves.toMatchObject({ ok: false, kind: 'invalid' });
});

test('timed-out DNS lookups keep their slots until the native lookup settles', async () => {
  const releases: Array<(addresses: LookupAddress[]) => void> = [];
  lookup.mockImplementation(() => new Promise(resolve => releases.push(resolve)));
  const pending = Array.from({ length: 32 }, () => fetchAppKeysFile('example.test'));
  const full = { ok: false, kind: 'busy', reason: 'DNS lookup capacity reached' } as const;

  try {
    await expect(fetchAppKeysFile('example.test')).resolves.toEqual(full);
    expect(await Promise.all(pending)).toEqual(Array.from({ length: 32 }, () => ({
      ok: false, kind: 'unavailable', reason: 'reportedOrigin DNS lookup threw',
    })));
    await expect(fetchAppKeysFile('example.test')).resolves.toEqual(full);
    expect(lookup).toHaveBeenCalledTimes(32);
    expect(fixture.dialed).toEqual([]);

    for (const release of releases) release([]);
    await Promise.resolve();
    lookup.mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }]);
    fixture.handler = (_req, res) => res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}');
    await expect(fetchAppKeysFile('example.test')).resolves.toMatchObject({ ok: true });
  } finally {
    for (const release of releases) release([]);
  }
}, 7_000);
