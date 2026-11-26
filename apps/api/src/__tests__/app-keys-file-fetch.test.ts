// The app-keys file goes through the same guarded fetcher as the manifest,
// on its own path; the manifest's behaviour is the same as before. The real
// pinned HTTPS transport runs against a local origin (see the fixture).

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, spyOn, test } from 'bun:test';
import { promises as dns, type LookupAddress } from 'node:dns';
import type { Server } from 'node:http';
import { fixture, fixtureConnect, resetFixture, startOrigin } from './pinned-transport-fixture';
import { mockModules } from './mock-module';

await mockModules({ 'node:tls': () => ({ connect: fixtureConnect }) });

let fetchAppKeysFile: typeof import('../services/manifest-origin-fetch')['fetchAppKeysFile'];
let fetchAndBindWellKnownManifest: typeof import('../services/manifest-origin-fetch')['fetchAndBindWellKnownManifest'];
let origin: Server;

beforeAll(async () => {
  origin = await startOrigin();
  ({ fetchAppKeysFile, fetchAndBindWellKnownManifest } = await import('../services/manifest-origin-fetch?app-keys-file-fetch' as string));
});
afterAll(() => {
  origin.closeAllConnections();
  origin.close();
});
beforeEach(resetFixture);

// An address literal: resolving it needs no network.
const PUBLIC_HOST = '93.184.216.34';
const MANIFEST_PATH = '/.well-known/openkey-manifest.json';
const APP_KEYS_PATH = '/.well-known/openkey-app-keys.json';
const JSON_TYPE = { 'Content-Type': 'application/json' };

describe('fetchAppKeysFile', () => {
  test('asks for the app-keys path over https with no redirects and returns the bytes', async () => {
    const body = '{"type":"openkey-app-keys","app_id":"x","keys":[]}';
    fixture.handler = (_req, res) => res.writeHead(200, { 'Content-Type': 'application/json; charset=UTF-8' }).end(body);
    const result = await fetchAppKeysFile(PUBLIC_HOST);
    expect(result.ok).toBe(true);
    expect(result.ok && new TextDecoder().decode(result.bytes)).toBe(body);
    expect(fixture.requests).toEqual([APP_KEYS_PATH]);
    expect(fixture.dialed).toEqual([{ host: PUBLIC_HOST, port: 443, servername: undefined }]);
  });

  test.each([[404, 'missing'], [410, 'missing'], [403, 'unavailable'], [500, 'unavailable']])('status %i is %s', async (status, kind) => {
    fixture.handler = (_req, res) => res.writeHead(status).end();
    await expect(fetchAppKeysFile(PUBLIC_HOST)).resolves.toMatchObject({ ok: false, kind });
  });

  test('a body over 64 KiB is unavailable', async () => {
    fixture.handler = (_req, res) => res.writeHead(200, JSON_TYPE).end('x'.repeat(64 * 1024 + 1));
    await expect(fetchAppKeysFile(PUBLIC_HOST)).resolves.toMatchObject({ ok: false, kind: 'unavailable' });
  });

  test('a fetch that throws is unavailable', async () => {
    fixture.handler = (req) => req.socket.destroy();
    await expect(fetchAppKeysFile(PUBLIC_HOST)).resolves.toMatchObject({ ok: false, kind: 'unavailable' });
  });

  test.each(['10.0.0.1', '127.0.0.1', '169.254.169.254', 'localhost'])('never asks a private host (%s)', async (host) => {
    await expect(fetchAppKeysFile(host)).resolves.toMatchObject({ ok: false, kind: 'unavailable' });
    expect(fixture.dialed).toEqual([]);
  });
});

describe('the manifest fetch', () => {
  test('still asks for the manifest path and reports the status as before', async () => {
    fixture.handler = (_req, res) => res.writeHead(404).end();
    const result = await fetchAndBindWellKnownManifest({ reportedOrigin: `https://${PUBLIC_HOST}`, declaredDigest: 'a'.repeat(64) });
    expect(result).toEqual({ ok: false, reason: 'fetch returned status 404' });
    expect(fixture.requests).toEqual([MANIFEST_PATH]);
  });

  test('checks the digest before it fetches', async () => {
    const result = await fetchAndBindWellKnownManifest({ reportedOrigin: `https://${PUBLIC_HOST}`, declaredDigest: 'nope' });
    expect(result).toEqual({ ok: false, reason: 'declaredDigest is not a 64-char hex sha256' });
    expect(fixture.dialed).toEqual([]);
  });
});

// The app-keys fetch must not reach anything the manifest fetch refuses. Each case
// runs against both fetchers and both must refuse, through the same transport.
describe('the app-keys fetch refuses what the manifest fetch refuses', () => {
  const allDns = dns as { lookup(host: string, options: { all: true }): Promise<LookupAddress[]> };
  let lookup: ReturnType<typeof spyOn<typeof allDns, 'lookup'>>;
  beforeEach(() => { lookup = spyOn(allDns, 'lookup'); });
  afterEach(() => { lookup.mockRestore(); });

  const digest = 'a'.repeat(64);
  const fetchers = {
    'the manifest fetch': async (host: string) => {
      const result = await fetchAndBindWellKnownManifest({ reportedOrigin: `https://${host}`, declaredDigest: digest });
      return { ok: result.ok, reason: result.ok ? '' : result.reason ?? '' };
    },
    'the app-keys fetch': async (host: string) => {
      const result = await fetchAppKeysFile(host);
      return { ok: result.ok, reason: result.ok ? '' : result.reason };
    },
  };
  const family = (address: string) => (address.includes(':') ? 6 : 4);

  const refusedAddresses = [
    '127.0.0.1', '127.255.255.254', '10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '100.127.0.1', '0.0.0.0', '192.0.0.1', '198.18.0.1', '224.0.0.1', '255.255.255.255',
    '::1', '::', '::ffff:127.0.0.1', '0:0:0:0:0:ffff:c0a8:101', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'febf::1',
    '2002::1', '2001:db8::1', '64:ff9b::7f00:1', '64:ff9b:1::1', '100::1', 'ff02::1',
  ];

  describe.each(Object.entries(fetchers))('%s', (_name, run) => {
    test.each(refusedAddresses)('a lookup answer of %s is refused before any connection', async (address) => {
      lookup.mockResolvedValue([{ address, family: family(address) }]);
      expect(await run('app.test')).toEqual({ ok: false, reason: `reportedOrigin resolves to reserved address ${address}` });
      expect(fixture.dialed).toEqual([]);
    });

    test.each(refusedAddresses)('a lookup that also answers %s is refused whole', async (address) => {
      lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }, { address, family: family(address) }]);
      expect(await run('app.test')).toEqual({ ok: false, reason: `reportedOrigin resolves to reserved address ${address}` });
      expect(fixture.dialed).toEqual([]);
    });

    test.each(['10.0.0.1', '127.0.0.1', '169.254.169.254', '[::1]', 'localhost', 'app.localhost'])('the host %s is refused', async (host) => {
      const result = await run(host);
      expect(result.ok).toBe(false);
      expect(fixture.dialed).toEqual([]);
    });

    test('a DNS answer that later changes is not looked up again: the connection goes to the first answer', async () => {
      lookup.mockResolvedValueOnce([{ address: PUBLIC_HOST, family: 4 }]);
      lookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }]);
      fixture.handler = (_req, res) => res.writeHead(404).end();
      const result = await run('app.test');
      expect(result.ok).toBe(false);
      expect(lookup).toHaveBeenCalledTimes(1);
      expect(fixture.dialed).toEqual([{ host: PUBLIC_HOST, port: 443, servername: 'app.test' }]);
    });

    test('the connection goes to the first of several public answers', async () => {
      lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }, { address: '8.8.4.4', family: 4 }]);
      fixture.handler = (_req, res) => res.writeHead(404).end();
      await run('app.test');
      expect(fixture.dialed.map(({ host }) => host)).toEqual([PUBLIC_HOST]);
    });

    test.each([301, 302, 303, 307, 308])('a %i redirect is refused and its target is never requested', async (status) => {
      lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
      fixture.handler = (_req, res) => res.writeHead(status, { Location: 'https://169.254.169.254/latest/meta-data' }).end();
      expect((await run('app.test')).ok).toBe(false);
      expect(fixture.requests).toHaveLength(1);
      expect(fixture.dialed).toHaveLength(1);
    });

    test('a same-host redirect is refused and not followed', async () => {
      lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
      fixture.handler = (req, res) => (req.url === '/destination'
        ? res.writeHead(200, JSON_TYPE).end('{}')
        : res.writeHead(302, { Location: '/destination' }).end());
      expect((await run('app.test')).ok).toBe(false);
      expect(fixture.requests).not.toContain('/destination');
    });

    test('a certificate for another host is refused before any request', async () => {
      lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
      fixture.certificateName = 'other.test';
      expect((await run('app.test')).ok).toBe(false);
      expect(fixture.requests).toEqual([]);
    });

    test('a body over 64 KiB is refused', async () => {
      lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
      fixture.handler = (_req, res) => res.writeHead(200, JSON_TYPE).end('x'.repeat(64 * 1024 + 1));
      expect(await run('app.test')).toEqual({ ok: false, reason: 'response exceeded 64KB' });
    });

    test('a request reaches the local origin when every answer is public (control)', async () => {
      lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
      fixture.handler = (_req, res) => res.writeHead(404).end();
      expect((await run('app.test')).ok).toBe(false);
      expect(fixture.requests).toHaveLength(1);
    });
  });

  test('both fetches ask for their own path only', async () => {
    lookup.mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
    fixture.handler = (_req, res) => res.writeHead(404).end();
    await fetchers['the manifest fetch']('app.test');
    await fetchers['the app-keys fetch']('app.test');
    expect(fixture.requests).toEqual([MANIFEST_PATH, APP_KEYS_PATH]);
  });

  test('both fetches share the 32-lookup cap and refuse at capacity', async () => {
    const releases: Array<(addresses: LookupAddress[]) => void> = [];
    lookup.mockImplementation(() => new Promise((resolve) => releases.push(resolve)));
    const pending = Array.from({ length: 32 }, () => fetchAppKeysFile('app.test'));
    try {
      expect(await fetchers['the manifest fetch']('app.test')).toEqual({ ok: false, reason: 'DNS lookup capacity reached' });
      await expect(fetchAppKeysFile('app.test')).resolves.toMatchObject({ ok: false, kind: 'busy' });
      expect(lookup).toHaveBeenCalledTimes(32);
      expect(fixture.dialed).toEqual([]);
    } finally {
      for (const release of releases) release([]);
      await Promise.all(pending);
    }
  });
});
