import { afterEach, expect, spyOn, test } from 'bun:test';
import dns, { type LookupAddress, type LookupAllOptions } from 'node:dns';
import type * as Manifest from '../services/manifest-origin-fetch';
import type * as Transport from '../services/pinned-https-fetch';

// File-specific instances isolate these imports from route tests that replace the binder.
const { fetchAndBindWellKnownManifest } = await import('../services/manifest-origin-fetch?pinned-https-fetch-test' as string) as typeof Manifest;
const { pinnedHttpsGet } = await import('../services/pinned-https-fetch?pinned-https-fetch-test' as string) as typeof Transport;
const origin = { reportedOrigin: 'https://manifest.test', declaredDigest: 'a'.repeat(64) };
const blocked = [
  '127.0.0.2', '10.0.0.1', '172.31.0.1', '192.168.1.1', '169.254.169.254', '100.127.0.1', '0.1.2.3',
  '::1', 'fc00::1', 'fd00::1', 'fe80::1', 'febf::1', '::ffff:127.0.0.1', '0:0:0:0:0:ffff:c0a8:101',
];
const resolver: { lookup(hostname: string, options: LookupAllOptions): Promise<LookupAddress[]> } = dns.promises;
let restoreLookup: (() => void) | undefined;
afterEach(() => {
  restoreLookup?.();
  restoreLookup = undefined;
});

test.each(blocked)('a lookup containing %s is refused', async (address) => {
  const lookup = spyOn(resolver, 'lookup');
  restoreLookup = () => lookup.mockRestore();
  const family = address.includes(':') ? 6 : 4;
  lookup.mockResolvedValue([{ address: '8.8.4.4', family: 4 }, { address, family }]);
  expect(await fetchAndBindWellKnownManifest(origin)).toEqual({
    ok: false, reason: `reportedOrigin resolves to reserved address ${address}`,
  });
});

test('the HTTPS transport refuses a hostname as a socket destination', async () => {
  expect(await pinnedHttpsGet(new URL(origin.reportedOrigin), 'manifest.test', 1024)).toEqual({ ok: false, kind: 'request' });
});

test('the HTTPS transport refuses a plain HTTP URL', async () => {
  expect(await pinnedHttpsGet(new URL('http://127.0.0.1'), '127.0.0.1', 1024)).toEqual({ ok: false, kind: 'request' });
});
