import { afterEach, expect, spyOn, test } from 'bun:test';
import dns, { type LookupAddress, type LookupAllOptions } from 'node:dns';
import type * as Manifest from '../services/manifest-origin-fetch';

// File-specific instance isolates this import from route tests that replace the binder.
const { fetchAndBindWellKnownManifest } = await import('../services/manifest-origin-fetch?manifest-origin-ipv6-ranges-test' as string) as typeof Manifest;
const origin = { reportedOrigin: 'https://manifest.test', declaredDigest: 'a'.repeat(64) };
const sentinel = '127.0.0.2';
const resolver: { lookup(hostname: string, options: LookupAllOptions): Promise<LookupAddress[]> } = dns.promises;
let restoreLookup: (() => void) | undefined;
afterEach(() => {
  restoreLookup?.();
  restoreLookup = undefined;
});

// Only global unicast 2000::/3 passes, minus the listed prefixes.
const refused = [
  // 2002::/16 6to4
  '2002::1', '2002:808:808::1', '2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
  // 2001::/32 Teredo and the rest of 2001::/23 IETF protocol assignments
  '2001::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2', '2001:1::1', '2001:2::1', '2001:10::1', '2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff',
  // 2001:db8::/32 documentation and 3fff::/20 documentation
  '2001:db8::1', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', '3fff::1', '3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff',
  // 64:ff9b::/96 and 64:ff9b:1::/48 translation, IPv4 embedded
  '64:ff9b::808:808', '64:ff9b::7f00:1', '64:ff9b:1::1',
  // ::/96 IPv4-compatible, unspecified, loopback, ::ffff:0:0/96 mapped
  '::', '::1', '::808:808', '::7f00:1', '::ffff:808:808', '::ffff:8.8.8.8', '0:0:0:0:0:ffff:808:808',
  // 100::/64 discard, fec0::/10 site-local, fe80::/10 link-local, fc00::/7 unique-local, ff00::/8 multicast
  '100::1', '100::ffff:ffff:ffff:ffff', 'fec0::1', 'feff::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1',
  // everything outside 2000::/3 fails closed
  '1::1', '4000::1', '5f00::1', '8000::1', 'e000::1',
];
const allowed = [
  '2606:4700:4700::1111', '2a00:1450:4001:81d::200e', '2001:4860:4860::8888',
  // first and last addresses next to refused prefixes
  '2001:200::1', '2001:db9::1', '2003::1', '3fff:1000::1', '2000::1', '3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
];

test.each([...refused.map((address) => [address, true] as const), ...allowed.map((address) => [address, false] as const)])(
  'IPv6 answer %s is refused: %p',
  async (address, isRefused) => {
    const lookup = spyOn(resolver, 'lookup');
    restoreLookup = () => lookup.mockRestore();
    // A passing answer reaches the sentinel; a refused one stops before it.
    lookup.mockResolvedValue([{ address, family: 6 }, { address: sentinel, family: 4 }]);
    expect(await fetchAndBindWellKnownManifest(origin)).toEqual({
      ok: false, reason: `reportedOrigin resolves to reserved address ${isRefused ? address : sentinel}`,
    });
  },
);
