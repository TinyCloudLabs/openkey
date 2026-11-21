// TC-3657 Bobbie N2 (15:42:43Z): the framing-headers predicate in hooks.server.ts MUST
// match on the SvelteKit route id (the decoded, normalised route template) and NOT on
// the raw URL pathname, so a crafted `/widget/tinycloud%2Dsetup` (or any other percent-
// encoded ASCII spelling of the same route) cannot bypass the `frame-ancestors 'none'` +
// `X-Frame-Options: DENY` headers.
//
// This test imports the standalone predicate module (no SvelteKit path-alias deps) so it
// can run under `bun test` without the full hooks chain. The predicate is wired into
// `hooks.server.ts` via a direct import of the same symbol.
//
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { isTinyCloudSetupWidgetRoute } from '../routes/widget/tinycloud-setup/route-match';

describe('tinycloud-setup widget route matcher (N2)', () => {
  test('matches the setup widget route id', () => {
    expect(isTinyCloudSetupWidgetRoute('/widget/tinycloud-setup')).toBe(true);
  });

  test('matches child routes under /widget/tinycloud-setup/', () => {
    expect(isTinyCloudSetupWidgetRoute('/widget/tinycloud-setup/consent')).toBe(true);
  });

  test('does not match adjacent widget routes', () => {
    expect(isTinyCloudSetupWidgetRoute('/widget/tinycloud-setup-adjacent')).toBe(false);
    expect(isTinyCloudSetupWidgetRoute('/widget/connect')).toBe(false);
    expect(isTinyCloudSetupWidgetRoute('/widget/sign')).toBe(false);
  });

  test('does not match the root or unrelated routes', () => {
    expect(isTinyCloudSetupWidgetRoute('')).toBe(false);
    expect(isTinyCloudSetupWidgetRoute('/')).toBe(false);
    expect(isTinyCloudSetupWidgetRoute('/api/tinycloud-setup/mint-ticket')).toBe(false);
  });

  // The %2D bypass lives in the ROUTE-ID space, not in this predicate. SvelteKit resolves
  // `/widget/tinycloud%2Dsetup` to the route template `/widget/tinycloud-setup` (it decodes
  // percent-encoded ASCII during routing), so the predicate called with that route id matches.
  // The old implementation keyed on `event.url.pathname` and would have seen the raw
  // `/widget/tinycloud%2Dsetup` string instead — which is NOT a route id this predicate
  // accepts, so anyone who regresses the hooks to a raw-pathname check will fail this test.
  test('raw-pathname look-alikes are NOT a bypass path (the predicate only matches route ids)', () => {
    expect(isTinyCloudSetupWidgetRoute('/widget/tinycloud%2Dsetup')).toBe(false);
    expect(isTinyCloudSetupWidgetRoute('/WIDGET/TINYCLOUD-SETUP')).toBe(false);
    expect(isTinyCloudSetupWidgetRoute('/widget//tinycloud-setup')).toBe(false);
  });
});
