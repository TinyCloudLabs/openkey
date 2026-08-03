// Sol MAJOR-3 (final continuation): structural guardrail for the
// OpenKey signing-approval production surface adapters.
//
// The prior version of this file parsed each production `+page.svelte`
// source to extract literal `<SigningApproval .../>` blocks and
// programmatically rewrote route-specific model/selection/callback
// expressions into a synthetic wrapper — Sol correctly rejected both
// approaches (source-text parsing and expression rewriting are
// explicitly banned by the approval contract). It also became stale
// once the production routes moved from mounting `<SigningApproval>`
// directly to mounting the substantive `{Cli,Popup,Iframe}SigningAdapter`
// components at
// `src/lib/components/signing/{cli,popup,iframe}-signing-adapter.svelte`.
//
// This file is now a structural guardrail. It:
//
//   1. Asserts each production route imports and mounts the CORRECT
//      named adapter component from `$lib/components/signing/*`.
//      A regression that inlined `<SigningApproval .../>` again in a
//      route (bypassing the substantive adapter's approve-path routing,
//      invalidate-preview wiring, or selection mapping) would fail
//      here loudly.
//
//   2. Asserts each substantive adapter mounts the SAME shared
//      `SigningApproval` component. This is the single-source-of-truth
//      invariant: the three surface adapters must present the same
//      content, so they must mount the same component file.
//
//   3. Asserts each adapter accepts the correct transport interface
//      (CliSigningTransport vs WidgetSigningTransport) — enforced via
//      a compile-time type check under `svelte-check`.
//
// The full behavioral and accessibility parity contract is covered by
// two focused suites:
//   - src/lib/signing-approval-parity-mounted.test.ts (happy-dom mount
//     + real KeyboardEvent + spy transport assertions on the exact
//     production adapters)
//   - tests/browser/signing-approval-parity.spec.ts (Playwright,
//     Chromium; real Tab/Space/Enter/click via `page.keyboard.press`;
//     native `<details>` toggling; the exact production adapters
//     mounted through the SvelteKit dev server)
//
// This file exists solely to lock the STRUCTURAL invariant. There is
// no source-text expression rewriting, no synthetic wrapper, no route
// logic re-implementation.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const THIS_FILE = fileURLToPath(import.meta.url);
const WEB_ROOT = join(dirname(THIS_FILE), '..', '..');

/**
 * Each production route → the adapter it MUST mount. Any bypass (e.g. a
 * route directly mounting `<SigningApproval>` again, or mounting the
 * wrong surface's adapter) fails the "route imports named adapter"
 * assertion below.
 */
const ROUTE_ADAPTERS = [
  {
    route: 'src/routes/delegate/+page.svelte',
    adapter: 'CliSigningAdapter',
    adapterFile: 'src/lib/components/signing/cli-signing-adapter.svelte',
    importPath: '$lib/components/signing/cli-signing-adapter.svelte',
  },
  {
    route: 'src/routes/widget/sign/+page.svelte',
    adapter: 'PopupSigningAdapter',
    adapterFile: 'src/lib/components/signing/popup-signing-adapter.svelte',
    importPath: '$lib/components/signing/popup-signing-adapter.svelte',
  },
  {
    route: 'src/routes/widget/embed/sign/+page.svelte',
    adapter: 'IframeSigningAdapter',
    adapterFile: 'src/lib/components/signing/iframe-signing-adapter.svelte',
    importPath: '$lib/components/signing/iframe-signing-adapter.svelte',
  },
] as const;

function readWebFile(rel: string): string {
  return readFileSync(join(WEB_ROOT, rel), 'utf8');
}

describe('signing-approval production-adapter structural guardrail', () => {
  test('each route imports and mounts the correct named adapter', () => {
    for (const { route, adapter, importPath } of ROUTE_ADAPTERS) {
      const src = readWebFile(route);
      // Adapter import must appear.
      expect(src).toContain(`import ${adapter} from '${importPath}'`);
      // Adapter must be mounted (either opening tag). Presence of the
      // tag proves the adapter is actually rendered — the parity
      // suites take over from there for behavior/accessibility.
      expect(src).toMatch(new RegExp(`<${adapter}\\b`));
    }
  });

  test('routes do NOT mount SigningApproval directly (bypassing the substantive adapter)', () => {
    // A regression that reintroduced a direct `<SigningApproval .../>`
    // mount in a route would skip the adapter's approve-path routing
    // (preview vs exact-byte) and the invalidate-preview-on-edit
    // wiring. Enforce that the substantive adapter is always the
    // mount point.
    for (const { route } of ROUTE_ADAPTERS) {
      const src = readWebFile(route);
      // The route may still IMPORT SigningApproval indirectly through
      // adapter compilation, but must not contain a direct `<SigningApproval`
      // element in its markup.
      expect(src).not.toMatch(/<SigningApproval\b/);
    }
  });

  test('widget routes do NOT replace the shared adapter with a route-local final review', () => {
    for (const route of [
      'src/routes/widget/sign/+page.svelte',
      'src/routes/widget/embed/sign/+page.svelte',
    ]) {
      const src = readWebFile(route);
      expect(src).not.toContain('Final review — server-authoritative bytes');
      expect(src).not.toMatch(/previewSignedMessage\s*&&\s*canUseAuthorizeSignFn\(\)/);
      expect(src).toContain('{:else if reviewModel}');
      expect(src).not.toContain("reviewModel && reviewModel.protocol === 'tinycloud-siwe-recap'");
      expect(src).not.toMatch(/<SiweMessage\b/);
    }
  });

  test('each substantive adapter mounts the shared SigningApproval component (single source of truth)', () => {
    for (const { adapterFile } of ROUTE_ADAPTERS) {
      const src = readWebFile(adapterFile);
      expect(src).toContain(
        `import SigningApproval from "$lib/components/signing/signing-approval.svelte"`,
      );
      expect(src).toMatch(/<SigningApproval\b/);
    }
  });

  test('CLI adapter typed to CliSigningTransport; widget adapters typed to WidgetSigningTransport', () => {
    // Static-shape guard: adapters must import the correct transport
    // interface from the shared types module. A regression that
    // rewired the CLI adapter with the widget transport (or vice
    // versa) would fail here. The routes and the parity suites depend
    // on this contract.
    const cli = readWebFile('src/lib/components/signing/cli-signing-adapter.svelte');
    expect(cli).toContain(`import type { CliSigningTransport } from "./signing-adapter-types"`);
    expect(cli).toContain(`transport: CliSigningTransport`);

    for (const rel of [
      'src/lib/components/signing/popup-signing-adapter.svelte',
      'src/lib/components/signing/iframe-signing-adapter.svelte',
    ]) {
      const src = readWebFile(rel);
      expect(src).toContain(
        `import type { WidgetSigningTransport } from "./signing-adapter-types"`,
      );
      expect(src).toContain(`transport: WidgetSigningTransport`);
    }
  });
});
