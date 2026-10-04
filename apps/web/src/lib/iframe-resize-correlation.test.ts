// Sol MAJOR-5 (final): the embed sign page's LEGACY fallback resize path
// (used only when the shared transport failed to construct — wildcard-
// origin compat) MUST carry the same correlation the shared transport
// enforces: `requestId` bound to the active request AND the negotiated
// `protocolVersion`. Missing correlation lets a stale sibling frame's
// resize be accepted or accepted after a newer request has already
// superseded this one.
//
// The fallback lives inside a Svelte `$effect` on a page that requires
// the full SvelteKit runtime to render — a full jsdom + SvelteKit
// harness is impractical in this suite. Instead this test asserts the
// source shape of the fallback branch. The RUNTIME correlation
// validation (wrong requestId, wrong protocolVersion, sequential
// requests, missing correlation) is exercised end-to-end against the
// PARENT-SIDE parser in `packages/sdk/src/index.test.ts::
// validateIframeResize`. Both sides of the correlation channel are
// therefore under test: the widget side (source-shape here) and the
// parent side (exhaustive validator branches there).
//
// TC-647: when no versioned request is bound (an unversioned
// `signMessage`), the page sends a plain `{ type, height }` resize to the
// configured origin. The SDK accepts it only on a modal that carries no
// versioned request.

// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const THIS_FILE = fileURLToPath(import.meta.url);
const WEB_ROOT = join(dirname(THIS_FILE), '..', '..');
const EMBED_SIGN_PAGE = join(
  WEB_ROOT,
  'src/routes/widget/embed/sign/+page.svelte',
);

describe('embed sign page fallback resize (Sol MAJOR-5 final)', () => {
  it('emits fallback resize messages carrying the active requestId AND protocolVersion', () => {
    const src = readFileSync(EMBED_SIGN_PAGE, 'utf8');
    // The pre-fix payload was:
    //   `{ type: 'openkey:resize', height, protocolVersion: 1 }`
    // — a hardcoded protocolVersion with NO requestId. That exact
    // literal must be gone.
    expect(src).not.toMatch(
      /\{\s*type:\s*'openkey:resize',\s*height,\s*protocolVersion:\s*1\s*\}/,
    );
    // The fallback branch (the ELSE arm where the shared transport
    // failed to construct) must reference the active correlation
    // state (currentRequestId + messageProtocolVersion) so a stale
    // sibling frame's resize cannot escape.
    const fallbackMatch = src.match(
      /if\s*\(\s*transport\s*\)\s*\{\s*transport\.emitResize\(height\);\s*\}\s*else\s*\{[\s\S]*?openkey:resize[\s\S]*?\}\s*,\s*origin\s*,?\s*\)\s*;/,
    );
    expect(fallbackMatch, 'fallback resize branch not found').not.toBeNull();
    const branchText = fallbackMatch?.[0] ?? '';
    expect(branchText).toMatch(/requestId\s*:\s*currentRequestId/);
    expect(branchText).toMatch(/protocolVersion\s*:\s*messageProtocolVersion/);
  });

  it('sends correlated resizes only while a versioned request is bound', () => {
    // The transport and the correlated fallback both sit behind this guard,
    // so a versioned request never sends an uncorrelated resize once bound.
    const src = readFileSync(EMBED_SIGN_PAGE, 'utf8');
    expect(src).toMatch(
      /if\s*\(\s*currentRequestId\s*&&\s*messageProtocolVersion\s*!==\s*null\s*\)\s*\{\s*(\/\/[^\n]*\n\s*)*if\s*\(\s*transport\s*\)/,
    );
  });

  it('sends a plain resize to the configured origin when no versioned request is bound (TC-647)', () => {
    // An unversioned `signMessage` binds no correlation in the SDK, which
    // then accepts only a plain resize from this iframe. Without it the
    // modal stays at its 400px default and hides Approve.
    const src = readFileSync(EMBED_SIGN_PAGE, 'utf8');
    expect(src).toMatch(
      /window\.parent\.postMessage\(\s*\{\s*type:\s*'openkey:resize',\s*height\s*\}\s*,\s*origin\s*\)/,
    );
    // Never to a wildcard target.
    expect(src).not.toMatch(/type:\s*'openkey:resize',\s*height\s*\}\s*,\s*'\*'/);
  });

  it('does not emit resize under wildcard origin (defense in depth)', () => {
    // Wildcard-origin sessions are refused elsewhere for versioned
    // callers; the observer additionally must not emit a resize
    // targeted at '*' since a wildcard target leaks DOM sizing to
    // any frame in the tab. This guard was pre-existing and MUST
    // remain.
    const src = readFileSync(EMBED_SIGN_PAGE, 'utf8');
    expect(src).toMatch(/if\s*\(\s*origin\s*===\s*['"]\*['"]\s*\)\s*return\s*;/);
  });
});
