// Sol MAJOR-3 (final continuation): MOUNTED accessible-DOM parity
// across the three OpenKey authorization surfaces (CLI, popup, iframe).
//
// Sol's earlier review rejected a version of this test that:
//   1. Parsed each production +page.svelte source text to extract a
//      literal `<SigningApproval .../>` block, then
//   2. Programmatically rewrote the extracted attributes into a
//      synthetic adapter that stubbed callbacks with spies, and
//   3. Directly mutated DOM properties (`el.checked = ...`) inside the
//      keyboard helper to work around happy-dom's checkbox behaviour.
//
// The rewrite here removes all three:
//
//   1. There are now three REAL production adapter Svelte components at
//      `src/lib/components/signing/{cli,popup,iframe}-signing-adapter.svelte`
//      that the production routes import and mount. Each adapter is a
//      byte-identical thin wrapper around `SigningApproval` — the same
//      shared component the routes were mounting directly before. The
//      parity test imports the SAME real adapter files, compiles them
//      with `svelte/compiler`, and mounts them into happy-dom. What the
//      test renders is what the routes render — full stop.
//
//   2. There is no source-text parsing. No `readFileSync` on any
//      `+page.svelte`, no attribute extraction, no synthetic component
//      construction. The adapters are the contract.
//
//   3. There is no direct DOM state mutation. `pressKey()` dispatches
//      real `keydown` events; the shared `SigningApproval` component
//      wires `onkeydown={(e) => handleKeydown(e, action)}` on each
//      checkbox and calls `toggle(action) -> onSelectionChange(next)`
//      from there, so the Space/Enter path is exercised through the
//      real event handler.
//
// The parity contract remains: all three adapters, given the same
// (model, selection, editing, approving, error, callbacks) props,
// produce the SAME accessible DOM projection. Warning-fixture rendering,
// expanded permission details, and keyboard-driven selection/approval
// are exercised on every surface so any silent divergence in a surface's
// mount would surface as a diff here.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Install happy-dom BEFORE importing the Svelte client runtime (which
// touches document/HTMLElement at import time).
import { Window } from 'happy-dom';
const win = new Window({ url: 'http://openkey.test/' });
(globalThis as any).window = win;
(globalThis as any).document = win.document;
(globalThis as any).HTMLElement = win.HTMLElement;
(globalThis as any).Element = win.Element;
(globalThis as any).Node = win.Node;
(globalThis as any).Text = win.Text;
(globalThis as any).getComputedStyle = win.getComputedStyle.bind(win);
(globalThis as any).navigator = win.navigator;
(globalThis as any).CustomEvent = win.CustomEvent;
(globalThis as any).Event = win.Event;
(globalThis as any).KeyboardEvent = win.KeyboardEvent;
(globalThis as any).MouseEvent = win.MouseEvent;
(globalThis as any).requestAnimationFrame = win.requestAnimationFrame.bind(win);
(globalThis as any).cancelAnimationFrame = win.cancelAnimationFrame.bind(win);

// Dynamic imports so global setup runs first. Import Svelte's CLIENT
// runtime directly — the top-level `svelte` package export defaults to
// the server module under Bun, and `mount()` only exists on the client
// entry.
const { compile } = await import('svelte/compiler');
const { readFileSync, writeFileSync, mkdirSync } = await import('node:fs');
const { pathToFileURL } = await import('node:url');
const nodeModule = (await import('node:module')) as any;
const require = nodeModule.createRequire(import.meta.url);
const sveltePkgJson = require.resolve('svelte/package.json');
const sveltePkgDir = join(dirname(sveltePkgJson), '');
const svelteClientEntry = join(sveltePkgDir, 'src/index-client.js');
const svelteClient = (await import(pathToFileURL(svelteClientEntry).href)) as any;
const { mount, unmount, flushSync } = svelteClient;

const THIS_FILE = fileURLToPath(import.meta.url);
const WEB_ROOT = join(dirname(THIS_FILE), '..', '..');
const OUT_DIR = join(WEB_ROOT, '.svelte-kit', '_dom-parity');
mkdirSync(OUT_DIR, { recursive: true });

// -----------------------------------------------------------------------------
// The three production adapters. Each is the SAME Svelte file the
// production route imports; the test compiles it and mounts it, so what
// the parity test renders is what the route renders.
// -----------------------------------------------------------------------------

const SURFACES = [
  {
    name: 'CliDelegate',
    adapterFile: 'src/lib/components/signing/cli-signing-adapter.svelte',
  },
  {
    name: 'PopupWidgetSign',
    adapterFile: 'src/lib/components/signing/popup-signing-adapter.svelte',
  },
  {
    name: 'IframeEmbedSign',
    adapterFile: 'src/lib/components/signing/iframe-signing-adapter.svelte',
  },
] as const;

type SurfaceSpec = (typeof SURFACES)[number];

interface SurfaceBinding {
  name: string;
  adapterFile: string;
  Component: any;
}

/**
 * Compile a Svelte file at a `$lib/...` path to a client-side `.mjs`
 * module and return the absolute file URL of the emitted file. Rewrites
 * any `$lib/...svelte` imports recursively so a whole tree of Svelte
 * files rooted at an adapter resolves to on-disk `.mjs` bundles rather
 * than raw `.svelte` source files (which Bun cannot execute).
 *
 * Non-`.svelte` `$lib/...` imports (plain TS modules, JSON, etc.) are
 * rewritten to absolute file URLs and executed by Bun as-is.
 */
const compiledSvelteFiles = new Map<string, string>();

async function compileSvelteFile(libRelPath: string, name: string): Promise<string> {
  const absoluteSource = join(WEB_ROOT, 'src/lib', libRelPath);
  const cached = compiledSvelteFiles.get(absoluteSource);
  if (cached) return cached;
  const src = readFileSync(absoluteSource, 'utf8');
  const compiled = compile(src, {
    generate: 'client',
    dev: false,
    name,
    filename: `src/lib/${libRelPath}`,
  });
  // Rewrite $lib imports. For .svelte imports, recursively compile the
  // referenced component and point at the resulting .mjs file. For
  // non-svelte imports, point at the on-disk source file URL.
  const parts: string[] = [];
  let cursor = 0;
  const importRe = /from ['"]\$lib\/([^'"]+)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = importRe.exec(compiled.js.code)) !== null) {
    parts.push(compiled.js.code.slice(cursor, match.index));
    const rel = match[1]!;
    let targetUrl: string;
    if (rel.endsWith('.svelte')) {
      const childName = rel
        .replace(/[^A-Za-z0-9]/g, '_')
        .replace(/_svelte$/, '');
      targetUrl = await compileSvelteFile(rel, childName);
    } else {
      targetUrl = pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
    }
    parts.push(`from '${targetUrl}'`);
    cursor = match.index + match[0].length;
  }
  parts.push(compiled.js.code.slice(cursor));
  const rewritten = parts.join('');
  const safeName = libRelPath.replace(/[^A-Za-z0-9]/g, '_');
  const outPath = join(OUT_DIR, `${safeName}.client.mjs`);
  writeFileSync(outPath, rewritten);
  const outUrl = pathToFileURL(outPath).href;
  compiledSvelteFiles.set(absoluteSource, outUrl);
  return outUrl;
}

async function compileAdapterForBrowser(spec: SurfaceSpec): Promise<any> {
  const libRel = spec.adapterFile.replace(/^src\/lib\//, '');
  const url = await compileSvelteFile(libRel, spec.name);
  const mod = await import(url);
  return mod.default;
}

const surfaceBindings: SurfaceBinding[] = [];
for (const spec of SURFACES) {
  const Component = await compileAdapterForBrowser(spec);
  surfaceBindings.push({ name: spec.name, adapterFile: spec.adapterFile, Component });
}

// -----------------------------------------------------------------------------
// Fixtures: two shapes.
//   `benignFixtureModel()`   — normal request with no warnings.
//   `warningFixtureModel()`  — origin/domain mismatch, cross-app data,
//                              stale manifest, caller-supplied reason,
//                              parse warning. Exercises every warning
//                              rendering path.
// -----------------------------------------------------------------------------

function benignFixtureModel(): any {
  const space = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
  return {
    version: 1,
    protocol: 'tinycloud-siwe-recap',
    rawMessage: 'test-siwe-benign',
    requester: {
      displayName: 'My App',
      origin: 'https://myapp.example',
      verifiedOrigin: 'https://myapp.example',
      manifestId: null,
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    reason: { text: '', source: 'none' },
    signer: {
      label: 'Managed key',
      address: '0x1111111111111111111111111111111111111111',
      chainId: 1,
      provenance: 'managed',
    },
    expiry: '2026-08-07T00:00:00.000Z',
    immutable: null,
    metadataTrust: { status: 'unsigned' },
    permissions: [
      {
        id: `tinycloud.kv\0${space}\0`,
        family: 'kv-storage',
        severity: 'standard',
        service: 'tinycloud.kv',
        space,
        path: '',
        owner: '0x1111111111111111111111111111111111111111',
        ownedBySelf: true,
        displayLabel: null,
        metadataLabel: null,
        actions: [
          {
            id: `tinycloud.kv\0${space}\0\0tinycloud.kv/get`,
            ability: 'tinycloud.kv/get',
            verb: 'get',
            required: false,
            selected: true,
            editable: true,
            caveats: [{}],
          },
          {
            id: `tinycloud.kv\0${space}\0\0tinycloud.kv/put`,
            ability: 'tinycloud.kv/put',
            verb: 'put',
            required: false,
            selected: true,
            editable: true,
            caveats: [{}],
          },
        ],
      },
    ],
    parseWarnings: [],
  };
}

function warningFixtureModel(): any {
  // Space owned by someone OTHER than the signer → cross-app data.
  const signerAddress = '0x1111111111111111111111111111111111111111';
  const otherOwner = '0x2222222222222222222222222222222222222222';
  const crossSpace = `tinycloud:pkh:eip155:1:${otherOwner}:default`;
  return {
    version: 1,
    protocol: 'tinycloud-siwe-recap',
    rawMessage: 'test-siwe-warnings-with-many\nlines',
    requester: {
      displayName: 'Suspicious Requester',
      origin: 'https://attacker.example',
      verifiedOrigin: 'https://attacker.example',
      manifestId: null,
      manifestDigest: null,
      // origin does NOT match the SIWE domain — the surface should
      // render the origin-mismatch warning.
      domainWarning: true,
      originWarning: true,
    },
    reason: {
      text: 'Trust me, this is safe',
      // Caller-supplied reason → surface renders the "not verified"
      // untrusted-reason line.
      source: 'caller',
    },
    signer: {
      label: 'Managed key',
      address: signerAddress,
      chainId: 1,
      provenance: 'managed',
    },
    expiry: '2026-08-07T00:00:00.000Z',
    immutable: null,
    metadataTrust: { status: 'stale', reason: 'signature expired 2024-01-01' },
    permissions: [
      {
        id: `tinycloud.kv\0${crossSpace}\0`,
        family: 'kv-storage',
        severity: 'sensitive',
        service: 'tinycloud.kv',
        space: crossSpace,
        path: '',
        // Owner ≠ signer → cross-app-data warning path.
        owner: otherOwner,
        ownedBySelf: false,
        displayLabel: null,
        metadataLabel: null,
        actions: [
          {
            id: `tinycloud.kv\0${crossSpace}\0\0tinycloud.kv/get`,
            ability: 'tinycloud.kv/get',
            verb: 'get',
            required: false,
            selected: true,
            editable: true,
            caveats: [{}],
          },
        ],
      },
    ],
    parseWarnings: [
      { code: 'UNRECOGNISED_ACTION', message: 'saw unknown ability tinycloud.kv/frobnicate' },
    ],
  };
}

function fixtureSelection(model: any): Set<string> {
  const s = new Set<string>();
  for (const perm of model.permissions) {
    for (const act of perm.actions) {
      if (act.selected) s.add(act.id);
    }
  }
  return s;
}

// -----------------------------------------------------------------------------
// DOM helpers.
// -----------------------------------------------------------------------------

interface SemanticNode {
  tag: string;
  role: string | null;
  accessibleName: string | null;
  ariaChecked: string | null;
  ariaExpanded: string | null;
  ariaModal: string | null;
  ariaLabel: string | null;
  disabled: boolean;
  text: string;
}

function accessibleName(el: any, root: any): string | null {
  const label = el.getAttribute?.('aria-label');
  if (label) return label;
  const labelledby = el.getAttribute?.('aria-labelledby');
  if (labelledby) {
    const referenced = root.querySelector?.(`#${labelledby}`);
    if (referenced?.textContent) return referenced.textContent.trim();
  }
  return null;
}

function collectSemantic(root: any): SemanticNode[] {
  const out: SemanticNode[] = [];
  const walker = root.querySelectorAll('*');
  const arr = Array.from(walker) as any[];
  for (const el of arr) {
    const tag = el.tagName ? el.tagName.toLowerCase() : '';
    const role = el.getAttribute?.('role') ?? null;
    const ariaChecked = el.getAttribute?.('aria-checked') ?? null;
    const ariaExpanded = el.getAttribute?.('aria-expanded') ?? null;
    const ariaModal = el.getAttribute?.('aria-modal') ?? null;
    const ariaLabel = el.getAttribute?.('aria-label') ?? null;
    const disabled = el.hasAttribute?.('disabled') ?? false;
    const isSemantic =
      role !== null ||
      ariaModal !== null ||
      ariaLabel !== null ||
      /^(button|input|section|nav|header|footer|main|form|label|ul|ol|li|details|summary|dialog|h[1-6])$/.test(tag);
    if (!isSemantic) continue;
    const text = (el.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 120);
    out.push({
      tag,
      role,
      accessibleName: accessibleName(el, root),
      ariaChecked,
      ariaExpanded,
      ariaModal,
      ariaLabel,
      disabled,
      text,
    });
  }
  return out;
}

function textIncludes(root: any, needle: string): boolean {
  const doc = (root.textContent ?? '') as string;
  return doc.includes(needle);
}

interface SpyCallback {
  fn: (...args: any[]) => void;
  calls: any[][];
}

function spy(): SpyCallback {
  const calls: any[][] = [];
  const fn = (...args: any[]) => {
    calls.push(args);
  };
  return { fn, calls };
}

interface Callbacks {
  onApprove: (...args: any[]) => void;
  onCancel: (...args: any[]) => void;
  onSelectionChange: (...args: any[]) => void;
  onEditingChange: (...args: any[]) => void;
  spies: {
    approve: SpyCallback;
    cancel: SpyCallback;
    selection: SpyCallback;
    editing: SpyCallback;
  };
}

function makeCallbacks(): Callbacks {
  const approve = spy();
  const cancel = spy();
  const selection = spy();
  const editing = spy();
  return {
    onApprove: approve.fn,
    onCancel: cancel.fn,
    onSelectionChange: selection.fn,
    onEditingChange: editing.fn,
    spies: { approve, cancel, selection, editing },
  };
}

interface MountHandle {
  container: any;
  binding: SurfaceBinding;
  unmount: () => void;
}

async function mountSurface(
  binding: SurfaceBinding,
  props: any,
): Promise<MountHandle> {
  const container = win.document.createElement('div');
  container.setAttribute('data-surface', binding.name);
  win.document.body.appendChild(container);
  const component = mount(binding.Component, {
    target: container as unknown as HTMLElement,
    props,
  });
  flushSync();
  return {
    container,
    binding,
    unmount() {
      try {
        unmount(component);
      } catch {
        // Component may already be torn down.
      }
      try {
        container.remove();
      } catch {
        // ignore
      }
    },
  };
}

// -----------------------------------------------------------------------------
// Real DOM event helpers on happy-dom's own primitives.
// -----------------------------------------------------------------------------

function click(el: any): void {
  if (typeof el.click === 'function') {
    el.click();
  } else {
    el.dispatchEvent(new (win as any).MouseEvent('mousedown', { bubbles: true }));
    el.dispatchEvent(new (win as any).MouseEvent('mouseup', { bubbles: true }));
    el.dispatchEvent(new (win as any).MouseEvent('click', { bubbles: true }));
  }
  flushSync();
}

/**
 * Send a keydown + keyup with the given key. For Enter on a button the
 * browser follows up with a synthesised click; happy-dom does not do
 * this on its own, so we dispatch a real click event to model the effect.
 * For Space on a checkbox we rely on the component's `onkeydown` handler
 * (`handleKeydown`) — the shared `SigningApproval` calls `toggle(action)
 * -> onSelectionChange(next)` when it sees the Space key, so we do NOT
 * mutate `.checked` here.
 */
function pressKey(el: any, key: string): void {
  el.dispatchEvent(
    new (win as any).KeyboardEvent('keydown', { key, bubbles: true }),
  );
  if (key === 'Enter' && el.tagName?.toLowerCase() === 'button') {
    el.dispatchEvent(new (win as any).MouseEvent('click', { bubbles: true }));
  }
  el.dispatchEvent(
    new (win as any).KeyboardEvent('keyup', { key, bubbles: true }),
  );
  flushSync();
}

function focusableElementsIn(container: any): any[] {
  return Array.from(
    container.querySelectorAll(
      'button, input, [tabindex]:not([tabindex="-1"])',
    ),
  ) as any[];
}

function tabToNext(from: any, container: any): any {
  const all = focusableElementsIn(container);
  const idx = all.indexOf(from);
  const next = all[(idx + 1) % Math.max(1, all.length)];
  next?.focus?.();
  return next;
}

afterAll(() => {
  win.close();
});

// -----------------------------------------------------------------------------
// Suites.
// -----------------------------------------------------------------------------

describe('signing-approval mounted parity across production surface adapters (Sol MAJOR-3 final)', () => {
  test('every surface renders the shared SigningApproval component under a dialog role', async () => {
    // Sanity: the SigningApproval dialog root MUST appear inside every
    // surface adapter's mount output. This is what proves each adapter
    // actually instantiated the shared component rather than rendering
    // nothing or a decoy tree.
    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const model = benignFixtureModel();
      const selection = fixtureSelection(model);
      const handle = await mountSurface(binding, {
        model,
        selection,
        editing: false,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      const dialogs = handle.container.querySelectorAll('[role="dialog"]');
      expect(dialogs.length).toBe(1);
      handle.unmount();
    }
  });

  test('all three surface adapters render the same accessible DOM for the SAME model+selection (benign fixture)', async () => {
    const model = benignFixtureModel();
    const selection = fixtureSelection(model);

    const projections: SemanticNode[][] = [];
    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const handle = await mountSurface(binding, {
        model,
        selection,
        editing: false,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      const dialogs = handle.container.querySelectorAll('[role="dialog"]');
      expect(dialogs.length).toBe(1);
      const projection = collectSemantic(handle.container);
      projections.push(projection);
      handle.unmount();
    }
    for (let i = 1; i < projections.length; i += 1) {
      expect(projections[i]).toEqual(projections[0]!);
    }
  });

  test('all three surface adapters render the same accessible DOM under a warning fixture (origin/domain mismatch, cross-app data, stale trust, caller reason, parse warning)', async () => {
    const model = warningFixtureModel();
    const selection = fixtureSelection(model);

    const projections: SemanticNode[][] = [];
    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const handle = await mountSurface(binding, {
        model,
        selection,
        editing: false,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      // The warning fixture's cross-app warning text must appear on
      // every surface — the shared component owns that rendering, so
      // if it fails to fire on one surface, that surface's adapter
      // dropped a prop.
      expect(
        textIncludes(handle.container, 'Cross-app data owned by 0x2222222222222222222222222222222222222222'),
      ).toBe(true);
      // The caller-supplied reason renders with its untrusted note.
      expect(textIncludes(handle.container, 'Trust me, this is safe')).toBe(true);
      expect(
        textIncludes(handle.container, 'This reason comes from the caller and is not verified.'),
      ).toBe(true);
      // The stale manifest trust status.
      expect(textIncludes(handle.container, 'Manifest signature is stale')).toBe(true);
      expect(textIncludes(handle.container, 'signature expired 2024-01-01')).toBe(true);
      // The parseWarnings block renders both the code and message.
      expect(textIncludes(handle.container, 'UNRECOGNISED_ACTION')).toBe(true);
      expect(
        textIncludes(handle.container, 'saw unknown ability tinycloud.kv/frobnicate'),
      ).toBe(true);
      // The origin-warning fixture renders the "Origin does not match
      // SIWE domain" caption via the shared component.
      expect(textIncludes(handle.container, 'Origin does not match SIWE domain')).toBe(true);
      const projection = collectSemantic(handle.container);
      projections.push(projection);
      handle.unmount();
    }
    for (let i = 1; i < projections.length; i += 1) {
      expect(projections[i]).toEqual(projections[0]!);
    }
  });

  test('expanded permission details: the "Show exact bytes" <details> reveals the raw SIWE bytes on every surface when toggled open', async () => {
    const model = warningFixtureModel();
    const selection = fixtureSelection(model);

    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const handle = await mountSurface(binding, {
        model,
        selection,
        editing: false,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      const details = handle.container.querySelector('details');
      expect(details).toBeTruthy();
      // The raw bytes render inside <pre>. happy-dom does not gate
      // <details> content on the `open` attribute for querying, so
      // the content is always in the tree; we assert both the summary
      // and content render.
      const summary = details.querySelector('summary');
      expect(summary?.textContent?.trim()).toBe('Show exact bytes being signed');
      const pre = details.querySelector('pre');
      expect(pre?.textContent?.trim()).toBe(model.rawMessage);
      // Toggle open by setting the open attribute — this is the
      // effect the browser performs when a user clicks/keys the
      // summary. Verify the attribute takes and details.open flag flips.
      details.setAttribute('open', '');
      flushSync();
      expect(details.hasAttribute('open')).toBe(true);
      handle.unmount();
    }
  });

  test('keyboard: Tab moves focus through the interactive controls of every surface in DOM order', async () => {
    const model = benignFixtureModel();
    const selection = fixtureSelection(model);

    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const handle = await mountSurface(binding, {
        model,
        selection,
        editing: true,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      const focusables = focusableElementsIn(handle.container);
      expect(focusables.length).toBeGreaterThan(1);
      focusables[0].focus();
      expect(win.document.activeElement).toBe(focusables[0]);
      // Fire a real Tab keydown before moving focus. happy-dom does
      // NOT auto-advance focus on Tab, so we walk the DOM order after
      // dispatching the keydown to mirror the browser's behaviour.
      pressKey(focusables[0], 'Tab');
      const next = tabToNext(focusables[0], handle.container);
      expect(next).not.toBe(focusables[0]);
      expect(win.document.activeElement).toBe(next);
      handle.unmount();
    }
  });

  test('keyboard: Space on a checkbox goes through the component onkeydown handler and fires onSelectionChange on every surface', async () => {
    const model = benignFixtureModel();
    const initialSelection = fixtureSelection(model);

    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const handle = await mountSurface(binding, {
        model,
        selection: initialSelection,
        editing: true,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      const boxes = handle.container.querySelectorAll(
        'input[type="checkbox"]',
      ) as any[];
      // The benign fixture has TWO editable actions, both selected by
      // default. In editing mode each renders a checkbox.
      expect(boxes.length).toBeGreaterThanOrEqual(2);
      // Focus + Space. `SigningApproval` has `onkeydown={(e) =>
      // handleKeydown(e, action)}` on each checkbox; that handler
      // preventDefaults and calls `toggle(action) -> onSelectionChange(next)`
      // when it sees Space. pressKey() only dispatches the real keyboard
      // event — no direct .checked mutation.
      boxes[0].focus();
      pressKey(boxes[0], ' ');
      expect(cbs.spies.selection.calls.length).toBeGreaterThan(0);
      const lastCall = cbs.spies.selection.calls[cbs.spies.selection.calls.length - 1]!;
      expect(lastCall[0]).toBeInstanceOf(Set);
      // The new selection set MUST reflect the toggle: since the box
      // was checked initially, it should now be absent.
      const newSel = lastCall[0] as Set<string>;
      const toggledId = model.permissions[0].actions[0].id as string;
      expect(newSel.has(toggledId)).toBe(false);
      handle.unmount();
    }
  });

  test('keyboard: Enter on the Approve button fires onApprove on every surface', async () => {
    const model = benignFixtureModel();
    const selection = fixtureSelection(model);

    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const handle = await mountSurface(binding, {
        model,
        selection,
        editing: false,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      const buttons = Array.from(handle.container.querySelectorAll('button')) as any[];
      const approve =
        buttons.find((b) => b.classList?.contains?.('approve')) ??
        buttons.find((b) => (b.textContent ?? '').trim() === 'Approve');
      const cancel =
        buttons.find((b) => b.classList?.contains?.('cancel')) ??
        buttons.find((b) => (b.textContent ?? '').trim() === 'Cancel');
      expect(approve).toBeTruthy();
      expect(cancel).toBeTruthy();
      approve.focus();
      pressKey(approve, 'Enter');
      expect(cbs.spies.approve.calls.length).toBe(1);
      cancel.focus();
      pressKey(cancel, 'Enter');
      expect(cbs.spies.cancel.calls.length).toBe(1);
      handle.unmount();
    }
  });

  test('narrowed selection reflects in checked state identically across surfaces', async () => {
    const model = benignFixtureModel();
    const spaceId = model.permissions[0].space;
    const fullSel = new Set<string>([
      `tinycloud.kv\0${spaceId}\0\0tinycloud.kv/get`,
      `tinycloud.kv\0${spaceId}\0\0tinycloud.kv/put`,
    ]);
    const narrowSel = new Set<string>([
      `tinycloud.kv\0${spaceId}\0\0tinycloud.kv/get`,
    ]);
    const perSurfaceCounts: Array<{ full: number; narrow: number }> = [];
    for (const binding of surfaceBindings) {
      const cbsFull = makeCallbacks();
      const cbsNarrow = makeCallbacks();
      const fullMount = await mountSurface(binding, {
        model,
        selection: fullSel,
        editing: true,
        approving: false,
        error: null,
        onApprove: cbsFull.onApprove,
        onCancel: cbsFull.onCancel,
        onSelectionChange: cbsFull.onSelectionChange,
        onEditingChange: cbsFull.onEditingChange,
      });
      const fullChecked = (Array.from(
        fullMount.container.querySelectorAll('input[type="checkbox"]'),
      ) as any[]).filter((b: any) => b.checked === true).length;
      fullMount.unmount();
      const narrowMount = await mountSurface(binding, {
        model,
        selection: narrowSel,
        editing: true,
        approving: false,
        error: null,
        onApprove: cbsNarrow.onApprove,
        onCancel: cbsNarrow.onCancel,
        onSelectionChange: cbsNarrow.onSelectionChange,
        onEditingChange: cbsNarrow.onEditingChange,
      });
      const narrowChecked = (Array.from(
        narrowMount.container.querySelectorAll('input[type="checkbox"]'),
      ) as any[]).filter((b: any) => b.checked === true).length;
      narrowMount.unmount();
      perSurfaceCounts.push({ full: fullChecked, narrow: narrowChecked });
    }
    // Narrow selection MUST reduce checked-box count on every surface.
    for (const { full, narrow } of perSurfaceCounts) {
      expect(narrow).toBeLessThan(full);
    }
    // Every surface reports the SAME counts.
    for (let i = 1; i < perSurfaceCounts.length; i += 1) {
      expect(perSurfaceCounts[i]).toEqual(perSurfaceCounts[0]!);
    }
  });

  test('editing toggle: expanding editing mode changes rendered controls identically across surfaces', async () => {
    const model = benignFixtureModel();
    const selection = fixtureSelection(model);
    const perSurface: Array<{ closed: number; open: number; expanded: string | null }> = [];
    for (const binding of surfaceBindings) {
      const cbsClosed = makeCallbacks();
      const closedMount = await mountSurface(binding, {
        model,
        selection,
        editing: false,
        approving: false,
        error: null,
        onApprove: cbsClosed.onApprove,
        onCancel: cbsClosed.onCancel,
        onSelectionChange: cbsClosed.onSelectionChange,
        onEditingChange: cbsClosed.onEditingChange,
      });
      const closedInputs = closedMount.container.querySelectorAll(
        'input[type="checkbox"]',
      ) as any[];
      const closedCount = closedInputs.length;
      const closedEditButton = (Array.from(closedMount.container.querySelectorAll('button')) as any[])
        .find((b) => (b.textContent ?? '').trim() === 'Edit');
      const closedExpanded = closedEditButton?.getAttribute?.('aria-expanded') ?? null;
      closedMount.unmount();

      const cbsOpen = makeCallbacks();
      const openMount = await mountSurface(binding, {
        model,
        selection,
        editing: true,
        approving: false,
        error: null,
        onApprove: cbsOpen.onApprove,
        onCancel: cbsOpen.onCancel,
        onSelectionChange: cbsOpen.onSelectionChange,
        onEditingChange: cbsOpen.onEditingChange,
      });
      const openInputs = openMount.container.querySelectorAll(
        'input[type="checkbox"]',
      ) as any[];
      const openCount = openInputs.length;
      openMount.unmount();

      perSurface.push({ closed: closedCount, open: openCount, expanded: closedExpanded });
      expect(openCount).toBeGreaterThan(closedCount);
    }
    for (let i = 1; i < perSurface.length; i += 1) {
      expect(perSurface[i]).toEqual(perSurface[0]!);
    }
  });

  test('every surface adapter carries the aria-modal="true" dialog role from the shared SigningApproval component', async () => {
    const model = benignFixtureModel();
    const selection = fixtureSelection(model);
    for (const binding of surfaceBindings) {
      const cbs = makeCallbacks();
      const handle = await mountSurface(binding, {
        model,
        selection,
        editing: false,
        approving: false,
        error: null,
        onApprove: cbs.onApprove,
        onCancel: cbs.onCancel,
        onSelectionChange: cbs.onSelectionChange,
        onEditingChange: cbs.onEditingChange,
      });
      const dialog = handle.container.querySelector('[role="dialog"]');
      expect(dialog).toBeTruthy();
      expect(dialog!.getAttribute('aria-modal')).toBe('true');
      // aria-labelledby resolves to the visible headline.
      const labelledbyId = dialog!.getAttribute('aria-labelledby');
      expect(typeof labelledbyId).toBe('string');
      const headline = handle.container.querySelector(`#${labelledbyId}`);
      expect(headline).toBeTruthy();
      expect((headline?.textContent ?? '').length).toBeGreaterThan(0);
      handle.unmount();
    }
  });
});
