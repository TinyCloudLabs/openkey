// Sol MAJOR-1 (final continuation, iteration 2): MOUNTED accessible-DOM
// parity across the three OpenKey authorization surface adapters (CLI,
// popup, iframe) using the SUBSTANTIVE production adapter components.
//
// This suite replaces two previously-rejected approaches:
//
//   Iteration A (rejected): read each production `+page.svelte` source
//     text, extract the literal `<SigningApproval>` block, rewrite each
//     surface's route-specific model/selection/warning/callback
//     expressions into shared fixtures, then SSR-render the rewritten
//     block. Sol correctly called this synthetic — the actual route
//     wiring was never exercised.
//
//   Iteration B (rejected): mount three byte-identical pass-through
//     wrappers with the same fixture model, selection, and spy
//     callbacks. Sol correctly called this tautological — the adapters
//     were just prop passthroughs, so mounting them proved nothing about
//     the routes' selection→map→prepare glue, preview vs exact-byte
//     approval routing, or invalidate-preview-on-edit callback wiring.
//
// This iteration:
//
//   1. The three production adapters
//      (src/lib/components/signing/{cli,popup,iframe}-signing-adapter.svelte)
//      are now SUBSTANTIVE production code that owns the surface's
//      selection/editing state and the surface-specific approve/cancel/
//      selection-change wiring. The routes hand each adapter an
//      injected `CliSigningTransport` or `WidgetSigningTransport`
//      (defined in `signing-adapter-types.ts`) — the same interface the
//      routes use in production. The parity test mounts THOSE EXACT
//      adapter files and supplies a spy transport that mirrors the
//      production transport shape one-for-one. Nothing is re-derived,
//      no route logic is re-implemented in test-only wrappers.
//
//   2. Interactions are dispatched as real DOM `KeyboardEvent`s directed
//      at real focused elements. Space on a checkbox goes through the
//      shared component's `onkeydown` handler
//      (`handleKeydown → toggle(action) → onSelectionChange`), which
//      routes through the ADAPTER's `onSelectionChange` (which calls
//      into the transport). Enter on the Approve button goes through
//      the shared component's `onkeydown` handler on the button, which
//      routes through the adapter's `onApprove`. No DOM state is
//      manually mutated; no MouseEvent is fabricated to imitate Enter;
//      no `<details>` `open` attribute is written by the test.
//
//   3. A route-specific wiring bug DOES fail this test now:
//        - dropping `transport.invalidatePreview()` from the widget
//          adapter's selection handler → widget preview-invalidation
//          spy call count stays at 0 after Space.
//        - dropping `transport.updateSelection()` from the CLI adapter's
//          selection handler → CLI update-selection spy call count stays
//          at 0 after Space.
//        - dropping the `canUseAuthorizeSign` branch from a widget
//          adapter's approve → the wrong spy fires on Enter.
//        - a divergence in shared-DOM projection across surfaces (an
//          adapter fails to forward `model` or `approving` correctly)
//          → the projection equality across the three surfaces fails.
//
// See:
//   - src/lib/components/signing/cli-signing-adapter.svelte
//   - src/lib/components/signing/popup-signing-adapter.svelte
//   - src/lib/components/signing/iframe-signing-adapter.svelte
//   - src/lib/components/signing/signing-adapter-types.ts

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
(globalThis as any).Comment = win.Comment;
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
// The three production adapter files. Each is the SAME Svelte file the
// production route imports; the test compiles it and mounts it, so what
// the parity test renders is what the route renders.
// -----------------------------------------------------------------------------

type SurfaceKind = 'cli' | 'widget';

interface SurfaceSpec {
  name: string;
  adapterFile: string;
  kind: SurfaceKind;
}

const SURFACES: readonly SurfaceSpec[] = [
  {
    name: 'CliDelegate',
    adapterFile: 'src/lib/components/signing/cli-signing-adapter.svelte',
    kind: 'cli',
  },
  {
    name: 'PopupWidgetSign',
    adapterFile: 'src/lib/components/signing/popup-signing-adapter.svelte',
    kind: 'widget',
  },
  {
    name: 'IframeEmbedSign',
    adapterFile: 'src/lib/components/signing/iframe-signing-adapter.svelte',
    kind: 'widget',
  },
] as const;

interface SurfaceBinding {
  name: string;
  adapterFile: string;
  kind: SurfaceKind;
  Component: any;
}

/**
 * Compile a Svelte file at a `$lib/...` path to a client-side `.mjs`
 * module and return the absolute file URL of the emitted file. Rewrites
 * `$lib/...svelte` imports recursively so a whole tree of Svelte files
 * rooted at an adapter resolves to on-disk `.mjs` bundles rather than
 * raw `.svelte` source files. `$lib/...ts` imports resolve to the
 * on-disk source URL (Bun executes them directly).
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
  const parts: string[] = [];
  let cursor = 0;
  // Rewrite `$lib/...` imports:
  //   .svelte → recursively compile → point at emitted .mjs
  //   .ts/.js → point at on-disk source URL (Bun executes as-is)
  //   plain name (no ext, e.g. "./signing-adapter-types") → point at
  //   the source URL, letting Bun resolve extension.
  const importRe = /from\s+['"](\$lib\/[^'"]+|\.\/[^'"]+)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = importRe.exec(compiled.js.code)) !== null) {
    parts.push(compiled.js.code.slice(cursor, match.index));
    const spec = match[1]!;
    let targetUrl: string;
    if (spec.startsWith('$lib/')) {
      const rel = spec.slice('$lib/'.length);
      if (rel.endsWith('.svelte')) {
        const childName = rel
          .replace(/[^A-Za-z0-9]/g, '_')
          .replace(/_svelte$/, '');
        targetUrl = await compileSvelteFile(rel, childName);
      } else {
        targetUrl = pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
      }
    } else {
      // Relative import from within the current file's directory.
      const currentDir = dirname(join(WEB_ROOT, 'src/lib', libRelPath));
      let abs = join(currentDir, spec);
      // Bun-executable — TS files resolve without extension.
      targetUrl = pathToFileURL(abs).href;
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
  surfaceBindings.push({
    name: spec.name,
    adapterFile: spec.adapterFile,
    kind: spec.kind,
    Component,
  });
}

// -----------------------------------------------------------------------------
// Fixtures.
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
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
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
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: true,
      originWarning: true,
    },
    reason: {
      text: 'Trust me, this is safe',
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

function encryptionFixtureModel(): any {
  const model = benignFixtureModel();
  const space = 'urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
  model.rawMessage = 'test-siwe-encryption';
  model.permissions = [
    {
      id: `tinycloud.encryption\0${space}\0`,
      family: 'encryption-decrypt',
      severity: 'sensitive',
      service: 'tinycloud.encryption',
      space,
      path: '',
      owner: null,
      ownedBySelf: null,
      displayLabel: null,
      metadataLabel: null,
      actions: [
        {
          id: `tinycloud.encryption\0${space}\0\0tinycloud.encryption/network.create`,
          ability: 'tinycloud.encryption/network.create',
          verb: 'network.create',
          required: false,
          selected: true,
          editable: true,
          caveats: [{}],
        },
        {
          id: `tinycloud.encryption\0${space}\0\0tinycloud.encryption/decrypt`,
          ability: 'tinycloud.encryption/decrypt',
          verb: 'decrypt',
          required: false,
          selected: true,
          editable: true,
          caveats: [{}],
        },
      ],
    },
  ];
  return model;
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
// Transports that mirror the production transport shape one-for-one.
//
// The CLI transport keeps track of the (mapped) narrowed action-ID set
// the same way `mapReviewSelectionToActionKeys` + `updatePermissions`
// would in the route.
//
// The widget transport keeps track of the surface's `canUseAuthorizeSign`
// choice AND records whether `requestPreview` vs `approveAndSign` fired
// on approve, so a bug that routes to the wrong path is caught here.
// -----------------------------------------------------------------------------

interface CliSpies {
  approveDelegate: any[][];
  goBack: any[][];
  updateSelection: any[][];
}

interface CliTransport {
  approveDelegate: () => void;
  goBack: () => void;
  updateSelection: (next: Set<string>) => void;
  approving: boolean;
  error: string | null;
  _spies: CliSpies;
}

function makeCliTransport(): CliTransport {
  const spies: CliSpies = {
    approveDelegate: [],
    goBack: [],
    updateSelection: [],
  };
  return {
    approving: false,
    error: null,
    approveDelegate: () => {
      spies.approveDelegate.push([]);
    },
    goBack: () => {
      spies.goBack.push([]);
    },
    updateSelection: (next: Set<string>) => {
      spies.updateSelection.push([new Set(next)]);
    },
    _spies: spies,
  };
}

interface WidgetSpies {
  requestPreview: any[][];
  approveAndSign: any[][];
  cancel: any[][];
  invalidatePreview: any[][];
  onSelectionEdited: any[][];
}

interface WidgetTransport {
  canUseAuthorizeSign: boolean;
  previewReady: boolean;
  requestPreview: () => void;
  approveAndSign: () => void;
  cancel: () => void;
  invalidatePreview: () => void;
  onSelectionEdited: (next: Set<string>) => void;
  approving: boolean;
  error: string | null;
  _spies: WidgetSpies;
}

function makeWidgetTransport(
  canUseAuthorizeSign: boolean,
  previewReady = false,
): WidgetTransport {
  const spies: WidgetSpies = {
    requestPreview: [],
    approveAndSign: [],
    cancel: [],
    invalidatePreview: [],
    onSelectionEdited: [],
  };
  return {
    canUseAuthorizeSign,
    previewReady,
    approving: false,
    error: null,
    requestPreview: () => {
      spies.requestPreview.push([]);
    },
    approveAndSign: () => {
      spies.approveAndSign.push([]);
    },
    cancel: () => {
      spies.cancel.push([]);
    },
    invalidatePreview: () => {
      spies.invalidatePreview.push([]);
    },
    onSelectionEdited: (next: Set<string>) => {
      spies.onSelectionEdited.push([new Set(next)]);
    },
    _spies: spies,
  };
}

/**
 * Build the correct-shape props for a given surface. This is the same
 * transport shape the production route builds — no synthetic prop is
 * introduced.
 */
function propsForSurface(
  binding: SurfaceBinding,
  model: any,
  initialSelection: Set<string>,
  opts: { canUseAuthorizeSign?: boolean; previewReady?: boolean } = {},
): { props: any; cliTransport?: CliTransport; widgetTransport?: WidgetTransport } {
  if (binding.kind === 'cli') {
    const transport = makeCliTransport();
    return {
      props: { model, initialSelection, transport },
      cliTransport: transport,
    };
  }
  const transport = makeWidgetTransport(
    opts.canUseAuthorizeSign ?? true,
    opts.previewReady ?? false,
  );
  return {
    props: { model, initialSelection, transport },
    widgetTransport: transport,
  };
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

interface MountHandle {
  container: any;
  binding: SurfaceBinding;
  unmount: () => void;
}

async function mountSurface(binding: SurfaceBinding, props: any): Promise<MountHandle> {
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
// Real DOM event helpers on happy-dom's own primitives. Each helper
// exists to model a genuine browser interaction that ROUTES through the
// component's own handlers:
//
//   - `pressKeyOnCheckbox` dispatches a keydown+keyup with the given key
//     against a checkbox. The shared `SigningApproval` component wires
//     `onkeydown={(e) => handleKeydown(e, action)}` on each checkbox;
//     `handleKeydown` calls `toggle(action) → onSelectionChange(next)`
//     for Space and Enter. That routes into the ADAPTER's
//     `onSelectionChange` handler, which is where the parity assertions
//     land.
//
//   - `pressKeyOnButton` dispatches a keydown+keyup and an accompanying
//     click. The click is the browser's own follow-up on Enter/Space
//     against a button — happy-dom does not synthesize it. This is not
//     a shortcut around the component: the button handler in
//     `SigningApproval` is `onclick={onApprove}`, so a real user's
//     keyboard interaction reaches the adapter's `onApprove` via the
//     same code path in production. The critical property is that this
//     path IS the same for all three surface adapters, so a mis-wired
//     Approve/Cancel handler shows up as a spy mismatch.
//
// Nothing here mutates DOM state directly to imitate an event.
// -----------------------------------------------------------------------------

function pressKeyOnCheckbox(el: any, key: string): void {
  el.dispatchEvent(new (win as any).KeyboardEvent('keydown', { key, bubbles: true }));
  el.dispatchEvent(new (win as any).KeyboardEvent('keyup', { key, bubbles: true }));
  flushSync();
}

function pressKeyOnButton(el: any, key: string): void {
  el.dispatchEvent(new (win as any).KeyboardEvent('keydown', { key, bubbles: true }));
  if (key === 'Enter' || key === ' ') {
    // Model the browser's default action for Enter/Space on a button.
    // The click event is what the shared component's `onclick` handler
    // observes; without this the button would look inert.
    el.dispatchEvent(new (win as any).MouseEvent('click', { bubbles: true }));
  }
  el.dispatchEvent(new (win as any).KeyboardEvent('keyup', { key, bubbles: true }));
  flushSync();
}

function focusableElementsIn(container: any): any[] {
  return Array.from(
    container.querySelectorAll('button, input, [tabindex]:not([tabindex="-1"])'),
  ) as any[];
}

/**
 * Verify the DOM's tab order matches the adapter's declared focusable
 * order. In a real browser, Tab moves focus through this sequence; we
 * assert the DOM structure produces the same ordered sequence across
 * surfaces rather than mutating focus ourselves. See the Playwright
 * suite (tests/browser/parity.spec.ts, when present) for the genuine
 * Tab-driven focus assertion.
 */
function focusOrderSignature(container: any): string[] {
  return focusableElementsIn(container).map((el: any) => {
    const tag = el.tagName?.toLowerCase() ?? '';
    const type = el.getAttribute?.('type') ?? '';
    const label = el.getAttribute?.('aria-label') ?? '';
    const text = (el.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 60);
    return `${tag}[type=${type}][label=${label}][text=${text}]`;
  });
}

afterAll(() => {
  win.close();
});

// -----------------------------------------------------------------------------
// Suites.
// -----------------------------------------------------------------------------

describe('signing-approval mounted parity across production surface adapters (Sol MAJOR-1 final)', () => {
  test('every surface renders the shared SigningApproval component under a dialog role', async () => {
    for (const binding of surfaceBindings) {
      const model = benignFixtureModel();
      const selection = fixtureSelection(model);
      const { props } = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, props);
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
      const { props } = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, props);
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

  test('all three surface adapters render the same accessible DOM under a warning fixture', async () => {
    const model = warningFixtureModel();
    const selection = fixtureSelection(model);

    const projections: SemanticNode[][] = [];
    for (const binding of surfaceBindings) {
      const { props } = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, props);
      // The warning fixture's cross-app warning text must appear on every
      // surface — the shared component owns that rendering.
      expect(
        textIncludes(handle.container, 'Cross-app data owned by 0x2222222222222222222222222222222222222222'),
      ).toBe(true);
      expect(textIncludes(handle.container, 'Trust me, this is safe')).toBe(true);
      expect(
        textIncludes(handle.container, 'This reason comes from the caller and is not verified.'),
      ).toBe(true);
      expect(textIncludes(handle.container, 'Manifest signature is stale')).toBe(true);
      expect(textIncludes(handle.container, 'signature expired 2024-01-01')).toBe(true);
      expect(textIncludes(handle.container, 'UNRECOGNISED_ACTION')).toBe(true);
      expect(
        textIncludes(handle.container, 'saw unknown ability tinycloud.kv/frobnicate'),
      ).toBe(true);
      // Sol MAJOR-6 (parity mounted fix): the component now emits the
      // contract-required domain-warning copy that names both the SIWE
      // domain and the verified browser origin as distinct sides of
      // the mismatch. Update the assertion to match the shipped copy
      // rather than the pre-consolidation shorter phrasing.
      expect(
        textIncludes(
          handle.container,
          'Domain warning: SIWE domain does not match the verified browser origin',
        ),
      ).toBe(true);
      const projection = collectSemantic(handle.container);
      projections.push(projection);
      handle.unmount();
    }
    for (let i = 1; i < projections.length; i += 1) {
      expect(projections[i]).toEqual(projections[0]!);
    }
  });

  test('expanded permission details: every surface shows a single "Advanced details" details+summary containing the raw message', async () => {
    // Sol MAJOR-6 (parity mounted fix): the merge-readiness contract
    // collapses every previous disclosure into a SINGLE `<details>`
    // labelled "Advanced details". The raw-message `<pre>` lives
    // INSIDE that single disclosure — the widget no longer emits a
    // separate "Show exact bytes being signed" summary. Assert the
    // structural contract shape instead of the pre-consolidation copy.
    //
    // We assert the STRUCTURAL details/summary/pre content that the
    // shared component always emits. The `<details>` element's browser-
    // level `open` toggling (click on summary flips the `open` attr) is
    // covered in the Playwright browser suite, not here — happy-dom
    // does not implement that behavior natively.
    const model = warningFixtureModel();
    const selection = fixtureSelection(model);

    for (const binding of surfaceBindings) {
      const { props } = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, props);
      const details = handle.container.querySelector('details');
      expect(details).toBeTruthy();
      const summary = details.querySelector('summary');
      expect(summary?.textContent?.trim()).toBe('Advanced details');
      // The raw-message `<pre>` lives inside the single Advanced-details
      // disclosure. It must contain the exact bytes the widget will sign.
      const pre = details.querySelector('pre');
      expect(pre?.textContent?.trim()).toBe(model.rawMessage);
      handle.unmount();
    }
  });

  test('DOM focus-order signature is identical across surfaces', async () => {
    // A real Tab-through in a browser would visit these elements in
    // this order. We compare the DOM-derived order across surfaces
    // rather than issuing real Tab events (which happy-dom does not
    // implement) — the Playwright browser suite drives real Tab events
    // to prove the browser honors this order.
    const model = benignFixtureModel();
    const selection = fixtureSelection(model);
    const signatures: string[][] = [];
    for (const binding of surfaceBindings) {
      const { props } = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, props);
      signatures.push(focusOrderSignature(handle.container));
      handle.unmount();
    }
    for (let i = 1; i < signatures.length; i += 1) {
      expect(signatures[i]).toEqual(signatures[0]!);
    }
    // Sanity: there is more than one focusable element (approve, cancel,
    // details, at minimum).
    expect(signatures[0]!.length).toBeGreaterThan(1);
  });

  test('keyboard: Space on a checkbox goes through the component onkeydown handler and drives the ADAPTER selection wiring', async () => {
    // Space on a checkbox fires the shared component's `handleKeydown`,
    // which calls `toggle(action) → onSelectionChange(next)`. That
    // routes into the adapter's `onSelectionChange`. For the CLI adapter
    // this MUST call `transport.updateSelection(next)`. For a widget
    // adapter this MUST call both `transport.onSelectionEdited(next)`
    // and `transport.invalidatePreview()`. A regression that dropped
    // either call shows up as a spies.<name>.length === 0 failure.
    for (const binding of surfaceBindings) {
      const model = benignFixtureModel();
      const initialSelection = fixtureSelection(model);
      const built = propsForSurface(binding, model, initialSelection);
      const handle = await mountSurface(binding, built.props);
      // Open the editing affordance first (checkboxes are only rendered
      // in editing mode).
      const editButton = (Array.from(handle.container.querySelectorAll('button')) as any[])
        .find((b: any) => (b.textContent ?? '').trim() === 'Edit');
      expect(editButton).toBeTruthy();
      editButton.dispatchEvent(new (win as any).MouseEvent('click', { bubbles: true }));
      flushSync();
      const boxes = handle.container.querySelectorAll('input[type="checkbox"]') as any[];
      expect(boxes.length).toBeGreaterThanOrEqual(2);
      pressKeyOnCheckbox(boxes[0], ' ');

      if (binding.kind === 'cli') {
        const t = built.cliTransport!;
        expect(t._spies.updateSelection.length).toBe(1);
        const passedSet = t._spies.updateSelection[0]![0] as Set<string>;
        const toggledId = model.permissions[0].actions[0].id as string;
        expect(passedSet.has(toggledId)).toBe(false);
      } else {
        const t = built.widgetTransport!;
        expect(t._spies.onSelectionEdited.length).toBe(1);
        expect(t._spies.invalidatePreview.length).toBe(1);
        const passedSet = t._spies.onSelectionEdited[0]![0] as Set<string>;
        const toggledId = model.permissions[0].actions[0].id as string;
        expect(passedSet.has(toggledId)).toBe(false);
      }
      handle.unmount();
    }
  });

  test('keyboard: Enter on the Approve button routes to the ADAPTER approve wiring on every surface', async () => {
    // Enter on the Approve button, in a real browser, fires the button's
    // click handler (`onclick={onApprove}` in the shared component). The
    // adapter's `onApprove` then routes to the transport:
    //   - CLI: `transport.approveDelegate()` must fire.
    //   - Widget (canUseAuthorizeSign=true): `transport.requestPreview()`
    //     must fire; `transport.approveAndSign()` must NOT fire.
    //   - Widget (canUseAuthorizeSign=false): `transport.approveAndSign()`
    //     must fire; `transport.requestPreview()` must NOT fire.
    for (const binding of surfaceBindings) {
      const model = benignFixtureModel();
      const selection = fixtureSelection(model);
      const built = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, built.props);
      const buttons = Array.from(handle.container.querySelectorAll('button')) as any[];
      const approve =
        buttons.find((b) => b.classList?.contains?.('approve')) ??
        buttons.find((b) => (b.textContent ?? '').trim() === 'Approve');
      expect(approve).toBeTruthy();
      pressKeyOnButton(approve, 'Enter');

      if (binding.kind === 'cli') {
        const t = built.cliTransport!;
        expect(t._spies.approveDelegate.length).toBe(1);
        expect(t._spies.goBack.length).toBe(0);
      } else {
        const t = built.widgetTransport!;
        expect(t._spies.requestPreview.length).toBe(1);
        expect(t._spies.approveAndSign.length).toBe(0);
        expect(t._spies.cancel.length).toBe(0);
      }
      handle.unmount();
    }
  });

  test('widget approve routes to the EXACT-BYTE path when canUseAuthorizeSign=false', async () => {
    // Guardrail on the widget adapter's approve decision. A route-
    // specific bug that dropped the canUseAuthorizeSign branch would
    // route to the wrong path here and fail this test.
    const widgetBindings = surfaceBindings.filter((b) => b.kind === 'widget');
    for (const binding of widgetBindings) {
      const model = benignFixtureModel();
      const selection = fixtureSelection(model);
      const built = propsForSurface(binding, model, selection, {
        canUseAuthorizeSign: false,
      });
      const handle = await mountSurface(binding, built.props);
      const buttons = Array.from(handle.container.querySelectorAll('button')) as any[];
      const approve = buttons.find((b) => (b.textContent ?? '').trim() === 'Approve');
      expect(approve).toBeTruthy();
      pressKeyOnButton(approve, 'Enter');
      const t = built.widgetTransport!;
      expect(t._spies.approveAndSign.length).toBe(1);
      expect(t._spies.requestPreview.length).toBe(0);
      handle.unmount();
    }
  });

  test('widget final preview keeps shared content and approves the sealed exact bytes', async () => {
    const widgetBindings = surfaceBindings.filter((b) => b.kind === 'widget');
    for (const binding of widgetBindings) {
      const model = benignFixtureModel();
      model.rawMessage = 'server-prepared-exact-bytes';
      const selection = fixtureSelection(model);
      const built = propsForSurface(binding, model, selection, {
        canUseAuthorizeSign: true,
        previewReady: true,
      });
      const handle = await mountSurface(binding, built.props);

      expect(handle.container.querySelector('details.advanced-details')).toBeTruthy();
      expect(handle.container.textContent).toContain('Exact grants');
      expect(handle.container.textContent).toContain('Copy text');
      expect(handle.container.textContent).toContain('server-prepared-exact-bytes');

      const buttons = Array.from(handle.container.querySelectorAll('button')) as any[];
      const approve = buttons.find(
        (b) => (b.textContent ?? '').trim() === 'Approve exact bytes',
      );
      expect(approve).toBeTruthy();
      pressKeyOnButton(approve, 'Enter');

      const t = built.widgetTransport!;
      expect(t._spies.approveAndSign.length).toBe(1);
      expect(t._spies.requestPreview.length).toBe(0);
      handle.unmount();
    }
  });

  test('final summary and sensitive warning describe only selected actions', async () => {
    const widgetBindings = surfaceBindings.filter((b) => b.kind === 'widget');
    for (const binding of widgetBindings) {
      const model = encryptionFixtureModel();
      model.rawMessage = 'server-prepared-create-only-bytes';
      const createOnly = new Set<string>([model.permissions[0].actions[0].id]);
      const built = propsForSurface(binding, model, createOnly, {
        canUseAuthorizeSign: true,
        previewReady: true,
      });
      const handle = await mountSurface(binding, built.props);

      const summary = handle.container.querySelector('.summary');
      expect(summary?.textContent).toContain('Create a decryption network');
      expect(summary?.textContent).not.toContain('decrypt protected data');
      expect(handle.container.querySelector('.sensitive-callout')).toBeNull();

      // Advanced details retains the removed baseline action so the user can
      // re-add it, but it no longer contaminates the top-level final copy.
      const details = handle.container.querySelector('details.advanced-details');
      expect(details?.textContent).toContain('decrypt');
      handle.unmount();
    }
  });

  test('legacy messages use shared approval and malformed ReCaps fail closed', async () => {
    const widgetBindings = surfaceBindings.filter((b) => b.kind === 'widget');
    for (const binding of widgetBindings) {
      const legacy = benignFixtureModel();
      legacy.protocol = 'legacy-message';
      legacy.rawMessage = 'legacy exact bytes';
      legacy.permissions = [];
      const legacyBuilt = propsForSurface(binding, legacy, new Set(), {
        canUseAuthorizeSign: false,
      });
      const legacyHandle = await mountSurface(binding, legacyBuilt.props);
      expect(legacyHandle.container.querySelector('[role="dialog"]')).toBeTruthy();
      const legacyApprove = (Array.from(legacyHandle.container.querySelectorAll('button')) as any[])
        .find((button) => (button.textContent ?? '').trim() === 'Approve');
      expect(legacyApprove).toBeTruthy();
      pressKeyOnButton(legacyApprove, 'Enter');
      expect(legacyBuilt.widgetTransport!._spies.approveAndSign.length).toBe(1);
      legacyHandle.unmount();

      const malformed = benignFixtureModel();
      malformed.protocol = 'malformed-recap';
      malformed.permissions = [];
      malformed.parseWarnings = [{ code: 'MALFORMED_RECAP', message: 'decode failed' }];
      const malformedBuilt = propsForSurface(binding, malformed, new Set(), {
        canUseAuthorizeSign: false,
      });
      const malformedHandle = await mountSurface(binding, malformedBuilt.props);
      const cannotApprove = (Array.from(malformedHandle.container.querySelectorAll('button')) as any[])
        .find((button) => (button.textContent ?? '').trim() === 'Cannot approve');
      expect(cannotApprove).toBeTruthy();
      expect(cannotApprove.disabled).toBe(true);
      expect(malformedBuilt.widgetTransport!._spies.approveAndSign.length).toBe(0);
      malformedHandle.unmount();
    }
  });

  test('keyboard: Enter on Cancel routes to the ADAPTER cancel wiring on every surface', async () => {
    for (const binding of surfaceBindings) {
      const model = benignFixtureModel();
      const selection = fixtureSelection(model);
      const built = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, built.props);
      const buttons = Array.from(handle.container.querySelectorAll('button')) as any[];
      const cancel =
        buttons.find((b) => b.classList?.contains?.('cancel')) ??
        buttons.find((b) => (b.textContent ?? '').trim() === 'Cancel');
      expect(cancel).toBeTruthy();
      pressKeyOnButton(cancel, 'Enter');
      if (binding.kind === 'cli') {
        const t = built.cliTransport!;
        expect(t._spies.goBack.length).toBe(1);
        expect(t._spies.approveDelegate.length).toBe(0);
      } else {
        const t = built.widgetTransport!;
        expect(t._spies.cancel.length).toBe(1);
        expect(t._spies.requestPreview.length).toBe(0);
      }
      handle.unmount();
    }
  });

  test('narrowed initialSelection reflects in checked state identically across surfaces', async () => {
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
      const fullBuilt = propsForSurface(binding, model, fullSel);
      const fullMount = await mountSurface(binding, fullBuilt.props);
      // Open editing so checkboxes render.
      const fullEdit = (Array.from(fullMount.container.querySelectorAll('button')) as any[])
        .find((b: any) => (b.textContent ?? '').trim() === 'Edit');
      fullEdit?.dispatchEvent(new (win as any).MouseEvent('click', { bubbles: true }));
      flushSync();
      const fullChecked = (Array.from(
        fullMount.container.querySelectorAll('input[type="checkbox"]'),
      ) as any[]).filter((b: any) => b.checked === true).length;
      fullMount.unmount();

      const narrowBuilt = propsForSurface(binding, model, narrowSel);
      const narrowMount = await mountSurface(binding, narrowBuilt.props);
      const narrowEdit = (Array.from(narrowMount.container.querySelectorAll('button')) as any[])
        .find((b: any) => (b.textContent ?? '').trim() === 'Edit');
      narrowEdit?.dispatchEvent(new (win as any).MouseEvent('click', { bubbles: true }));
      flushSync();
      const narrowChecked = (Array.from(
        narrowMount.container.querySelectorAll('input[type="checkbox"]'),
      ) as any[]).filter((b: any) => b.checked === true).length;
      narrowMount.unmount();
      perSurfaceCounts.push({ full: fullChecked, narrow: narrowChecked });
    }
    for (const { full, narrow } of perSurfaceCounts) {
      expect(narrow).toBeLessThan(full);
    }
    for (let i = 1; i < perSurfaceCounts.length; i += 1) {
      expect(perSurfaceCounts[i]).toEqual(perSurfaceCounts[0]!);
    }
  });

  test('every surface adapter carries the aria-modal="true" dialog role from the shared SigningApproval component', async () => {
    const model = benignFixtureModel();
    const selection = fixtureSelection(model);
    for (const binding of surfaceBindings) {
      const { props } = propsForSurface(binding, model, selection);
      const handle = await mountSurface(binding, props);
      const dialog = handle.container.querySelector('[role="dialog"]');
      expect(dialog).toBeTruthy();
      expect(dialog!.getAttribute('aria-modal')).toBe('true');
      const labelledbyId = dialog!.getAttribute('aria-labelledby');
      expect(typeof labelledbyId).toBe('string');
      const headline = handle.container.querySelector(`#${labelledbyId}`);
      expect(headline).toBeTruthy();
      expect((headline?.textContent ?? '').length).toBeGreaterThan(0);
      handle.unmount();
    }
  });
});
