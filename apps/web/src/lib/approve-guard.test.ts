// A click on Approve that arrives less than 500 ms after the button became actionable is ignored; the window restarts
// whenever Approve becomes actionable again. The guard is tested on its own with a fake clock, and through the real
// signing approval view mounted in the popup and iframe adapters.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { afterAll, afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { APPROVE_SETTLE_MS, approveGuardForFrame, createApproveGuard } from './approve-guard';

describe('the guard', () => {
  function clocked() {
    let now = 10_000;
    const guard = createApproveGuard(() => now);
    return { guard, at: (ms: number) => { now = ms; } };
  }

  test('the window is 500 ms', () => {
    expect(APPROVE_SETTLE_MS).toBe(500);
  });

  test('a button that was never actionable is not ready', () => {
    const { guard, at } = clocked();
    at(1_000_000);
    expect(guard.ready()).toBe(false);
    guard.track(false);
    expect(guard.ready()).toBe(false);
  });

  test('ready only once the button has been actionable for the whole window', () => {
    const { guard, at } = clocked();
    at(1000);
    guard.track(true);
    for (const [elapsed, ready] of [[0, false], [1, false], [499, false], [500, true], [501, true], [60_000, true]] as const) {
      at(1000 + elapsed);
      expect(guard.ready(), `${elapsed} ms`).toBe(ready);
    }
  });

  test('tracking an already actionable button does not restart the window', () => {
    const { guard, at } = clocked();
    at(1000);
    guard.track(true);
    at(1400);
    guard.track(true);
    at(1500);
    expect(guard.ready()).toBe(true);
  });

  test('the window restarts every time the button becomes actionable again', () => {
    const { guard, at } = clocked();
    at(1000);
    guard.track(true);
    at(1600);
    expect(guard.ready()).toBe(true);
    guard.track(false);
    expect(guard.ready()).toBe(false);
    at(2000);
    guard.track(true);
    at(2499);
    expect(guard.ready()).toBe(false);
    at(2500);
    expect(guard.ready()).toBe(true);
  });

  test('the default clock is the monotonic one', () => {
    const guard = createApproveGuard();
    guard.track(true);
    expect(guard.ready()).toBe(false);
  });
});

// ---- the real approval view -------------------------------------------------

const win = new Window({ url: 'http://openkey.test/' });
const browserGlobals = globalThis as unknown as Record<string, unknown>;
Object.assign(browserGlobals, {
  window: win,
  document: win.document,
  HTMLElement: win.HTMLElement,
  Element: win.Element,
  Node: win.Node,
  Text: win.Text,
  Comment: win.Comment,
  getComputedStyle: win.getComputedStyle.bind(win),
  navigator: win.navigator,
  CustomEvent: win.CustomEvent,
  Event: win.Event,
  KeyboardEvent: win.KeyboardEvent,
  MouseEvent: win.MouseEvent,
  requestAnimationFrame: win.requestAnimationFrame.bind(win),
  cancelAnimationFrame: win.cancelAnimationFrame.bind(win),
});

const { compile } = await import('svelte/compiler');
const require = createRequire(import.meta.url);
const SVELTE_CLIENT = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = (await import(SVELTE_CLIENT)) as {
  mount: (component: unknown, options: { target: Element; props: Record<string, unknown> }) => unknown;
  unmount: (instance: unknown) => void;
  flushSync: () => void;
};

const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'approve-guard.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const compiledFiles = new Map<string, string>();
function compileSvelte(libRelPath: string): string {
  const cached = compiledFiles.get(libRelPath);
  if (cached) return cached;
  const compiled = compile(readFileSync(join(WEB_ROOT, 'src/lib', libRelPath), 'utf8'), {
    generate: 'client', dev: false, name: 'Component', filename: libRelPath,
  });
  let rewritten = '';
  let cursor = 0;
  for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    const spec = match[1]!;
    let target = spec;
    if (spec === 'svelte') target = SVELTE_CLIENT;
    else if (spec === '@openkey/capability-review') {
      target = pathToFileURL(join(WEB_ROOT, '..', '..', 'packages', 'capability-review', 'src', 'index.ts')).href;
    } else if (spec.startsWith('$lib/')) {
      const rel = spec.slice('$lib/'.length);
      target = rel.endsWith('.svelte') ? compileSvelte(rel) : pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
    }
    rewritten += `${compiled.js.code.slice(cursor, match.index)}from '${target}'`;
    cursor = match.index! + match[0].length;
  }
  rewritten += compiled.js.code.slice(cursor);
  const out = join(OUT_DIR, `${libRelPath.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, rewritten);
  const url = pathToFileURL(out).href;
  compiledFiles.set(libRelPath, url);
  return url;
}

// Holds the transport's state where the test can change it, and gives the guard a clock the test sets.
const HOLDER_SOURCE = (adapter: string, guard: string) => `<script>
  import Adapter from '${adapter}';
  import { createApproveGuard } from '${guard}';
  let { model, initialSelection, withGuard } = $props();
  const state = $state({ previewReady: true, approving: false });
  globalThis.__guard = { state };
  const transport = {
    get previewReady() { return state.previewReady; },
    get approving() { return state.approving; },
    canUseAuthorizeSign: true,
    approveGuard: withGuard ? createApproveGuard(() => globalThis.__now) : undefined,
    approveAndSign() { globalThis.__approved += 1; },
    cancel() {},
    onSelectionEdited() {},
    invalidatePreview() {},
    error: '',
  };
</script>
<Adapter {model} {initialSelection} {transport} />`;

function holder(adapterPath: string, name: string): unknown {
  const code = compile(HOLDER_SOURCE(compileSvelte(adapterPath), pathToFileURL(join(WEB_ROOT, 'src/lib/approve-guard.ts')).href), {
    generate: 'client', dev: false, name: 'Holder', filename: `${name}.svelte`,
  }).js.code;
  const rewritten = code.replace(/from\s+['"]svelte(\/[^'"]*)?['"]/g, (whole) => whole.replace(/['"]svelte['"]/, `'${SVELTE_CLIENT}'`));
  const file = join(OUT_DIR, `${name}.mjs`);
  writeFileSync(file, rewritten);
  return file;
}

const OWNER = '0x1111111111111111111111111111111111111111';
const SPACE = `tinycloud:pkh:eip155:1:${OWNER}:default`;
const recap = (att: Record<string, Record<string, unknown[]>>) =>
  `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;
const message = [
  'app.example wants you to sign in with your Ethereum account:',
  OWNER,
  '',
  'URI: https://app.example',
  'Version: 1',
  'Chain ID: 1',
  'Nonce: abcdef123456',
  'Issued At: 2026-10-24T00:00:00.000Z',
  'Resources:',
  `- ${recap({ [`${SPACE}/notes/`]: { 'tinycloud.kv/get': [{}] } })}`,
].join('\n');
const model = parseCapabilityReview({
  message,
  signer: { label: 'Selected key', address: OWNER, chainId: 1, provenance: 'managed' },
  editable: false,
  metadataTrust: { status: 'unsigned', reason: 'no manifest' },
  reason: { text: '', source: 'none' },
  requester: {
    displayName: 'app.example', verifiedOrigin: 'https://app.example', appId: null, manifestName: null, manifestNameProvenance: 'none',
    manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
  },
});
const selection = new Set(model.permissions.flatMap((grant) => grant.actions.map((action) => action.id)));

type Globals = { __now: number; __approved: number; __guard: { state: { previewReady: boolean; approving: boolean } } };
const g = () => globalThis as unknown as Globals;

for (const [label, adapterPath] of [
  ['iframe', 'components/signing/iframe-signing-adapter.svelte'],
  ['popup', 'components/signing/popup-signing-adapter.svelte'],
] as const) {
  describe(`the ${label} adapter with the guard`, () => {
    let target: HTMLElement | null = null;
    let app: unknown = null;
    afterEach(() => {
      if (app) unmount(app);
      target?.remove();
      app = null;
      target = null;
    });

    async function open(withGuard: boolean, startAt = 1000) {
      g().__now = startAt;
      g().__approved = 0;
      const Holder = (await import(holder(adapterPath, `${label}-${withGuard ? 'guarded' : 'plain'}-${Math.random().toString(36).slice(2)}`))).default;
      target = win.document.createElement('div') as unknown as HTMLElement;
      win.document.body.appendChild(target as unknown as Node);
      app = mount(Holder, { target: target as unknown as Element, props: { model, initialSelection: selection, withGuard } });
      flushSync();
      const button = () => target!.querySelector('button.approve') as HTMLButtonElement;
      const click = (at: number) => {
        g().__now = at;
        button().click();
        flushSync();
      };
      return { button, click, text: () => (target!.textContent ?? '').replace(/\s+/g, ' ').trim() };
    }

    test('a click less than 500 ms after the button became actionable is ignored, with nothing said', async () => {
      const screen = await open(true);
      expect(screen.button().disabled).toBe(false);
      const before = screen.text();
      screen.click(1000);
      screen.click(1300);
      screen.click(1499);
      expect(g().__approved).toBe(0);
      expect(screen.text()).toBe(before);
      expect(target!.querySelector('[role="alert"]')).toBeNull();
    });

    test('a click at 500 ms or later signs', async () => {
      const screen = await open(true);
      screen.click(1500);
      expect(g().__approved).toBe(1);
    });

    test('a click inside the window is ignored and the next one after it signs', async () => {
      const screen = await open(true);
      screen.click(1200);
      expect(g().__approved).toBe(0);
      screen.click(1700);
      expect(g().__approved).toBe(1);
    });

    test('a new preview restarts the window', async () => {
      const screen = await open(true);
      screen.click(1500);
      expect(g().__approved).toBe(1);

      // The selection changes: the preview is dropped and a new one arrives at 2000.
      g().__guard.state.previewReady = false;
      flushSync();
      expect(screen.button().disabled).toBe(true);
      g().__now = 2000;
      g().__guard.state.previewReady = true;
      flushSync();
      expect(screen.button().disabled).toBe(false);

      screen.click(2499);
      expect(g().__approved).toBe(1);
      screen.click(2500);
      expect(g().__approved).toBe(2);
    });

    test('Approve enabled again after a signing attempt restarts the window', async () => {
      const screen = await open(true);
      g().__now = 1500;
      g().__guard.state.approving = true;
      flushSync();
      g().__now = 3000;
      g().__guard.state.approving = false;
      flushSync();
      screen.click(3200);
      expect(g().__approved).toBe(0);
      screen.click(3500);
      expect(g().__approved).toBe(1);
    });

    test('a transport without the guard signs at once', async () => {
      const screen = await open(false);
      screen.click(1000);
      expect(g().__approved).toBe(1);
    });
  });
}

describe('the sign pages', () => {
  test('both give the adapter the frame guard', () => {
    for (const file of ['routes/widget/embed/sign/+page.svelte', 'routes/widget/sign/+page.svelte']) {
      const source = readFileSync(join(WEB_ROOT, 'src', file), 'utf8');
      expect(source, file).toContain('const approveGuard = approveGuardForFrame();');
      expect(source, file).toMatch(/transport=\{\{\s*approveGuard,/);
    }
  });

  test('the guard exists in a frame, including one that cannot read its parent, and not in a top-level window', () => {
    const realWindow = Object.getOwnPropertyDescriptor(globalThis, 'window')!;
    try {
      const top = {};
      Object.defineProperty(globalThis, 'window', { configurable: true, writable: true, value: { self: top, top } });
      expect(approveGuardForFrame()).toBeUndefined();
      Object.defineProperty(globalThis, 'window', { configurable: true, writable: true, value: { self: {}, top } });
      expect(approveGuardForFrame()).toBeDefined();
      Object.defineProperty(globalThis, 'window', {
        configurable: true,
        writable: true,
        value: { self: {}, get top() { throw new Error('cross-origin'); } },
      });
      expect(approveGuardForFrame()).toBeDefined();
    } finally {
      Object.defineProperty(globalThis, 'window', realWindow);
    }
  });
});
