// Mounted tests for the host approval rows (space, node ID and the node marker)
// and for the framed Approve gate in the shared approval view. The real
// `signing-approval.svelte` is compiled and mounted in happy-dom, the same way
// `signing-approval-parity-mounted.test.ts` mounts the adapters.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { afterAll, afterEach, beforeEach, describe, expect, test, vi } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Cleanup is registered first. HOME is a private dir for the whole file and is
// put back afterwards; the test writes nothing there.
const PRIOR_HOME = process.env.HOME;
const HOME = mkdtempSync(join('/var/tmp', 'tc1950.'));
afterAll(() => {
  if (PRIOR_HOME === undefined) delete process.env.HOME;
  else process.env.HOME = PRIOR_HOME;
  rmSync(HOME, { recursive: true, force: true });
});
process.env.HOME = HOME;

import { Window } from 'happy-dom';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import type { CapabilityReviewModel } from '../../../../packages/capability-review/src/index';

const win = new Window({ url: 'http://openkey.test/' });
// Browser globals the Svelte client runtime and the component read. Typed as a
// record because the host global has no such fields.
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

// Dynamic imports: the browser globals above must exist before the Svelte
// client runtime loads, and static imports are hoisted above them.
const { compile } = await import('svelte/compiler');
const { readFileSync, writeFileSync, mkdirSync } = await import('node:fs');
const { pathToFileURL } = await import('node:url');
const require = createRequire(import.meta.url);
const sveltePkgDir = dirname(require.resolve('svelte/package.json'));
const svelteClient = (await import(pathToFileURL(join(sveltePkgDir, 'src/index-client.js')).href)) as {
  mount: (component: unknown, options: { target: Element; props: Record<string, unknown> }) => unknown;
  unmount: (instance: unknown) => void;
  flushSync: () => void;
};
const { mount, unmount, flushSync } = svelteClient;

const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const OUT_DIR = join(WEB_ROOT, '.svelte-kit', '_host-approval-mounted');
mkdirSync(OUT_DIR, { recursive: true });

// Compile a component under `src/lib` to an `.mjs` next to the build output,
// compiling the `.svelte` files it imports the same way and pointing `$lib` and
// package imports at source files Bun can run directly.
const compiledFiles = new Map<string, string>();
async function compileSvelte(libRelPath: string): Promise<string> {
  const cached = compiledFiles.get(libRelPath);
  if (cached) return cached;
  const source = readFileSync(join(WEB_ROOT, 'src/lib', libRelPath), 'utf8');
  const compiled = compile(source, { generate: 'client', dev: false, name: 'Component', filename: libRelPath });
  const code = compiled.js.code;
  let rewritten = '';
  let cursor = 0;
  for (const match of code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    const spec = match[1]!;
    let target = spec;
    if (spec === '@openkey/capability-review') {
      target = pathToFileURL(join(WEB_ROOT, '..', '..', 'packages', 'capability-review', 'src', 'index.ts')).href;
    } else if (spec.startsWith('$lib/')) {
      const rel = spec.slice('$lib/'.length);
      target = rel.endsWith('.svelte') ? await compileSvelte(rel) : pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
    }
    rewritten += `${code.slice(cursor, match.index)}from '${target}'`;
    cursor = match.index + match[0].length;
  }
  rewritten += code.slice(cursor);
  const outPath = join(OUT_DIR, `${libRelPath.replace(/[^A-Za-z0-9]/g, '_')}.client.mjs`);
  writeFileSync(outPath, rewritten);
  const url = pathToFileURL(outPath).href;
  compiledFiles.set(libRelPath, url);
  return url;
}
const SigningApproval = (await import(await compileSvelte('components/signing/signing-approval.svelte'))).default;
const PopupAdapter = (await import(await compileSvelte('components/signing/popup-signing-adapter.svelte'))).default;

const OWNER = '0x1111111111111111111111111111111111111111';
const PEER = 'did:key:z6Mkj8ZndSavdU1RqiTepC1hj4jcKHC5qELaBUxBKrPteD25';
const SPACE = `tinycloud:pkh:eip155:1:${OWNER}:default`;

function recap(att: Record<string, Record<string, unknown[]>>): string {
  return `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;
}

function siwe(uri: string, ability: string, expiry?: string): string {
  return [
    'app.example wants you to sign in with your Ethereum account:',
    OWNER,
    '',
    `URI: ${uri}`,
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    'Issued At: 2026-10-24T00:00:00.000Z',
    ...(expiry ? [`Expiration Time: ${expiry}`] : []),
    'Resources:',
    `- ${recap({ [`${SPACE}/space`]: { [ability]: [{}] } })}`,
  ].join('\n');
}

function modelFor(message: string) {
  return parseCapabilityReview({
    message,
    signer: { label: 'Selected key', address: OWNER, chainId: 1, provenance: 'managed' },
    editable: false,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'app.example',
      verifiedOrigin: 'https://app.example',
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
}

type Review = CapabilityReviewModel;
const hostModel = () => modelFor(siwe(PEER, 'tinycloud.space/host'));
const selectionOf = (model: Review) => new Set(model.permissions.flatMap((grant) => grant.actions.map((action) => action.id)));

interface Mounted {
  target: HTMLElement;
  approve: HTMLButtonElement;
  approveCalls: () => number;
  destroy: () => void;
}

function render(model: Review, extra: Record<string, unknown> = {}): Mounted {
  const created = win.document.createElement('div');
  win.document.body.appendChild(created);
  // happy-dom's element stands in for the DOM lib's element type.
  const target = created as unknown as HTMLElement;
  let approveCalls = 0;
  const instance = mount(SigningApproval, {
    target,
    props: {
      model,
      selection: selectionOf(model),
      editing: false,
      onApprove: () => {
        approveCalls += 1;
      },
      onCancel: () => {},
      onSelectionChange: () => {},
      onEditingChange: () => {},
      ...extra,
    },
  });
  flushSync();
  return {
    target,
    approve: target.querySelector('button.approve') as HTMLButtonElement,
    approveCalls: () => approveCalls,
    destroy: () => {
      unmount(instance);
      target.remove();
    },
  };
}

const text = (element: Element | null) => (element?.textContent ?? '').replace(/\s+/g, ' ').trim();

// A click the browser itself produced.
function trustedClick(button: Element) {
  const event = new win.MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'isTrusted', { value: true });
  button.dispatchEvent(event as unknown as Event);
  flushSync();
}

describe('host approval rows', () => {
  let mounted: Mounted | null = null;
  afterEach(() => {
    mounted?.destroy();
    mounted = null;
  });

  test('home is the private dir', () => {
    expect(process.env.HOME).toBe(HOME);
  });

  test('space and node ID are in the visible summary, not in Advanced details', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    const summary = mounted.target.querySelector('section.summary')!;
    const rows = [...summary.querySelectorAll('.host-fact')].map((row) => text(row));
    expect(rows).toHaveLength(2);
    expect(rows[0]).toContain('Space');
    expect(rows[0]).toContain('default');
    expect(rows[0]).toContain('tinycloud:pkh:eip155:1:0x1111…1111:default');
    expect(rows[1]).toContain('Node ID');
    expect(rows[1]).toContain('did:key:z6Mkj8Zn…rPteD25');
    expect(mounted.target.querySelector('.advanced-details .host-facts')).toBeNull();
    // The pinned consent line is unchanged and still the first line.
    expect(text(summary.querySelector('.statement-primary'))).toBe('Create a new TinyCloud space');
  });

  test('the full ids are on the elements and the copy buttons carry the final labels', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    const codes = [...mounted.target.querySelectorAll('.host-fact code')];
    expect(codes[0]!.getAttribute('title')).toBe(SPACE);
    expect(codes[1]!.getAttribute('title')).toBe(PEER);
    const buttons = [...mounted.target.querySelectorAll('.host-fact .copy-btn')];
    expect(buttons.map((button) => [text(button), button.getAttribute('aria-label'), button.getAttribute('title')])).toEqual([
      ['Copy space ID', 'Copy space ID', 'Copy space ID'],
      ['Copy node ID', 'Copy node ID', 'Copy node ID'],
    ]);
  });

  test('a known node: the marker names the configured origin and Approve stays enabled', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'known', origin: 'https://node.tinycloud.xyz' } });
    const status = mounted.target.querySelector('.host-node-status')!;
    expect(text(status)).toBe('Known TinyCloud node at https://node.tinycloud.xyz');
    expect(status.getAttribute('data-node-state')).toBe('known');
    expect(mounted.approve.disabled).toBe(false);
  });

  test('an unconfirmed node: the marker and the line under it show, Approve stays enabled', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    const status = mounted.target.querySelector('.host-node-status')!;
    expect(text(status)).toBe('Not confirmed as a known TinyCloud node Approving lets this node store and serve your new space.');
    expect(status.getAttribute('data-node-state')).toBe('other');
    expect(mounted.approve.disabled).toBe(false);
    trustedClick(mounted.approve);
    expect(mounted.approveCalls()).toBe(1);
  });

  test('while the node is checked the status says so and Approve is really disabled', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'checking' } });
    expect(text(mounted.target.querySelector('.host-node-status'))).toBe('Checking the node…');
    expect(mounted.approve.disabled).toBe(true);
    expect(mounted.approve.getAttribute('aria-describedby')).toBe('host-node-status');
    mounted.approve.click();
    expect(mounted.approveCalls()).toBe(0);
  });

  test('without a lookup state (the /delegate session grant) only the space row shows', () => {
    mounted = render(modelFor(siwe(PEER, 'tinycloud.space/host', '2026-10-31T00:00:00.000Z')));
    const rows = [...mounted.target.querySelectorAll('.host-fact')].map((row) => text(row));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain('Space');
    expect(mounted.target.querySelector('.host-node-status')).toBeNull();
    expect(text(mounted.target)).not.toContain('Node ID');
  });

  test('a request that does not host a space shows no rows', () => {
    mounted = render(modelFor(siwe(PEER, 'tinycloud.space/info')), { peerRecognition: { state: 'other' } });
    expect(mounted.target.querySelector('.host-facts')).toBeNull();
    expect(mounted.target.querySelector('.host-node-status')).toBeNull();
  });
});

class FakeObserver {
  static latest: FakeObserver | null = null;
  trackVisibility = true;
  observed: Element[] = [];
  pending: IntersectionObserverEntry[] = [];
  constructor(public callback: (entries: IntersectionObserverEntry[]) => void) {
    FakeObserver.latest = this;
  }
  observe(element: Element) {
    this.observed.push(element);
  }
  disconnect() {}
  takeRecords() {
    const taken = this.pending;
    this.pending = [];
    return taken;
  }
  report(state: { isIntersecting: boolean; intersectionRatio: number; isVisible: boolean }) {
    this.callback(this.observed.map((target) => ({ target, ...state }) as unknown as IntersectionObserverEntry));
  }
  entriesFor(state: { isIntersecting: boolean; intersectionRatio: number; isVisible: boolean }) {
    return this.observed.map((target) => ({ target, ...state }) as unknown as IntersectionObserverEntry);
  }
}
const FULL = { isIntersecting: true, intersectionRatio: 1, isVisible: true };
const COVERED = { isIntersecting: true, intersectionRatio: 1, isVisible: false };
const WAIT = 'Approve becomes available once this window is fully visible.';

describe('framed Approve', () => {
  let mounted: Mounted | null = null;
  const realTop = Object.getOwnPropertyDescriptor(win, 'top');

  beforeEach(() => {
    vi.useFakeTimers();
    FakeObserver.latest = null;
    browserGlobals.IntersectionObserver = FakeObserver;
    Object.defineProperty(win, 'top', { value: {}, configurable: true });
  });
  afterEach(() => {
    mounted?.destroy();
    mounted = null;
    vi.useRealTimers();
    delete browserGlobals.IntersectionObserver;
    if (realTop) Object.defineProperty(win, 'top', realTop);
    else Reflect.deleteProperty(win, 'top');
  });

  const tick = (ms: number) => {
    vi.advanceTimersByTime(ms);
    flushSync();
  };

  test('starts disabled with the status line, then opens after the delay once visible', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    const observer = FakeObserver.latest!;
    expect(observer.observed).toHaveLength(2);
    expect(mounted.approve.disabled).toBe(true);
    expect(text(mounted.target.querySelector('.approve-blocked'))).toBe(WAIT);
    observer.report(FULL);
    flushSync();
    tick(599);
    expect(mounted.approve.disabled).toBe(true);
    tick(1);
    expect(mounted.approve.disabled).toBe(false);
    expect(mounted.target.querySelector('.approve-blocked')).toBeNull();
  });

  test('a covered view (still intersecting) never opens', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    FakeObserver.latest!.report(COVERED);
    tick(10_000);
    expect(mounted.approve.disabled).toBe(true);
    expect(text(mounted.target.querySelector('.approve-blocked'))).toBe(WAIT);
  });

  test('Cancel is never gated', () => {
    let cancelled = 0;
    mounted = render(hostModel(), { peerRecognition: { state: 'other' }, onCancel: () => (cancelled += 1) });
    const cancel = mounted.target.querySelector('button.cancel') as HTMLButtonElement;
    expect(cancel.disabled).toBe(false);
    cancel.click();
    expect(cancelled).toBe(1);
  });

  test('a click that is not from the browser is ignored, a trusted one goes through', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    FakeObserver.latest!.report(FULL);
    flushSync();
    tick(600);
    expect(mounted.approve.disabled).toBe(false);
    mounted.approve.click();
    expect(mounted.approveCalls()).toBe(0);
    trustedClick(mounted.approve);
    expect(mounted.approveCalls()).toBe(1);
  });

  test('a cover reported just before the click refuses the tap', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    const observer = FakeObserver.latest!;
    observer.report(FULL);
    flushSync();
    tick(600);
    observer.pending = observer.entriesFor(COVERED);
    trustedClick(mounted.approve);
    expect(mounted.approveCalls()).toBe(0);
    expect(mounted.approve.disabled).toBe(true);
  });

  test('window blur closes Approve and the delay starts over', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    FakeObserver.latest!.report(FULL);
    flushSync();
    tick(600);
    expect(mounted.approve.disabled).toBe(false);
    win.dispatchEvent(new win.Event('blur'));
    flushSync();
    expect(mounted.approve.disabled).toBe(true);
    tick(599);
    expect(mounted.approve.disabled).toBe(true);
    tick(1);
    expect(mounted.approve.disabled).toBe(false);
  });

  test('a node check in progress keeps Approve disabled even when visible', () => {
    mounted = render(hostModel(), { peerRecognition: { state: 'checking' } });
    FakeObserver.latest!.report(FULL);
    flushSync();
    tick(5_000);
    expect(mounted.approve.disabled).toBe(true);
  });
});

describe('not framed', () => {
  test('Approve is enabled at once and no observer is created', () => {
    FakeObserver.latest = null;
    browserGlobals.IntersectionObserver = FakeObserver;
    const mounted = render(hostModel(), { peerRecognition: { state: 'other' } });
    try {
      expect(FakeObserver.latest).toBeNull();
      expect(mounted.approve.disabled).toBe(false);
      expect(mounted.target.querySelector('.approve-blocked')).toBeNull();
    } finally {
      mounted.destroy();
      delete browserGlobals.IntersectionObserver;
    }
  });
});

describe('popup adapter looks the node up', () => {
  const realFetch = globalThis.fetch;
  let mounted: Mounted | null = null;
  afterEach(() => {
    mounted?.destroy();
    mounted = null;
    globalThis.fetch = realFetch;
  });

  const transport = {
    canUseAuthorizeSign: false,
    previewReady: false,
    approving: false,
    error: null,
    requestPreview: async () => {},
    approveAndSign: async () => {},
    cancel: () => {},
    onSelectionEdited: () => {},
    invalidatePreview: () => {},
  };

  function renderAdapter(model: Review): Mounted {
    const created = win.document.createElement('div');
    win.document.body.appendChild(created);
    const target = created as unknown as HTMLElement;
    const instance = mount(PopupAdapter, { target, props: { model, initialSelection: selectionOf(model), transport } });
    flushSync();
    return {
      target,
      approve: target.querySelector('button.approve') as HTMLButtonElement,
      approveCalls: () => 0,
      destroy: () => {
        unmount(instance);
        target.remove();
      },
    };
  }

  // Let already-resolved promises run to completion.
  const settle = async () => {
    for (let turn = 0; turn < 30; turn += 1) await Promise.resolve();
    flushSync();
  };

  test('checking first, then the known marker; only the known origins are asked, for the encoded space', async () => {
    const urls: string[] = [];
    const gate = Promise.withResolvers<Response>();
    globalThis.fetch = (async (url: string) => {
      urls.push(url);
      return gate.promise.then((response) => response.clone());
    }) as typeof fetch;
    mounted = renderAdapter(hostModel());
    expect(text(mounted.target.querySelector('.host-node-status'))).toBe('Checking the node…');
    expect(mounted.approve.disabled).toBe(true);
    gate.resolve(new Response(PEER, { status: 200 }));
    await settle();
    expect(text(mounted.target.querySelector('.host-node-status'))).toBe('Known TinyCloud node at https://node.tinycloud.xyz');
    expect(mounted.approve.disabled).toBe(false);
    expect(urls.sort()).toEqual([
      `https://node.tinycloud.xyz/peer/generate/${encodeURIComponent(SPACE)}`,
      `https://tee.node.tinycloud.xyz/peer/generate/${encodeURIComponent(SPACE)}`,
    ]);
  });

  test('another key or a failing node gives the not-confirmed marker and Approve is enabled', async () => {
    globalThis.fetch = (async () => new Response('did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH', { status: 200 })) as typeof fetch;
    mounted = renderAdapter(hostModel());
    await settle();
    expect(text(mounted.target.querySelector('.host-node-status'))).toContain('Not confirmed as a known TinyCloud node');
    expect(mounted.approve.disabled).toBe(false);
    mounted.destroy();

    globalThis.fetch = (async () => {
      throw new TypeError('Failed to fetch');
    }) as typeof fetch;
    mounted = renderAdapter(hostModel());
    await settle();
    expect(text(mounted.target.querySelector('.host-node-status'))).toContain('Not confirmed as a known TinyCloud node');
    expect(mounted.approve.disabled).toBe(false);
  });

  test('a request that does not host a space makes no lookup', async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      return new Response(PEER, { status: 200 });
    }) as typeof fetch;
    mounted = renderAdapter(modelFor(siwe(PEER, 'tinycloud.space/info')));
    await settle();
    expect(calls).toBe(0);
  });
});
