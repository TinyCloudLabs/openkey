// A sign page inside another page's frame uses the one-passkey cover only while Approve has been in plain view.
// Mounts the production popup page (widget/sign) and embed page (widget/embed/sign) with their real signing adapters
// and the real approval screen, frames them (the window's top is another window), and replaces the browser's
// intersection observer with one the test drives. The offer is covered while the flow id is named and asks for the
// passkey when it is not.
//
// The passkey prompt is replaced by a recorder that answers with a fixed assertion.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import type { ApprovalPasskeyNeed } from './approval-passkey';

const win = new Window({ url: 'http://openkey.test/' });
(win as unknown as { postMessage: () => void }).postMessage = () => {};
Object.assign(globalThis, {
  window: win,
  document: win.document,
  HTMLElement: win.HTMLElement,
  HTMLMediaElement: win.HTMLMediaElement,
  HTMLInputElement: win.HTMLInputElement,
  HTMLSelectElement: win.HTMLSelectElement,
  HTMLTextAreaElement: win.HTMLTextAreaElement,
  HTMLFormElement: win.HTMLFormElement,
  Element: win.Element,
  Node: win.Node,
  Text: win.Text,
  Comment: win.Comment,
  navigator: win.navigator,
  CustomEvent: win.CustomEvent,
  Event: win.Event,
  KeyboardEvent: win.KeyboardEvent,
  MouseEvent: win.MouseEvent,
  MutationObserver: win.MutationObserver,
  getComputedStyle: win.getComputedStyle.bind(win),
  requestAnimationFrame: win.requestAnimationFrame.bind(win),
  cancelAnimationFrame: win.cancelAnimationFrame.bind(win),
  sessionStorage: win.sessionStorage,
  location: win.location,
  ResizeObserver: class { observe() {} unobserve() {} disconnect() {} },
});

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-cover-visibility.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
interface SvelteClient {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
}
const SVELTE_CLIENT = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = (await import(SVELTE_CLIENT)) as SvelteClient;

// ---- the clock, the frame and the intersection observer ---------------------

let skew = 0;
const realNow = performance.now.bind(performance);
Object.defineProperty(performance, 'now', { configurable: true, writable: true, value: () => realNow() + skew });
const advance = (ms: number) => { skew += ms; };
afterAll(() => { Object.defineProperty(performance, 'now', { configurable: true, writable: true, value: realNow }); });

const setTop = (value: object | null) => {
  if (value === null) delete (win as unknown as { top?: unknown }).top;
  else Object.defineProperty(win, 'top', { configurable: true, value });
};

type ObserverEntry = { isIntersecting: boolean; isVisible: boolean };
class FakeObserver {
  static all: FakeObserver[] = [];
  targets = new Set<Element>();
  constructor(readonly callback: (entries: ObserverEntry[]) => void, readonly options: Record<string, unknown>) {
    FakeObserver.all.push(this);
  }
  observe(target: Element) { this.targets.add(target); }
  disconnect() { this.targets.clear(); }
}
class FakeEntryV2 { get isVisible() { return false; } }
class FakeEntryV1 {}
const browser = globalThis as unknown as Record<string, unknown>;
const useObserver = (version: 1 | 2) => {
  FakeObserver.all = [];
  browser.IntersectionObserver = FakeObserver;
  browser.IntersectionObserverEntry = version === 2 ? FakeEntryV2 : FakeEntryV1;
};
const dropObserver = () => { delete browser.IntersectionObserver; delete browser.IntersectionObserverEntry; };
/** The observer reports on the Approve button it watches now. */
const report = (visible: boolean) => {
  const live = FakeObserver.all.filter((observer) => observer.targets.size > 0).at(-1);
  if (!live) throw new Error('no observer is watching the Approve button');
  live.callback([{ isIntersecting: visible, isVisible: visible }]);
};

// ---- what the test and the pages share ------------------------------------

type Shared = {
  options: { onRequest: (request: unknown) => void } | null;
  offerCalls: unknown[][];
  signCalls: unknown[][];
  prompts: Array<ApprovalPasskeyNeed | null>;
};
const store = globalThis as unknown as { __cover: Shared };
const shared = (): Shared => store.__cover;
const reset = () => { store.__cover = { options: null, offerCalls: [], signCalls: [], prompts: [] }; };

const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };
const ASSERTION = { challengeToken: 'challenge-1', response: { id: 'credential-1' } };
const REQUIRED = { required: true, challengeToken: 'challenge-1', options: { challenge: 'abc' } } as unknown as ApprovalPasskeyNeed;
const COVERED: ApprovalPasskeyNeed = { required: false, flowCover: true };
const FLOW_SHAPE = /^w\.[A-Za-z0-9_-]{32}$/;

const EMPTY_SOURCE = '<div data-testid="sign-in"></div>';
const wrapperSource = (adapterUrl: string) => `<script>
  import Adapter from ${JSON.stringify(adapterUrl)};
  let { transport, ...rest } = $props();
</script>
<Adapter {transport} {...rest} layoutBlocked={false} />`;

function compileSource(source: string, name: string): string {
  const out = compile(source, { generate: 'client', dev: false, name: 'Stub', filename: `${name}.svelte` }).js.code;
  const file = join(OUT_DIR, `${name}.mjs`);
  writeFileSync(file, out);
  return pathToFileURL(file).href;
}

const REAL_PASSKEY_MODULE = pathToFileURL(join(WEB_ROOT, 'src/lib/approval-passkey.ts')).href;
const baseStubs = (pageUrl: string): Record<string, string> => ({
  '$app/stores': `export const page = { subscribe(run) { run({ url: new URL(${JSON.stringify(pageUrl)}) }); return () => {}; } };`,
  '$lib/auth-client': `export const authErrorMessage = (e, fallback) => fallback;
    export const authClient = { useSession: () => ({ subscribe(run) { run({ data: { user: { id: 'user_1' } }, isPending: false }); return () => {}; } }) };`,
  // The offer is covered when the flow id is named and asks for the passkey when it is not.
  '$lib/api': `export const api = {
    getKey: async () => ({ key: ${JSON.stringify(KEY)} }),
    listKeys: async () => ({ keys: [${JSON.stringify(KEY)}] }),
    signMessagePasskey: async (...args) => {
      globalThis.__cover.offerCalls.push(args);
      return args[3] ? ${JSON.stringify(COVERED)} : ${JSON.stringify(REQUIRED)};
    },
    signMessage: async (...args) => {
      globalThis.__cover.signCalls.push(args);
      return { signature: '0x${'11'.repeat(65)}', address: ${JSON.stringify(KEY.address)} };
    },
  };`,
  '$lib/approval-passkey': `export * from ${JSON.stringify(REAL_PASSKEY_MODULE)};
    export const answerApprovalPasskey = async (need) => {
      globalThis.__cover.prompts.push(need ?? null);
      return need?.required ? ${JSON.stringify(ASSERTION)} : undefined;
    };`,
  '$lib/embed-passkey': `export const isEmbedContext = () => true; export const getSessionToken = () => 'session-token';
    export const withSessionCredential = (init) => init; export const clearSessionToken = () => {};`,
  '$lib/widget-transport': `export const createWidgetTransport = (options) => {
      globalThis.__cover.options = options;
      return { emitReady() {}, emitResize() {}, emitLayoutSignal() {}, destroy() {}, respond() {} };
    };
    export const createIframeLayoutGate = () => ({ measure() {}, changed() {}, applied() {}, isCurrent: () => false, destroy() {} });`,
});

const compiledFiles = new Map<string, string>();
function compileComponent(file: string, name: string, stubs: Record<string, string>): string {
  const cached = compiledFiles.get(`${name}:${file}`);
  if (cached) return cached;
  const compiled = compile(readFileSync(file, 'utf8'), { generate: 'client', dev: false, name: 'Subject', filename: file });
  let code = '';
  let cursor = 0;
  for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    code += compiled.js.code.slice(cursor, match.index);
    const spec = match[1]!;
    let target = spec;
    if (spec in stubs) {
      const stubFile = join(OUT_DIR, `${name}-${spec.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
      writeFileSync(stubFile, stubs[spec]!);
      target = pathToFileURL(stubFile).href;
    } else if (spec === 'svelte') target = SVELTE_CLIENT;
    else if (spec === '@openkey/capability-review') {
      target = pathToFileURL(join(WEB_ROOT, '..', '..', 'packages', 'capability-review', 'src', 'index.ts')).href;
    } else if (spec.startsWith('$lib/') && spec.endsWith('.svelte')) {
      target = compileComponent(join(WEB_ROOT, 'src/lib', spec.slice(5)), name, stubs);
    } else if (spec.startsWith('$lib/')) target = pathToFileURL(join(WEB_ROOT, 'src/lib', spec.slice(5))).href;
    code += `from '${target}'`;
    cursor = match.index! + match[0].length;
  }
  code += compiled.js.code.slice(cursor);
  const out = join(OUT_DIR, `${name}-${file.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, code);
  const url = pathToFileURL(out).href;
  compiledFiles.set(`${name}:${file}`, url);
  return url;
}

const PAGES = [
  {
    name: 'popup',
    file: join(WEB_ROOT, 'src/routes/widget/sign/+page.svelte'),
    url: 'https://openkey.test/widget/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz',
    adapter: '$lib/components/signing/popup-signing-adapter.svelte',
    adapterFile: join(WEB_ROOT, 'src/lib/components/signing/popup-signing-adapter.svelte'),
  },
  {
    name: 'embed',
    file: join(WEB_ROOT, 'src/routes/widget/embed/sign/+page.svelte'),
    url: 'https://openkey.test/widget/embed/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz',
    adapter: '$lib/components/signing/iframe-signing-adapter.svelte',
    adapterFile: join(WEB_ROOT, 'src/lib/components/signing/iframe-signing-adapter.svelte'),
  },
] as const;

const emptyUrl = compileSource(EMPTY_SOURCE, 'empty');
const Pages: Record<string, unknown> = {};
for (const page of PAGES) {
  const stubs: Record<string, string> = {
    ...baseStubs(page.url),
    '$lib/components/auth/embedded-sign-in.svelte': `export { default } from '${emptyUrl}';`,
  };
  const realAdapterUrl = compileComponent(page.adapterFile, page.name, stubs);
  stubs[page.adapter] = `export { default } from '${compileSource(wrapperSource(realAdapterUrl), `${page.name}-wrapper`)}';`;
  Pages[page.name] = (await import(compileComponent(page.file, page.name, stubs))).default;
}

// A plain sign-in message: no ReCap, so the page signs the exact bytes and asks for the offer for them.
function plainSiwe(): string {
  const now = new Date();
  return [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:',
    KEY.address,
    '',
    'Sign in to the demo.',
    '',
    'URI: https://cli.tinycloud.xyz',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    `Issued At: ${now.toISOString()}`,
    `Expiration Time: ${new Date(now.getTime() + 3_600_000).toISOString()}`,
  ].join('\n');
}

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 2000; i++) {
    flushSync();
    if (condition()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

type Screen = { approve: () => HTMLButtonElement; tap: () => void };

async function withPage(
  pageName: 'popup' | 'embed',
  setup: { framed: boolean; observer: 1 | 2 | null },
  body: (screen: Screen) => Promise<void>,
) {
  reset();
  FakeObserver.all = [];
  if (setup.observer === null) dropObserver();
  else useObserver(setup.observer);
  setTop(setup.framed ? {} : null);
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Pages[pageName], { target, props: {} });
  try {
    await until(() => shared().options !== null, 'the transport');
    shared().options!.onRequest({ requestId: 'req-1', protocolVersion: 1, data: { message: plainSiwe(), keyId: KEY.id } });
    const approve = () => target.querySelector('button.approve') as HTMLButtonElement;
    await until(() => approve() !== null, 'the Approve button');
    await body({ approve, tap: () => { approve().click(); } });
  } finally {
    unmount(app);
    target.remove();
    setTop(null);
    dropObserver();
    Object.assign(console, realConsole);
  }
}

const flowOf = (call: unknown[] | undefined, index: number) => call?.[index] as string | undefined;

for (const { name } of PAGES) {
  describe(`the ${name} page in a frame holds the cover to the visibility of Approve`, () => {
    test('Approve in plain view for 500 ms uses the cover: the flow id is named on the offer and the signature, and no prompt is shown', async () => {
      await withPage(name, { framed: true, observer: 2 }, async ({ approve, tap }) => {
        await until(() => !approve().disabled, 'Approve to be ready');
        expect(shared().offerCalls).toHaveLength(1);
        expect(flowOf(shared().offerCalls[0], 3)).toMatch(FLOW_SHAPE);
        // The observer asks for the strict v2 report.
        const options = FakeObserver.all.at(-1)!.options;
        expect(options).toMatchObject({ threshold: 1, trackVisibility: true, delay: 100 });

        report(true);
        advance(500);
        tap();
        await until(() => shared().signCalls.length === 1, 'the sign request');

        expect(shared().prompts).toEqual([COVERED]);
        expect(shared().signCalls[0]![4]).toBeUndefined();
        expect(flowOf(shared().signCalls[0], 5)).toBe(flowOf(shared().offerCalls[0], 3));
        expect(shared().offerCalls).toHaveLength(1);
      });
    });

    test('Approve in view for 499 ms is not the cover: the tap sends nothing, a fresh offer is fetched without the flow id, and the next tap asks for the passkey', async () => {
      await withPage(name, { framed: true, observer: 2 }, async ({ approve, tap }) => {
        await until(() => !approve().disabled, 'Approve to be ready');
        report(true);
        advance(499);
        tap();
        await until(() => shared().offerCalls.length === 2, 'the fresh offer request');

        expect(shared().signCalls).toEqual([]);
        expect(shared().prompts).toEqual([]);
        expect(flowOf(shared().offerCalls[1], 3)).toBeUndefined();

        await until(() => !approve().disabled, 'Approve to be ready again');
        tap();
        await until(() => shared().signCalls.length === 1, 'the sign request');

        expect(shared().prompts).toEqual([REQUIRED]);
        expect(shared().signCalls[0]![4]).toEqual(ASSERTION);
        expect(flowOf(shared().signCalls[0], 5)).toBeUndefined();
        expect(shared().offerCalls).toHaveLength(2);
      });
    });

    test('a report that Approve is covered or faded, however long it was in view before, is not the cover', async () => {
      await withPage(name, { framed: true, observer: 2 }, async ({ approve, tap }) => {
        await until(() => !approve().disabled, 'Approve to be ready');
        report(true);
        advance(5_000);
        report(false);
        tap();
        await until(() => shared().offerCalls.length === 2, 'the fresh offer request');

        expect(shared().signCalls).toEqual([]);
        expect(flowOf(shared().offerCalls[1], 3)).toBeUndefined();
      });
    });

    test('a report that never came is not the cover', async () => {
      await withPage(name, { framed: true, observer: 2 }, async ({ approve, tap }) => {
        await until(() => !approve().disabled, 'Approve to be ready');
        advance(5_000);
        tap();
        await until(() => shared().offerCalls.length === 2, 'the fresh offer request');

        expect(shared().signCalls).toEqual([]);
      });
    });

    test('where the browser has no observer v2 the page never names the flow, so the passkey is asked straight away', async () => {
      for (const observer of [1, null] as const) {
        await withPage(name, { framed: true, observer }, async ({ approve, tap }) => {
          await until(() => !approve().disabled, 'Approve to be ready');
          expect(shared().offerCalls).toHaveLength(1);
          expect(flowOf(shared().offerCalls[0], 3)).toBeUndefined();

          advance(5_000);
          tap();
          await until(() => shared().signCalls.length === 1, 'the sign request');

          expect(shared().prompts).toEqual([REQUIRED]);
          expect(shared().signCalls[0]![4]).toEqual(ASSERTION);
          expect(flowOf(shared().signCalls[0], 5)).toBeUndefined();
        });
      }
    });

    test('a page that is not framed uses the cover at once, with no observer', async () => {
      await withPage(name, { framed: false, observer: null }, async ({ approve, tap }) => {
        await until(() => !approve().disabled, 'Approve to be ready');
        expect(flowOf(shared().offerCalls[0], 3)).toMatch(FLOW_SHAPE);

        tap();
        await until(() => shared().signCalls.length === 1, 'the sign request');

        expect(shared().prompts).toEqual([COVERED]);
        expect(shared().signCalls[0]![4]).toBeUndefined();
        expect(flowOf(shared().signCalls[0], 5)).toMatch(FLOW_SHAPE);
        expect(shared().offerCalls).toHaveLength(1);
      });
    });

    test('a top window that cannot be read counts as a frame', async () => {
      reset();
      useObserver(2);
      Object.defineProperty(win, 'top', { configurable: true, get() { throw new Error('cross-origin'); } });
      try {
        const { isFramed } = await import('./approve-visibility');
        expect(isFramed()).toBe(true);
      } finally {
        setTop(null);
        dropObserver();
      }
    });
  });
}

// ---- the preview path: a request the owner can narrow ------------------------

const ADDR = KEY.address;
const SPACE = `tinycloud:pkh:eip155:1:${ADDR}:default`;
const recap = (att: Record<string, Record<string, unknown[]>>) =>
  `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;

function reviewSiwe(): string {
  const now = new Date();
  return [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:',
    ADDR,
    '',
    'TinyCloud delegation',
    '',
    'URI: https://cli.tinycloud.xyz',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    `Issued At: ${now.toISOString()}`,
    `Expiration Time: ${new Date(now.getTime() + 3_600_000).toISOString()}`,
    'Resources:',
    `- ${recap({ [`${SPACE}/notes/`]: { 'tinycloud.kv/get': [{}] } })}`,
  ].join('\n');
}

async function untilTimers(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

type Call = { name: string; headers: Record<string, string>; body: Record<string, unknown> };

async function withPreviewPage(
  pageName: 'popup' | 'embed',
  body: (screen: Screen & { calls: Call[]; named: (name: string) => Call[] }) => Promise<void>,
) {
  reset();
  useObserver(2);
  setTop({});
  const calls: Call[] = [];
  const realFetch = globalThis.fetch;
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  let previews = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const name = String(input).split('/').pop() ?? '';
    const headers = { ...((init?.headers ?? {}) as Record<string, string>) };
    const request = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    calls.push({ name, headers, body: request });
    let answer: unknown = { error: 'unexpected' };
    let status = 500;
    if (name === 'authorize-sign-prepare') {
      status = 200;
      answer = { authorizationContextToken: 'context-token', expiresAt: new Date(Date.now() + 300_000).toISOString() };
    }
    if (name === 'authorize-sign-preview') {
      const ids = request.selectedActionIds as string[];
      status = 200;
      answer = {
        signedMessage: 'signed', previewApprovalToken: `approval-${++previews}`,
        previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        authorizationContextToken: 'context-token', selectedActionKeys: ids,
        permissions: ids.map((id) => {
          const [service, space, path, ability] = id.split('\0');
          return { service, space, path, actions: [ability] };
        }),
        // The offer is covered when the flow id is named and asks for the passkey when it is not.
        passkey: headers['x-openkey-passkey-flow'] ? COVERED : REQUIRED,
      };
    }
    if (name === 'authorize-sign') {
      status = 200;
      answer = {
        signature: `0x${'11'.repeat(65)}`, address: ADDR, signedMessage: 'signed', selectedActionKeys: ['key-1'],
        permissions: [{ service: 'tinycloud.kv', space: SPACE, path: 'notes/', actions: ['tinycloud.kv/get'] }],
      };
    }
    return { ok: status === 200, status, headers: new Headers({ Date: new Date().toUTCString() }), json: async () => answer };
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Pages[pageName], { target, props: {} });
  try {
    await untilTimers(() => shared().options !== null, 'the transport');
    shared().options!.onRequest({
      requestId: 'req-1', protocolVersion: 1,
      data: {
        message: reviewSiwe(), keyId: KEY.id, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
        host: 'https://node.tinycloud.xyz',
      },
    });
    const approve = () => target.querySelector('button.approve') as HTMLButtonElement;
    await untilTimers(() => approve() !== null && !approve().disabled, 'Approve to be ready');
    await body({
      approve, tap: () => { approve().click(); }, calls,
      named: (name) => calls.filter((call) => call.name === name),
    });
  } finally {
    unmount(app);
    target.remove();
    setTop(null);
    dropObserver();
    globalThis.fetch = realFetch;
    Object.assign(console, realConsole);
  }
}

const HEADER = 'x-openkey-passkey-flow';

for (const { name } of PAGES) {
  describe(`the ${name} page in a frame holds the preview cover to the visibility of Approve`, () => {
    test('Approve in plain view for 500 ms uses the cover: the preview and the approval carry the flow id and no assertion is sent', async () => {
      await withPreviewPage(name, async ({ tap, named }) => {
        expect(named('authorize-sign-preview')).toHaveLength(1);
        expect(named('authorize-sign-preview')[0]!.headers[HEADER]).toMatch(FLOW_SHAPE);

        report(true);
        advance(500);
        tap();
        await untilTimers(() => named('authorize-sign').length === 1, 'the approval');

        const approval = named('authorize-sign')[0]!;
        expect(approval.headers[HEADER]).toBe(named('authorize-sign-preview')[0]!.headers[HEADER]);
        expect(approval.body.passkeyAssertion).toBeUndefined();
        expect(named('authorize-sign-preview')).toHaveLength(1);
      });
    });

    test('Approve in view for 499 ms is not the cover: a fresh preview is fetched without the flow id, and the next tap sends the assertion without it', async () => {
      await withPreviewPage(name, async ({ approve, tap, named }) => {
        report(true);
        advance(499);
        tap();
        await untilTimers(() => named('authorize-sign-preview').length === 2, 'the fresh preview');

        expect(named('authorize-sign')).toEqual([]);
        expect(named('authorize-sign-preview')[1]!.headers[HEADER]).toBeUndefined();
        expect(shared().prompts).toEqual([]);

        await untilTimers(() => !approve().disabled, 'Approve to be ready again');
        tap();
        await untilTimers(() => named('authorize-sign').length === 1, 'the approval');

        const approval = named('authorize-sign')[0]!;
        expect(shared().prompts).toEqual([REQUIRED]);
        expect(approval.body.passkeyAssertion).toEqual(ASSERTION);
        expect(approval.headers[HEADER]).toBeUndefined();
        expect(approval.body.previewApprovalToken).toBe('approval-2');
      });
    });

    test('a cover placed over Approve after it was in view for long is not the cover', async () => {
      await withPreviewPage(name, async ({ tap, named }) => {
        report(true);
        advance(10_000);
        report(false);
        tap();
        await untilTimers(() => named('authorize-sign-preview').length === 2, 'the fresh preview');

        expect(named('authorize-sign')).toEqual([]);
        expect(named('authorize-sign-preview')[1]!.headers[HEADER]).toBeUndefined();
      });
    });
  });
}
