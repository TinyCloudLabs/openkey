// Mounts the production embed page (widget/embed/sign) and popup page (widget/sign), each with its real signing adapter, and drives a sign-in whose app
// asked for renewal, holding the prepare answer. While the answer is out the access line reads "Checking renewal…"
// (no length, no date, no box) inside a polite live region. When it lands the line settles: the renewal line and box
// where the answer offers renewal, the length where it does not or where the prepare fails. An app that did not ask
// shows the length from the first render.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { termsAcceptedStubs } from './terms-accepted-stubs';

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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-renewal-checking.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
interface SvelteClient {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
}
const SVELTE_CLIENT = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = (await import(SVELTE_CLIENT)) as SvelteClient;

// ---- what the test and the page share ---------------------------------------

type Shared = { options: { onRequest: (request: unknown) => void } | null };
const store = globalThis as unknown as { __renewalChecking: Shared };
const shared = (): Shared => store.__renewalChecking;
store.__renewalChecking = { options: null };

const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };

const wrapperSource = (adapterUrl: string) => `<script>
  import Adapter from ${JSON.stringify(adapterUrl)};
  let { transport, ...rest } = $props();
</script>
<Adapter {transport} {...rest} layoutBlocked={false} />`;
const EMPTY_SOURCE = '<div data-testid="sign-in"></div>';

function compileSource(source: string, name: string): string {
  const out = compile(source, { generate: 'client', dev: false, name: 'Stub', filename: `${name}.svelte` }).js.code;
  const file = join(OUT_DIR, `${name}.mjs`);
  writeFileSync(file, out);
  return pathToFileURL(file).href;
}

const PAGES = {
  embed: {
    file: join(WEB_ROOT, 'src/routes/widget/embed/sign/+page.svelte'),
    url: 'https://openkey.test/widget/embed/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz',
    adapter: '$lib/components/signing/iframe-signing-adapter.svelte',
  },
  popup: {
    file: join(WEB_ROOT, 'src/routes/widget/sign/+page.svelte'),
    url: 'https://openkey.test/widget/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz',
    adapter: '$lib/components/signing/popup-signing-adapter.svelte',
  },
} as const;
type PageName = keyof typeof PAGES;

const baseStubs = (pageUrl: string): Record<string, string> => ({
  '$app/stores': `export const page = { subscribe(run) { run({ url: new URL(${JSON.stringify(pageUrl)}) }); return () => {}; } };`,
  '$lib/auth-client': `export const authErrorMessage = (e, fallback) => fallback;
    export const authClient = { useSession: () => ({ subscribe(run) { run({ data: { user: { id: 'user_1' } }, isPending: false }); return () => {}; } }) };`,
  '$lib/api': `export const api = { getKey: async () => ({ key: ${JSON.stringify(KEY)} }), listKeys: async () => ({ keys: [${JSON.stringify(KEY)}] }) };`,
  '$lib/embed-passkey': `export const isEmbedContext = () => true; export const getSessionToken = () => 'session-token';
    export const withSessionCredential = (init) => init; export const clearSessionToken = () => {};`,
  '$lib/widget-transport': `export const createWidgetTransport = (options) => {
      globalThis.__renewalChecking.options = options;
      return { emitReady() {}, emitResize() {}, emitLayoutSignal() {}, destroy() {}, respond() {} };
    };
    export const createIframeLayoutGate = () => ({ measure() {}, changed() {}, applied() {}, isCurrent: () => false, canApprove: () => true, destroy() {} });`,
});

const compiledFiles = new Map<string, string>();
function compileComponent(file: string, name: string, stubFiles: Record<string, string>): string {
  const cached = compiledFiles.get(`${name}:${file}`);
  if (cached) return cached;
  const compiled = compile(readFileSync(file, 'utf8'), { generate: 'client', dev: false, name: 'Subject', filename: file });
  let code = '';
  let cursor = 0;
  for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    code += compiled.js.code.slice(cursor, match.index);
    const spec = match[1]!;
    let target = spec;
    if (spec in stubFiles) {
      const stubFile = join(OUT_DIR, `${name}-stub-${spec.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
      writeFileSync(stubFile, stubFiles[spec]!);
      target = pathToFileURL(stubFile).href;
    } else if (spec === 'svelte') target = SVELTE_CLIENT;
    else if (spec === '@openkey/capability-review') {
      target = pathToFileURL(join(WEB_ROOT, '..', '..', 'packages', 'capability-review', 'src', 'index.ts')).href;
    } else if (spec.startsWith('$lib/') && spec.endsWith('.svelte')) {
      target = compileComponent(join(WEB_ROOT, 'src/lib', spec.slice(5)), name, stubFiles);
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

const emptyUrl = compileSource(EMPTY_SOURCE, 'empty');
const Pages: Record<string, unknown> = {};
for (const [name, page] of Object.entries(PAGES)) {
  const pageStubs: Record<string, string> = {
    ...baseStubs(page.url),
    '$lib/components/auth/embedded-sign-in.svelte': `export { default } from '${emptyUrl}';`,
    ...termsAcceptedStubs(emptyUrl),
  };
  const realAdapterUrl = compileComponent(join(WEB_ROOT, 'src/lib', page.adapter.slice(5)), name, pageStubs);
  pageStubs[page.adapter] = `export { default } from '${compileSource(wrapperSource(realAdapterUrl), `${name}-wrapper`)}';`;
  Pages[name] = (await import(compileComponent(page.file, name, pageStubs))).default;
}

// ---- the request ------------------------------------------------------------

const ADDR = KEY.address;
const SPACE = `tinycloud:pkh:eip155:1:${ADDR}:default`;
const recap = (att: Record<string, Record<string, unknown[]>>) =>
  `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;

function siwe(): string {
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

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

const ASK = { version: 1, leaseLifetimeSeconds: 7_776_000, purpose: 'standing' };

type Answer = { offer: { leaseLifetimeSeconds: number } | null } | { fail: string };

interface Screen {
  /** The prepare answer is out: the page has asked and has not been answered. */
  prepareAsked: () => boolean;
  /** Answers the held prepare request. */
  answer: (answer: Answer) => Promise<void>;
  line: () => string | null;
  lineElement: () => Element | null;
  box: () => HTMLInputElement | null;
  approve: () => HTMLButtonElement | null;
  bodyText: () => string;
}

const squash = (text: string | null | undefined) => (text ?? '').replace(/\s+/g, ' ').trim();

async function withPage(pageName: PageName, ask: Record<string, unknown> | undefined, body: (screen: Screen) => Promise<void>) {
  store.__renewalChecking = { options: null };
  let release: ((answer: Answer) => void) | null = null;
  let asked = false;
  const realFetch = globalThis.fetch;
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const name = String(input).split('/').pop() ?? '';
    const sent = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    let answer: unknown = { error: 'unexpected' };
    let status = 500;
    if (name === 'authorize-sign-prepare') {
      asked = true;
      const result = await new Promise<Answer>((resolve) => { release = resolve; });
      if ('fail' in result) throw new Error(result.fail);
      status = 200;
      answer = {
        authorizationContextToken: 'context-token',
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
        ...(result.offer ? { renewal: result.offer } : {}),
      };
    }
    if (name === 'authorize-sign-preview') {
      const ids = sent.selectedActionIds as string[];
      const permissions = ids.map((id) => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      });
      status = 200;
      answer = {
        signedMessage: 'signed', previewApprovalToken: 'approval', previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        authorizationContextToken: 'context-token', selectedActionKeys: ids, permissions,
        ...(sent.renewal ? { renewal: sent.renewal } : {}),
      };
    }
    return { ok: status === 200, status, headers: new Headers({ Date: new Date().toUTCString() }), json: async () => answer };
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Pages[pageName], { target, props: {} });
  try {
    await until(() => shared().options !== null, 'the transport');
    shared().options!.onRequest({
      requestId: 'req-1',
      protocolVersion: 1,
      data: {
        message: siwe(), keyId: KEY.id, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
        host: 'https://node.tinycloud.xyz', expiryChangeable: true, ...(ask ? { renewal: ask } : {}),
      },
    });
    await until(() => asked, 'the prepare request');
    const lineElement = () => target.querySelector('[data-testid="approval-expiry-line"]');
    await body({
      prepareAsked: () => asked,
      answer: async (answer) => {
        release!(answer);
        release = null;
        await until(() => lineElement() === null || !squash(lineElement()!.textContent).includes('Checking renewal'), 'the line to settle');
      },
      line: () => (lineElement() ? squash(lineElement()!.textContent) : null),
      lineElement,
      box: () => target.querySelector<HTMLInputElement>('.renewal-box'),
      approve: () => target.querySelector<HTMLButtonElement>('button.approve'),
      bodyText: () => squash(target.textContent),
    });
  } finally {
    // A held prepare must not outlive the test.
    if (release) (release as (answer: Answer) => void)({ fail: 'test over' });
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
    Object.assign(console, realConsole);
  }
}

const CHECKING = 'Checking renewal…';
const ONE_HOUR = /^This app's access to your data lasts 1 hour\.$/;
const LASTS = /access to your data lasts/;

for (const pageName of Object.keys(PAGES) as PageName[]) describe(`the ${pageName} page while the renewal offer is out`, () => {
  test('an app that asked shows "Checking renewal…" with no length, no date and no box, and Approve waits', async () => {
    await withPage(pageName, ASK, async ({ line, box, approve, bodyText, lineElement }) => {
      await until(() => line() !== null, 'the line');
      expect(line()).toBe(CHECKING);
      expect(bodyText()).not.toMatch(LASTS);
      expect(bodyText()).not.toMatch(/until [A-Z][a-z]{2} \d/);
      expect(box()).toBeNull();
      expect(approve()!.disabled).toBe(true);
      expect(lineElement()!.closest('[aria-live="polite"]')).not.toBeNull();
    });
  });

  test('an offer settles the line to the ticked renewal box and the placeholder is gone', async () => {
    await withPage(pageName, ASK, async ({ line, box, answer, bodyText, lineElement }) => {
      await until(() => line() === CHECKING, 'the placeholder');
      const live = lineElement()!.closest('[aria-live="polite"]')!;
      await answer({ offer: { leaseLifetimeSeconds: 7_776_000 } });
      expect(line()).toBe('This permission renews automatically for up to 90 days');
      expect(box()!.checked).toBe(true);
      expect(bodyText()).not.toContain(CHECKING);
      // The region that held the placeholder holds the settled line, so a screen reader hears it.
      expect(lineElement()!.closest('[aria-live="polite"]')).toBe(live);
    });
  });

  test('an answer without an offer settles the line to the length and the placeholder is gone', async () => {
    await withPage(pageName, ASK, async ({ line, box, answer, bodyText, lineElement }) => {
      await until(() => line() === CHECKING, 'the placeholder');
      const live = lineElement()!.closest('[aria-live="polite"]')!;
      await answer({ offer: null });
      expect(line()).toMatch(ONE_HOUR);
      expect(box()).toBeNull();
      expect(bodyText()).not.toContain(CHECKING);
      expect(lineElement()!.closest('[aria-live="polite"]')).toBe(live);
    });
  });

  test('a failed prepare settles the line to the length and shows the error; the placeholder is gone', async () => {
    await withPage(pageName, ASK, async ({ line, box, answer, bodyText }) => {
      await until(() => line() === CHECKING, 'the placeholder');
      await answer({ fail: 'prepare unreachable' });
      expect(line()).toMatch(ONE_HOUR);
      expect(box()).toBeNull();
      expect(bodyText()).not.toContain(CHECKING);
      expect(bodyText()).toContain('prepare unreachable');
    });
  });

  test('an app that did not ask shows the length from the first render, with no placeholder', async () => {
    await withPage(pageName, undefined, async ({ line, box, bodyText, prepareAsked }) => {
      await until(() => line() !== null, 'the line');
      expect(prepareAsked()).toBe(true);
      expect(line()).toMatch(ONE_HOUR);
      expect(box()).toBeNull();
      expect(bodyText()).not.toContain(CHECKING);
    });
  });
});
