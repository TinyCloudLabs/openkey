// The sign pop-up after the login round trip. The return is a client-side navigation, so the page is created twice in
// one document: the first instance reads the id the passkey sign-in named from the tab's storage and is destroyed, the
// second renders the request. The offer and the signature name the id the sign-in named, and a destroyed page leaves
// no message listener behind.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { termsAcceptedStubs } from './terms-accepted-stubs';
import { carryPopupSignFlow, newWebSignFlowId, popupSignFlowForLogin } from './web-sign-flow';

const win = new Window({ url: 'https://openkey.test/' });
(win as unknown as { postMessage: () => void }).postMessage = () => {};
Object.assign(globalThis, {
  window: win,
  document: win.document,
  HTMLElement: win.HTMLElement,
  HTMLInputElement: win.HTMLInputElement,
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-popup-remount.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
interface SvelteClient {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
}
const SVELTE_CLIENT = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = (await import(SVELTE_CLIENT)) as SvelteClient;

// ---- what the test and the pages share ------------------------------------

type Call = { name: string; headers: Record<string, string>; body: Record<string, unknown> };
type Shared = {
  adapter: { canUseAuthorizeSign: boolean; previewReady: boolean; approveAndSign: () => Promise<void>; cancel: () => void } | null;
  options: { onRequest: (request: unknown) => void } | null;
  signedIn: boolean;
  offerCalls: unknown[][];
  signCalls: unknown[][];
  passkeyCalls: unknown[][];
  embedCalls: unknown[][];
  embedContext: boolean;
};
const shared = (): Shared => (globalThis as unknown as { __flow: Shared }).__flow;
const reset = (signedIn = true) => {
  (globalThis as unknown as { __flow: Shared }).__flow = {
    adapter: null, options: null, signedIn, offerCalls: [], signCalls: [], passkeyCalls: [], embedCalls: [], embedContext: true,
  };
};
reset();

const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };
const FLOW_SHAPE = /^w\.[A-Za-z0-9_-]{32}$/;

const ADAPTER_SOURCE = `<script>
  let { transport } = $props();
  $effect(() => { globalThis.__flow.adapter = transport; });
</script>
<div data-testid="adapter"></div>`;
const EMPTY_SOURCE = '<div data-testid="sign-in"></div>';

function compileSource(source: string, name: string): string {
  const out = compile(source, { generate: 'client', dev: false, name: 'Stub', filename: `${name}.svelte` }).js.code;
  const file = join(OUT_DIR, `${name}.mjs`);
  writeFileSync(file, out);
  return pathToFileURL(file).href;
}

const baseStubs = (pageUrl: string): Record<string, string> => ({
  '$app/stores': `export const page = { subscribe(run) { run({ url: new URL(${JSON.stringify(pageUrl)}) }); return () => {}; } };`,
  '$lib/auth-client': `export const authErrorMessage = (e, fallback) => fallback;
    export const authClient = {
      useSession: () => ({ subscribe(run) { run({ data: globalThis.__flow.signedIn ? { user: { id: 'user_1' } } : null, isPending: false }); return () => {}; } }),
      signIn: { passkey: async (...args) => { globalThis.__flow.passkeyCalls.push(args); return {}; } },
    };`,
  '$lib/api': `export const api = {
    getKey: async () => ({ key: ${JSON.stringify(KEY)} }),
    listKeys: async () => ({ keys: [${JSON.stringify(KEY)}] }),
    signMessagePasskey: async (...args) => { globalThis.__flow.offerCalls.push(args); return { required: false }; },
    signMessage: async (...args) => { globalThis.__flow.signCalls.push(args); return { signature: '0x${'11'.repeat(65)}', address: ${JSON.stringify(KEY.address)} }; },
  };`,
  '$lib/embed-passkey': `export const isEmbedContext = () => globalThis.__flow.embedContext; export const getSessionToken = () => 'session-token';
    export const withSessionCredential = (init) => init; export const clearSessionToken = () => {};
    export const embedSignInPasskey = async (...args) => { globalThis.__flow.embedCalls.push(args); return {}; };
    export const embedSendEmailOtp = async () => {}; export const embedVerifyEmailOtp = async () => ({}); export const embedCreateAccount = async () => '';`,
  '$lib/social-auth': `export const loadConfiguredSocialProviders = async () => []; export const signInWithSocialPopup = async () => {};`,
  '$lib/widget-transport': `export const createWidgetTransport = (options) => {
      globalThis.__flow.options = options;
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

const PAGE = {
  file: join(WEB_ROOT, 'src/routes/widget/sign/+page.svelte'),
  url: 'https://openkey.test/widget/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz',
  adapter: '$lib/components/signing/popup-signing-adapter.svelte',
};

const adapterUrl = compileSource(ADAPTER_SOURCE, 'adapter');
const emptyUrl = compileSource(EMPTY_SOURCE, 'empty');
const Popup = (await import(compileComponent(PAGE.file, 'popup', {
  ...baseStubs(PAGE.url),
  [PAGE.adapter]: `export { default } from '${adapterUrl}';`,
  '$lib/components/auth/embedded-sign-in.svelte': `export { default } from '${emptyUrl}';`,
  ...termsAcceptedStubs(emptyUrl),
}))).default;

const ADDR = KEY.address;
const siwe = () => {
  const now = new Date();
  return [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', ADDR, '', 'TinyCloud delegation', '',
    'URI: https://cli.tinycloud.xyz', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
    `Issued At: ${now.toISOString()}`, `Expiration Time: ${new Date(now.getTime() + 3_600_000).toISOString()}`,
  ].join('\n');
};

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

// The message listeners the pages hold on the window right now.
const messageListeners = new Set<unknown>();
const realAdd = win.addEventListener.bind(win);
const realRemove = win.removeEventListener.bind(win);
(win as unknown as { addEventListener: unknown }).addEventListener = (type: string, listener: unknown, ...more: unknown[]) => {
  if (type === 'message') messageListeners.add(listener);
  return (realAdd as (...args: unknown[]) => void)(type, listener, ...more);
};
(win as unknown as { removeEventListener: unknown }).removeEventListener = (type: string, listener: unknown, ...more: unknown[]) => {
  if (type === 'message') messageListeners.delete(listener);
  return (realRemove as (...args: unknown[]) => void)(type, listener, ...more);
};

function mountPopup() {
  shared().options = null;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Popup, { target, props: {} });
  return { stop: () => { unmount(app); target.remove(); } };
}

/** Carries an id to the login page, creates the page twice as the client-side return does, and signs on the second. */
async function loginReturn() {
  reset(true);
  sessionStorage.clear();
  const heldBefore = messageListeners.size;
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  try {
    // The first sign page drew this id and the Sign In link carried it to the login page, which names it on its
    // passkey sign-in.
    carryPopupSignFlow(newWebSignFlowId());
    const signInFlow = popupSignFlowForLogin('/widget/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz', 'https://openkey.test');

    // The login returns by a client-side navigation: the first page instance is created and destroyed before the
    // second one renders the request.
    const first = mountPopup();
    await until(() => shared().options !== null, 'the first transport');
    first.stop();
    const listenersAfterFirst = messageListeners.size - heldBefore;

    const second = mountPopup();
    try {
      await until(() => shared().options !== null, 'the second transport');
      shared().options!.onRequest({
        requestId: 'req-1', protocolVersion: 1,
        data: { message: siwe(), keyId: KEY.id, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz' },
      });
      await until(() => shared().adapter?.canUseAuthorizeSign === false && shared().offerCalls.length === 1, 'the offer');
      await shared().adapter!.approveAndSign();
      await until(() => shared().signCalls.length === 1, 'the signature');
    } finally {
      second.stop();
    }
    return { signInFlow, listenersAfterFirst, listenersAfterSecond: messageListeners.size - heldBefore };
  } finally {
    Object.assign(console, realConsole);
  }
}

describe('the pop-up page created twice after the login round trip', () => {
  test('the offer and the signature name the flow id the passkey sign-in named', async () => {
    const { signInFlow } = await loginReturn();
    expect(signInFlow).toMatch(FLOW_SHAPE);
    expect(shared().offerCalls[0]![3]).toBe(signInFlow);
    expect(shared().signCalls[0]![5]).toBe(signInFlow);
  });

  test('a destroyed page leaves no message listener on the window', async () => {
    const { listenersAfterFirst, listenersAfterSecond } = await loginReturn();
    expect(listenersAfterFirst).toBe(0);
    expect(listenersAfterSecond).toBe(0);
  });
});
