// One passkey per web sign interaction, as the production pages send it. Mounts the sign pop-up (widget/sign), the sign
// iframe (widget/embed/sign) and the embedded sign-in, and checks which flow id each call carries: the id the page drew
// itself, never one from the app's request, on the preview, the approval, the exact-byte offer and signature, and the
// passkey sign-in; the pop-up's id crosses the login redirect in the tab's storage; a cancelled request releases it.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-web-flow.'));
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
const HEADER = 'x-openkey-passkey-flow';
const APP_CHOSEN = `w.${'A'.repeat(32)}`;

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

const PAGES = [
  {
    name: 'popup',
    file: join(WEB_ROOT, 'src/routes/widget/sign/+page.svelte'),
    url: 'https://openkey.test/widget/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz',
    adapter: '$lib/components/signing/popup-signing-adapter.svelte',
  },
  {
    name: 'embed',
    file: join(WEB_ROOT, 'src/routes/widget/embed/sign/+page.svelte'),
    url: 'https://openkey.test/widget/embed/sign?origin=https%3A%2F%2Fcli.tinycloud.xyz',
    adapter: '$lib/components/signing/iframe-signing-adapter.svelte',
  },
] as const;

const adapterUrl = compileSource(ADAPTER_SOURCE, 'adapter');
const emptyUrl = compileSource(EMPTY_SOURCE, 'empty');
const Pages: Record<string, unknown> = {};
for (const page of PAGES) {
  const stubs: Record<string, string> = {
    ...baseStubs(page.url),
    [page.adapter]: `export { default } from '${adapterUrl}';`,
    '$lib/components/auth/embedded-sign-in.svelte': `export { default } from '${emptyUrl}';`,
  };
  Pages[page.name] = (await import(compileComponent(page.file, page.name, stubs))).default;
}
const EmbeddedSignIn = (await import(compileComponent(
  join(WEB_ROOT, 'src/lib/components/auth/embedded-sign-in.svelte'),
  'sign-in',
  {
    ...baseStubs('https://openkey.test/widget/embed/sign'),
    './social-buttons.svelte': `export { default } from '${emptyUrl}';`,
    './new-account-confirmation.svelte': `export { default } from '${emptyUrl}';`,
  },
))).default;

// ---- the request ------------------------------------------------------------

const ADDR = KEY.address;
const SPACE = `tinycloud:pkh:eip155:1:${ADDR}:default`;
const recap = (att: Record<string, Record<string, unknown[]>>) =>
  `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;

function siwe(withRecap: boolean): string {
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
    ...(withRecap ? ['Resources:', `- ${recap({ [`${SPACE}/notes/`]: { 'tinycloud.kv/get': [{}] } })}`] : []),
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

const SIGNED = { signature: `0x${'11'.repeat(65)}`, address: ADDR, signedMessage: 'signed', selectedActionKeys: ['key-1'], permissions: [] };

/** Mounts a page, sends it the request, and lets `act` drive it; every server call it makes is returned. */
async function withPage(
  pageName: 'popup' | 'embed',
  options: { signedIn?: boolean; recap: boolean; data?: Record<string, unknown> },
  act: (screen: { adapter: NonNullable<Shared['adapter']>; calls: Call[]; target: HTMLElement }) => Promise<void>,
) {
  reset(options.signedIn ?? true);
  const calls: Call[] = [];
  const realFetch = globalThis.fetch;
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const name = String(input).split('/').pop() ?? '';
    calls.push({ name, headers: { ...(init?.headers as Record<string, string> | undefined) }, body: JSON.parse(String(init?.body ?? '{}')) });
    let answer: unknown = { released: true };
    if (name === 'authorize-sign-prepare') answer = { authorizationContextToken: 'context-token', expiresAt: new Date(Date.now() + 300_000).toISOString() };
    if (name === 'authorize-sign-preview') {
      const ids = (JSON.parse(String(init?.body)) as { selectedActionIds: string[] }).selectedActionIds;
      const permissions = ids.map((id) => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      });
      answer = {
        signedMessage: 'signed', previewApprovalToken: 'approval', previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        authorizationContextToken: 'context-token', selectedActionKeys: ids, permissions,
      };
    }
    if (name === 'authorize-sign') answer = SIGNED;
    return { ok: true, status: 200, headers: new Headers({ Date: new Date().toUTCString() }), json: async () => answer };
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
        message: siwe(options.recap), keyId: KEY.id, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
        host: 'https://node.tinycloud.xyz', ...options.data,
      },
    });
    if (options.signedIn ?? true) {
      await until(() => shared().adapter?.canUseAuthorizeSign === options.recap, 'the review');
      if (options.recap) await until(() => shared().adapter?.previewReady === true, 'the preview');
    }
    await act({ adapter: shared().adapter!, calls, target });
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
    Object.assign(console, realConsole);
  }
  return calls;
}

const flowOf = (headers: Record<string, string>) => headers[HEADER];

// The app's own request names a flow in every place it can: none of them is the page's flow id.
const APP_REQUEST = { flowId: APP_CHOSEN, passkeyFlow: APP_CHOSEN, [HEADER]: APP_CHOSEN, headers: { [HEADER]: APP_CHOSEN } };

for (const { name } of PAGES) {
  describe(`the ${name} page`, () => {
    test('the preview and the approval carry the flow id the page drew, not one from the app', async () => {
      const calls = await withPage(name, { recap: true, data: APP_REQUEST }, async ({ adapter }) => {
        await adapter.approveAndSign();
      });
      const preview = calls.find((call) => call.name === 'authorize-sign-preview')!;
      const approve = calls.find((call) => call.name === 'authorize-sign')!;
      expect(flowOf(preview.headers)).toMatch(FLOW_SHAPE);
      expect(flowOf(approve.headers)).toBe(flowOf(preview.headers));
      expect(flowOf(approve.headers)).not.toBe(APP_CHOSEN);
      // The prepare call names no flow: it offers no passkey.
      expect(flowOf(calls.find((call) => call.name === 'authorize-sign-prepare')!.headers)).toBeUndefined();
      // Nothing in a body carries it.
      expect(JSON.stringify(calls.map((call) => call.body))).not.toContain('w.');
    });

    test('the exact-byte offer and signature carry the same flow id', async () => {
      await withPage(name, { recap: false, data: APP_REQUEST }, async ({ adapter }) => {
        await until(() => shared().offerCalls.length === 1, 'the offer');
        await adapter.approveAndSign();
        await until(() => shared().signCalls.length === 1, 'the signature');
      });
      const offerFlow = shared().offerCalls[0]![3];
      const signFlow = shared().signCalls[0]![5];
      expect(offerFlow).toMatch(FLOW_SHAPE);
      expect(signFlow).toBe(offerFlow);
      expect(signFlow).not.toBe(APP_CHOSEN);
    });

    test('each request gets its own flow id', async () => {
      const ids: string[] = [];
      for (let i = 0; i < 3; i++) {
        const calls = await withPage(name, { recap: true }, async ({ adapter }) => { await adapter.approveAndSign(); });
        ids.push(flowOf(calls.find((call) => call.name === 'authorize-sign')!.headers)!);
      }
      expect(new Set(ids).size).toBe(3);
    });

    test('cancelling releases the flow the preview carried, and the approval is not sent', async () => {
      const calls = await withPage(name, { recap: true }, async ({ adapter }) => { adapter.cancel(); await until(() => true, ''); });
      const preview = calls.find((call) => call.name === 'authorize-sign-preview')!;
      const release = calls.filter((call) => call.name === 'authorize-sign-release');
      expect(release).toHaveLength(1);
      expect(flowOf(release[0]!.headers)).toBe(flowOf(preview.headers));
      expect(calls.some((call) => call.name === 'authorize-sign')).toBe(false);
    });
  });
}

describe('the pop-up page across the login redirect', () => {
  test('the Sign In link keeps the page\'s flow id in this tab, and the page that opens after sign-in uses it and forgets it', async () => {
    sessionStorage.clear();
    let carried: string | null = null;
    await withPage('popup', { signedIn: false, recap: true }, async ({ target }) => {
      const link = await (async () => {
        await until(() => target.querySelector('a[href^="/auth/login"]') !== null, 'the Sign In link');
        return target.querySelector('a[href^="/auth/login"]') as HTMLAnchorElement;
      })();
      expect(link.getAttribute('href')).toContain('redirect=/widget/sign?origin=');
      document.addEventListener('click', (event: Event) => event.preventDefault(), { once: true });
      link.click();
      carried = sessionStorage.getItem('openkey_sign_flow');
    });
    expect(carried).toMatch(FLOW_SHAPE);

    // The page loads again after sign-in, with the user signed in and the app's request sent again.
    const calls = await withPage('popup', { signedIn: true, recap: true }, async ({ adapter }) => { await adapter.approveAndSign(); });
    expect(flowOf(calls.find((call) => call.name === 'authorize-sign-preview')!.headers)).toBe(carried);
    expect(flowOf(calls.find((call) => call.name === 'authorize-sign')!.headers)).toBe(carried);
    expect(sessionStorage.getItem('openkey_sign_flow')).toBeNull();
  });

  test('a stored value without the web shape is ignored and a fresh id is drawn', async () => {
    for (const stored of ['not-a-flow', 'x'.repeat(32), `W.${'A'.repeat(32)}`, `w.${'A'.repeat(31)}`, `w.${'A'.repeat(33)}`, `w.${'A'.repeat(31)}!`]) {
      sessionStorage.setItem('openkey_sign_flow', stored);
      const calls = await withPage('popup', { recap: true }, async ({ adapter }) => { await adapter.approveAndSign(); });
      const used = flowOf(calls.find((call) => call.name === 'authorize-sign')!.headers)!;
      expect(used, stored).toMatch(FLOW_SHAPE);
      expect(used, stored).not.toBe(stored);
      expect(sessionStorage.getItem('openkey_sign_flow')).toBeNull();
    }
  });
});

describe('the embedded sign-in', () => {
  async function press(props: Record<string, unknown>, embedContext: boolean) {
    reset();
    shared().embedContext = embedContext;
    const target = document.createElement('div');
    document.body.appendChild(target);
    const app = mount(EmbeddedSignIn, { target, props: { prompt: 'Sign in', onauthenticated: () => {}, ...props } });
    try {
      await until(() => [...target.querySelectorAll('button')].some((button) => button.textContent?.includes('Passkey')), 'the passkey button');
      [...target.querySelectorAll('button')].find((button) => button.textContent?.includes('Passkey'))!.click();
      await until(() => shared().embedCalls.length + shared().passkeyCalls.length === 1, 'the passkey sign-in');
    } finally {
      unmount(app);
      target.remove();
    }
  }

  test('the iframe sign-in names the flow on the verification, and the cookie sign-in names it as a header', async () => {
    await press({ flowId: APP_CHOSEN }, true);
    expect(shared().embedCalls[0]).toEqual([{ [HEADER]: APP_CHOSEN }]);
    expect(shared().passkeyCalls).toEqual([]);

    await press({ flowId: APP_CHOSEN }, false);
    expect(shared().passkeyCalls[0]).toEqual([{ fetchOptions: { headers: { [HEADER]: APP_CHOSEN } } }]);
    expect(shared().embedCalls).toEqual([]);
  });

  test('a sign-in opened for anything else names no flow', async () => {
    await press({}, true);
    expect(shared().embedCalls[0]).toEqual([undefined]);
    await press({}, false);
    expect(shared().passkeyCalls[0]).toEqual([undefined]);
  });
});
