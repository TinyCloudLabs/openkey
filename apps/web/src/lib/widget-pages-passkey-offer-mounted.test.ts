// Mounts the production popup page (widget/sign) and embed page (widget/embed/sign) with their real signing adapters
// and drives a plain sign request (the exact-byte path), where Approve needs the passkey offer for exactly those
// bytes. Approve sends nothing until the offer has landed: while it is on its way the button is busy, after a failed
// fetch the page shows the retry line and the next Approve fetches the offer again, and once the offer has landed
// Approve opens the passkey step and sends its assertion.
//
// The passkey prompt is replaced by a recorder that answers with a fixed assertion; the page, its adapter and the
// approval screen are as built.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { passkeyApprovalCopy, type ApprovalPasskeyNeed } from './approval-passkey';
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-passkey-offer.'));
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

type Transport = { approveAndSign: () => Promise<void> };
type Shared = {
  options: { onRequest: (request: unknown) => void } | null;
  transport: (() => Transport) | null;
  offer: () => Promise<ApprovalPasskeyNeed>;
  offerCalls: unknown[][];
  signCalls: unknown[][];
  prompts: Array<ApprovalPasskeyNeed | null>;
  signErrors: unknown[];
};
const store = globalThis as unknown as { __passkeyOffer: Shared };
const shared = (): Shared => store.__passkeyOffer;
const reset = (offer: () => Promise<ApprovalPasskeyNeed>) => {
  store.__passkeyOffer = { options: null, transport: null, offer, offerCalls: [], signCalls: [], prompts: [], signErrors: [] };
};

const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };
const ASSERTION = { challengeToken: 'challenge-1', response: { id: 'credential-1' } };
const REQUIRED = { required: true, challengeToken: 'challenge-1', options: { challenge: 'abc' } } as unknown as ApprovalPasskeyNeed;
const NOT_REQUIRED: ApprovalPasskeyNeed = { required: false };

// Hands the page's transport to the test and passes everything else to the real adapter. The embed adapter holds
// Approve back until its frame has settled; the wrapper lifts only that hold.
const wrapperSource = (adapterUrl: string) => `<script>
  import Adapter from ${JSON.stringify(adapterUrl)};
  let { transport, ...rest } = $props();
  $effect(() => { globalThis.__passkeyOffer.transport = () => transport; });
</script>
<Adapter {transport} {...rest} layoutBlocked={false} />`;
const EMPTY_SOURCE = '<div data-testid="sign-in"></div>';

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
  '$lib/api': `export const api = {
    getKey: async () => ({ key: ${JSON.stringify(KEY)} }),
    listKeys: async () => ({ keys: [${JSON.stringify(KEY)}] }),
    signMessagePasskey: (...args) => { globalThis.__passkeyOffer.offerCalls.push(args); return globalThis.__passkeyOffer.offer(); },
    signMessage: async (...args) => {
      globalThis.__passkeyOffer.signCalls.push(args);
      const refusal = globalThis.__passkeyOffer.signErrors.shift();
      if (refusal) throw refusal;
      return { signature: '0x${'11'.repeat(65)}', address: ${JSON.stringify(KEY.address)} };
    },
  };`,
  '$lib/approval-passkey': `export * from ${JSON.stringify(REAL_PASSKEY_MODULE)};
    export const answerApprovalPasskey = async (need) => {
      globalThis.__passkeyOffer.prompts.push(need ?? null);
      return need?.required ? ${JSON.stringify(ASSERTION)} : undefined;
    };`,
  '$lib/embed-passkey': `export const isEmbedContext = () => true; export const getSessionToken = () => 'session-token';
    export const withSessionCredential = (init) => init; export const clearSessionToken = () => {};`,
  '$lib/widget-transport': `export const createWidgetTransport = (options) => {
      globalThis.__passkeyOffer.options = options;
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
    ...termsAcceptedStubs(emptyUrl),
  };
  const realAdapterUrl = compileComponent(page.adapterFile, page.name, stubs);
  stubs[page.adapter] = `export { default } from '${compileSource(wrapperSource(realAdapterUrl), `${page.name}-wrapper`)}';`;
  Pages[page.name] = (await import(compileComponent(page.file, page.name, stubs))).default;
}

// ---- the request ------------------------------------------------------------

// A plain sign-in message: no ReCap, so the page signs the exact bytes and needs the offer for them.
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

const deferred = <T>() => Promise.withResolvers<T>();

async function withPage(
  pageName: 'popup' | 'embed',
  offer: () => Promise<ApprovalPasskeyNeed>,
  body: (screen: {
    approve: () => HTMLButtonElement;
    alertText: () => string;
    tap: () => void;
    transport: () => Transport;
  }) => Promise<void>,
) {
  reset(offer);
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Pages[pageName], { target, props: {} });
  try {
    await until(() => shared().options !== null, 'the transport');
    shared().options!.onRequest({
      requestId: 'req-1',
      protocolVersion: 1,
      data: { message: plainSiwe(), keyId: KEY.id },
    });
    const approve = () => target.querySelector('button.approve') as HTMLButtonElement;
    await until(() => approve() !== null, 'the Approve button');
    await body({
      approve,
      alertText: () => [...target.querySelectorAll('[role="alert"]')].map((node) => node.textContent?.trim()).join(' '),
      tap: () => { approve().click(); },
      transport: () => shared().transport!(),
    });
  } finally {
    unmount(app);
    target.remove();
    Object.assign(console, realConsole);
  }
}

for (const { name } of PAGES) {
  describe(`the ${name} page's Approve and the passkey offer for the exact bytes`, () => {
    test('Approve before the offer lands sends nothing and the button is busy', async () => {
      const pending = deferred<ApprovalPasskeyNeed>();
      await withPage(name, () => pending.promise, async ({ approve, tap, transport }) => {
        await until(() => shared().offerCalls.length === 1, 'the offer request');
        expect(approve().disabled).toBe(true);
        expect(approve().textContent).toContain('Getting ready');

        tap();
        await transport().approveAndSign();
        flushSync();

        expect(shared().prompts).toEqual([]);
        expect(shared().signCalls).toEqual([]);
        expect(shared().offerCalls).toHaveLength(1);
        expect(approve().disabled).toBe(true);
        pending.resolve(NOT_REQUIRED);
      });
    });

    test('once the offer has landed Approve opens the passkey step and sends the assertion', async () => {
      const pending = deferred<ApprovalPasskeyNeed>();
      await withPage(name, () => pending.promise, async ({ approve, tap }) => {
        await until(() => shared().offerCalls.length === 1, 'the offer request');
        pending.resolve(REQUIRED);
        await until(() => !approve().disabled, 'Approve to be ready');
        // The landing of the offer approves nothing by itself.
        expect(shared().prompts).toEqual([]);
        expect(shared().signCalls).toEqual([]);

        tap();
        await until(() => shared().signCalls.length === 1, 'the sign request');

        expect(shared().prompts).toEqual([REQUIRED]);
        const [keyId, , , , assertion] = shared().signCalls[0]!;
        expect(keyId).toBe(KEY.id);
        expect(assertion).toEqual(ASSERTION);
      });
    });

    test('an offer that says no passkey is needed is answered with no assertion', async () => {
      await withPage(name, async () => NOT_REQUIRED, async ({ approve, tap }) => {
        await until(() => !approve().disabled, 'Approve to be ready');

        tap();
        await until(() => shared().signCalls.length === 1, 'the sign request');

        const [, , , , assertion] = shared().signCalls[0]!;
        expect(assertion).toBeUndefined();
      });
    });

    test('a failed offer fetch shows the retry line; Approve fetches again and sends nothing until it lands', async () => {
      const second = deferred<ApprovalPasskeyNeed>();
      let fetches = 0;
      await withPage(name, () => (++fetches === 1 ? Promise.reject(new Error('offline')) : second.promise), async ({ approve, alertText, tap }) => {
        await until(() => alertText().includes(passkeyApprovalCopy.offerFailed), 'the retry line');
        expect(approve().disabled).toBe(false);
        expect(shared().signCalls).toEqual([]);

        tap();
        await until(() => shared().offerCalls.length === 2, 'the second offer request');
        flushSync();

        expect(shared().prompts).toEqual([]);
        expect(shared().signCalls).toEqual([]);
        expect(approve().disabled).toBe(true);
        expect(alertText()).not.toContain(passkeyApprovalCopy.offerFailed);

        second.resolve(REQUIRED);
        await until(() => !approve().disabled, 'Approve to be ready');
        expect(shared().signCalls).toEqual([]);

        tap();
        await until(() => shared().signCalls.length === 1, 'the sign request');
        expect(shared().prompts).toEqual([REQUIRED]);
        expect(shared().signCalls[0]![4]).toEqual(ASSERTION);
      });
    });

    test('after the API refuses over the passkey, Approve stays busy while the new offer is fetched and sends nothing until it lands', async () => {
      const second = deferred<ApprovalPasskeyNeed>();
      let fetches = 0;
      await withPage(name, () => (++fetches === 1 ? Promise.resolve(REQUIRED) : second.promise), async ({ approve, tap, transport }) => {
        await until(() => !approve().disabled, 'Approve to be ready');
        shared().signErrors.push(Object.assign(new Error('This approval needs your passkey.'), { code: 'passkey_approval_required' }));

        tap();
        await until(() => shared().signCalls.length === 1, 'the refused sign request');
        await until(() => shared().offerCalls.length === 2, 'the new offer request');
        expect(shared().prompts).toEqual([REQUIRED]);

        // The spent offer is gone and the new one is on its way: Approve is busy and taps send nothing.
        expect(approve().disabled).toBe(true);
        for (let i = 0; i < 3; i++) {
          tap();
          await transport().approveAndSign();
          flushSync();
        }
        expect(shared().signCalls).toHaveLength(1);
        expect(shared().prompts).toEqual([REQUIRED]);
        expect(shared().offerCalls).toHaveLength(2);
        expect(approve().disabled).toBe(true);

        second.resolve(REQUIRED);
        await until(() => !approve().disabled, 'Approve to be ready again');
        expect(shared().signCalls).toHaveLength(1);

        tap();
        await until(() => shared().signCalls.length === 2, 'the second sign request');
        expect(shared().prompts).toEqual([REQUIRED, REQUIRED]);
        expect(shared().signCalls[1]![4]).toEqual(ASSERTION);
      });
    });
  });
}
