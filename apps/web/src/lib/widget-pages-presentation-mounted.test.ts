// Mounts the production popup page (widget/sign) and embed page (widget/embed/sign) with their real signing adapters
// and drives a plain signMessage() request that carries a `presentation`: what the app says about itself. The pages
// show the app's words under the verified origin, as unchecked claims, and only what survives the rules in
// `claimed-presentation.ts`. The words never change the signed bytes, nothing is signed before an Approve tap, and
// nothing of them reaches the signer, the API or the reply.
//
// The popup page gets the request the way the SDK sends it from a popup (an unversioned `message` event from its
// opener); the embed page gets it as a v2 phase request. The passkey prompt is replaced by a recorder.
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
(win as unknown as { close: () => void }).close = () => {};
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-presentation.'));
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

type Shared = {
  options: { onRequest: (request: unknown) => void } | null;
  transportOptions: Array<Record<string, unknown>>;
  offerCalls: unknown[][];
  signCalls: unknown[][];
  prompts: Array<ApprovalPasskeyNeed | null>;
  /** Everything the page sent back to the app: transport replies and messages to the opener. */
  sent: unknown[];
};
const store = globalThis as unknown as { __presentation: Shared };
const shared = (): Shared => store.__presentation;
const reset = () => {
  store.__presentation = { options: null, transportOptions: [], offerCalls: [], signCalls: [], prompts: [], sent: [] };
};

const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };
const DELEGATEE = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const APP_ORIGIN = 'https://notes.example';
const SHELL_ORIGIN = 'https://tinycloud.chat';
const ORIGINS = { app: APP_ORIGIN, shell: SHELL_ORIGIN } as const;

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

const REAL_PASSKEY_MODULE = pathToFileURL(join(WEB_ROOT, 'src/lib/approval-passkey.ts')).href;
const baseStubs = (pageUrl: string): Record<string, string> => ({
  '$app/stores': `export const page = { subscribe(run) { run({ url: new URL(${JSON.stringify(pageUrl)}) }); return () => {}; } };`,
  '$lib/auth-client': `export const authErrorMessage = (e, fallback) => fallback;
    export const authClient = { useSession: () => ({ subscribe(run) { run({ data: { user: { id: 'user_1' } }, isPending: false }); return () => {}; } }) };`,
  '$lib/api': `export const api = {
    getKey: async () => ({ key: ${JSON.stringify(KEY)} }),
    listKeys: async () => ({ keys: [${JSON.stringify(KEY)}] }),
    signMessagePasskey: async (...args) => { globalThis.__presentation.offerCalls.push(args); return { required: false }; },
    signMessage: async (...args) => { globalThis.__presentation.signCalls.push(args); return { signature: '0x${'11'.repeat(65)}', address: ${JSON.stringify(KEY.address)} }; },
  };`,
  '$lib/approval-passkey': `export * from ${JSON.stringify(REAL_PASSKEY_MODULE)};
    export const answerApprovalPasskey = async (need) => {
      globalThis.__presentation.prompts.push(need ?? null);
      return undefined;
    };`,
  '$lib/embed-passkey': `export const isEmbedContext = () => true; export const getSessionToken = () => 'session-token';
    export const withSessionCredential = (init) => init; export const clearSessionToken = () => {};`,
  '$lib/widget-transport': `export const createWidgetTransport = (options) => {
      globalThis.__presentation.options = options;
      globalThis.__presentation.transportOptions.push(options);
      return { emitReady() {}, emitResize() {}, emitLayoutSignal() {}, destroy() {}, respond(message) { globalThis.__presentation.sent.push(message); } };
    };
    export const createIframeLayoutGate = () => ({ measure() {}, changed() {}, applied() {}, isCurrent: () => false, canApprove: () => true, destroy() {} });`,
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

const PAGES = {
  popup: {
    file: join(WEB_ROOT, 'src/routes/widget/sign/+page.svelte'),
    url: (origin: string) => `https://openkey.test/widget/sign?origin=${encodeURIComponent(origin)}`,
    adapter: '$lib/components/signing/popup-signing-adapter.svelte',
    adapterFile: join(WEB_ROOT, 'src/lib/components/signing/popup-signing-adapter.svelte'),
  },
  embed: {
    file: join(WEB_ROOT, 'src/routes/widget/embed/sign/+page.svelte'),
    url: (origin: string) =>
      `https://openkey.test/widget/embed/sign?origin=${encodeURIComponent(origin)}&protocolVersion=2&requestId=phase-1&keyId=${KEY.id}`,
    adapter: '$lib/components/signing/iframe-signing-adapter.svelte',
    adapterFile: join(WEB_ROOT, 'src/lib/components/signing/iframe-signing-adapter.svelte'),
  },
} as const;
type PageName = keyof typeof PAGES;
type OriginName = keyof typeof ORIGINS;

const emptyUrl = compileSource(EMPTY_SOURCE, 'empty');
const Pages: Record<string, unknown> = {};
for (const [pageName, page] of Object.entries(PAGES)) {
  for (const [originName, origin] of Object.entries(ORIGINS)) {
    const name = `${pageName}-${originName}`;
    const stubs: Record<string, string> = {
      ...baseStubs(page.url(origin)),
      '$lib/components/auth/embedded-sign-in.svelte': `export { default } from '${emptyUrl}';`,
    };
    const realAdapterUrl = compileComponent(page.adapterFile, name, stubs);
    stubs[page.adapter] = `export { default } from '${compileSource(wrapperSource(realAdapterUrl), `${name}-wrapper`)}';`;
    Pages[name] = (await import(compileComponent(page.file, name, stubs))).default;
  }
}

// ---- the request ------------------------------------------------------------

// The one moment every message is stamped with, so the same request is the same bytes in every run.
const NOW = new Date();

// A plain sign-in message for the given origin whose URI is the delegatee: no ReCap, so the page signs the exact bytes.
function plainSiwe(origin: string): string {
  const now = NOW;
  return [
    `${new URL(origin).host} wants you to sign in with your Ethereum account:`,
    KEY.address,
    '',
    'Sign in to the demo.',
    '',
    `URI: ${DELEGATEE}`,
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    `Issued At: ${now.toISOString()}`,
    `Expiration Time: ${new Date(now.getTime() + 3_600_000).toISOString()}`,
  ].join('\n');
}

const PNG = `data:image/png;base64,${Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...new Array(30).fill(7)]).toString('base64')}`;
const SVG = `data:image/svg+xml;base64,${Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>').toString('base64')}`;
const OVERSIZE = `data:image/png;base64,iVBORw0KGgo${'A'.repeat(32748 - 11)}`;

const claim = (fields: Record<string, unknown>) => ({ protocolVersion: 1, ...fields });

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 2000; i++) {
    flushSync();
    if (condition()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

// happy-dom's `window.opener` is a getter; the popup page reads it to find the app that opened it.
function setOpener(value: unknown): void {
  Object.defineProperty(win, 'opener', { value, configurable: true });
}

// Runs effects and promise chains for a while so that "nothing has been sent" is not just "nothing yet".
async function settle(): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    await Promise.resolve();
  }
}

const squash = (text: string | null | undefined) => (text ?? '').replace(/\s+/g, ' ').trim();

interface Screen {
  message: string;
  approve: () => HTMLButtonElement;
  tap: () => void;
  bodyText: () => string;
  requesterLine: () => string;
  section: () => Element | null;
  claimLines: () => string[];
  icons: () => Element[];
}

async function withPage(
  pageName: PageName,
  originName: OriginName,
  presentation: unknown,
  body: (screen: Screen) => Promise<void>,
) {
  reset();
  const origin = ORIGINS[originName];
  const message = plainSiwe(origin);
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  const opener = { postMessage: (data: unknown) => { shared().sent.push(data); } };
  if (pageName === 'popup') setOpener(opener);
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Pages[`${pageName}-${originName}`], { target, props: {} });
  try {
    await until(() => shared().options !== null, 'the transport');
    const request = { type: 'openkey:sign:request', message, keyId: KEY.id, ...(presentation === undefined ? {} : { presentation }) };
    if (pageName === 'popup') {
      win.dispatchEvent(new win.MessageEvent('message', { data: request, origin, source: opener as never }));
    } else {
      const { type: _type, ...data } = request;
      void _type;
      shared().options!.onRequest({ requestId: 'phase-1', protocolVersion: 2, data });
    }
    const approve = () => target.querySelector('button.approve') as HTMLButtonElement;
    await until(() => approve() !== null && !approve().disabled, 'the Approve button');
    await body({
      message,
      approve,
      tap: () => { approve().click(); },
      bodyText: () => squash(target.textContent),
      requesterLine: () => squash(target.querySelector('.requester-line')?.textContent),
      section: () => target.querySelector('[data-testid="claimed-presentation"]'),
      claimLines: () => [...target.querySelectorAll('[data-testid="claimed-presentation"] p')].map((line) => squash(line.textContent)),
      icons: () => [...target.querySelectorAll('[data-testid="claimed-presentation"] img')],
    });
  } finally {
    unmount(app);
    target.remove();
    setOpener(null);
    Object.assign(console, realConsole);
  }
}

const PAGE_NAMES: PageName[] = ['popup', 'embed'];

for (const pageName of PAGE_NAMES) {
  describe(`the ${pageName} page shows what the app says about a plain sign request`, () => {
    test('three claims show in order under the verified origin, with one closing line and a small icon', async () => {
      const presentation = claim({
        displayName: 'Acme Notes',
        onBehalfOf: 'Sync in Acme Notes',
        reason: 'Keep your notes in step.',
        iconUrl: PNG,
      });
      await withPage(pageName, 'app', presentation, async ({ requesterLine, section, claimLines, icons, bodyText }) => {
        // The verified origin is the heading and the only identity.
        expect(requesterLine()).toContain('notes.example');
        expect(requesterLine()).not.toContain('Acme');

        const lines = claimLines();
        expect(lines).toEqual([
          'It calls itself "Acme Notes".',
          `It says it's asking for "Sync in Acme Notes".`,
          'Its reason: "Keep your notes in step."',
          `OpenKey hasn't checked these.`,
        ]);
        expect(bodyText().split(`OpenKey hasn't checked`).length - 1).toBe(1);

        // Secondary: after the requester line, with a 20px icon beside the name line and no alt text.
        const requester = document.querySelector('.requester-line')!;
        expect(requester.compareDocumentPosition(section()!) & 4).toBe(4);
        expect(icons()).toHaveLength(1);
        expect(icons()[0]!.getAttribute('alt')).toBe('');
        expect(icons()[0]!.getAttribute('src')).toBe(PNG);
        expect(icons()[0]!.getAttribute('width')).toBe('20');
        expect(icons()[0]!.closest('p')!.textContent).toContain('Acme Notes');

        // The text a screenshot of this screen shows for the claims.
        process.stdout.write(`[${pageName} three-claim screen]\n${requesterLine()}\n${lines.join('\n')}\n`);
      });
    });

    test('a third-party name alone is a claim with the unchecked line', async () => {
      await withPage(pageName, 'app', claim({ displayName: 'Acme Notes' }), async ({ claimLines }) => {
        expect(claimLines()).toEqual([`It calls itself "Acme Notes". OpenKey hasn't checked that name.`]);
      });
    });

    test('on behalf of alone and a reason alone each end with "OpenKey hasn\'t checked this."', async () => {
      await withPage(pageName, 'app', claim({ onBehalfOf: 'Sync in Acme', reason: undefined }), async ({ claimLines }) => {
        expect(claimLines()).toEqual([`It says it's asking for "Sync in Acme".`, `OpenKey hasn't checked this.`]);
      });
      await withPage(pageName, 'app', claim({ reason: 'To sync.' }), async ({ claimLines }) => {
        expect(claimLines()).toEqual([`Its reason: "To sync."`, `OpenKey hasn't checked this.`]);
      });
    });

    test('an on-behalf-of that is the delegatee DID in the signed bytes is the same unchecked claim', async () => {
      await withPage(pageName, 'app', claim({ onBehalfOf: DELEGATEE }), async ({ claimLines }) => {
        expect(claimLines()).toEqual([`It says it's asking for "${DELEGATEE}".`, `OpenKey hasn't checked this.`]);
      });
    });

    test('"TinyCloud One" from an app that is not a trusted shell is dropped without a trace', async () => {
      const presentation = claim({ displayName: 'TinyCloud One', iconUrl: PNG, reason: 'Keep your notes in step.' });
      await withPage(pageName, 'app', presentation, async ({ claimLines, icons, bodyText }) => {
        expect(claimLines()).toEqual(['Its reason: "Keep your notes in step."', `OpenKey hasn't checked this.`]);
        expect(icons()).toHaveLength(0);
        expect(bodyText()).not.toContain('TinyCloud One');
        expect(bodyText().toLowerCase()).not.toContain('calls itself');
      });
    });

    test('"Tiny Cloud One" spelled with lookalike and zero-width characters is dropped', async () => {
      const disguised = 'Tіny\u200B Clоud\u200D Оne';
      await withPage(pageName, 'app', claim({ displayName: disguised, onBehalfOf: 'Sync in ТinyCloud' }), async ({ section, bodyText }) => {
        expect(section()).toBeNull();
        expect(bodyText()).not.toContain('Cl');
        expect(bodyText()).not.toContain('Tіny');
        expect(bodyText()).not.toContain('calls itself');
        expect(bodyText()).not.toContain('asking for');
      });
    });

    test('the same name is shown when the requester is a trusted shell origin', async () => {
      await withPage(pageName, 'shell', claim({ displayName: 'TinyCloud One', onBehalfOf: 'Tiny Chat in TinyCloud One' }), async ({ claimLines, requesterLine }) => {
        expect(requesterLine()).toContain('tinycloud.chat');
        expect(claimLines()).toEqual([
          'It calls itself "TinyCloud One".',
          `It says it's asking for "Tiny Chat in TinyCloud One".`,
          `OpenKey hasn't checked these.`,
        ]);
      });
    });

    test('a name that reads as another host is dropped', async () => {
      await withPage(pageName, 'app', claim({ displayName: 'secure-login.example.com', reason: 'To sync.' }), async ({ claimLines, bodyText }) => {
        expect(claimLines()).toEqual([`Its reason: "To sync."`, `OpenKey hasn't checked this.`]);
        expect(bodyText()).not.toContain('secure-login');
      });
    });

    test('an icon that is oversize, SVG or remote is omitted and the name stays', async () => {
      for (const iconUrl of [OVERSIZE, SVG, 'https://notes.example/icon.png']) {
        await withPage(pageName, 'app', claim({ displayName: 'Acme Notes', iconUrl }), async ({ claimLines, icons }) => {
          expect(claimLines()).toEqual([`It calls itself "Acme Notes". OpenKey hasn't checked that name.`]);
          expect(icons()).toHaveLength(0);
        });
      }
    });

    test('markup in a claim is text', async () => {
      await withPage(pageName, 'app', claim({ reason: '<img src=x onerror=alert(1)>' }), async ({ section, claimLines }) => {
        expect(claimLines()[0]).toBe('Its reason: "<img src=x onerror=alert(1)>"');
        expect(section()!.querySelector('img')).toBeNull();
      });
    });

    test('a request with no presentation, or one the page cannot read, shows no claim section', async () => {
      for (const presentation of [undefined, 'Acme', { displayName: 'Acme' }, claim({ displayName: ' \u200B ' })]) {
        await withPage(pageName, 'app', presentation, async ({ section }) => {
          expect(section()).toBeNull();
        });
      }
    });

    test('the page has its transport announce that it shows presentation', async () => {
      await withPage(pageName, 'app', claim({ displayName: 'Acme Notes' }), async () => {
        expect(shared().transportOptions.length).toBeGreaterThan(0);
        for (const options of shared().transportOptions) expect(options.showsPresentation).toBe(true);
      });
    });

    test('no sign request is made, and nothing is sent back, before Approve is tapped', async () => {
      const presentation = claim({ displayName: 'Acme Notes', onBehalfOf: DELEGATEE, reason: 'To sync.', iconUrl: PNG });
      await withPage(pageName, 'app', presentation, async ({ approve, tap }) => {
        await settle();
        expect(approve().disabled).toBe(false);
        expect(shared().signCalls).toEqual([]);
        expect(shared().sent).toEqual([]);
        expect(shared().prompts).toEqual([]);

        tap();
        await until(() => shared().signCalls.length === 1, 'the sign request');
        await until(() => shared().sent.length >= 1, 'the reply');
      });
    });

    test('the signed bytes are the same with and without a presentation, and nothing of it leaves the page', async () => {
      const words = claim({ displayName: 'Acme Notes', onBehalfOf: 'Sync in Acme Notes', reason: 'Keep your notes in step.', iconUrl: PNG });
      const runs: Array<{ message: string; signCalls: unknown[][]; offerCalls: unknown[][]; sent: unknown[] }> = [];
      for (const presentation of [undefined, words]) {
        await withPage(pageName, 'app', presentation, async ({ message, tap }) => {
          tap();
          await until(() => shared().signCalls.length === 1, 'the sign request');
          await until(() => shared().sent.length >= 1, 'the reply');
          const { signCalls, offerCalls, sent } = shared();
          runs.push({ message, signCalls: [...signCalls], offerCalls: [...offerCalls], sent: [...sent] });
        });
      }
      const [without, withWords] = runs;

      // The string the signer got is the request's message, byte for byte, and the whole call is the same.
      expect(withWords!.signCalls[0]![1]).toBe(withWords!.message);
      expect(without!.signCalls[0]![1]).toBe(without!.message);
      expect(withWords!.message).toBe(without!.message);
      expect(withWords!.signCalls).toEqual(without!.signCalls);
      expect(withWords!.offerCalls).toEqual(without!.offerCalls);
      expect(withWords!.sent).toEqual(without!.sent);

      // None of the app's words, nor the icon, is in anything the page sent to the signer, the API or the app.
      const everything = JSON.stringify([withWords!.signCalls, withWords!.offerCalls, withWords!.sent]);
      for (const text of ['Acme Notes', 'Sync in Acme', 'Keep your notes', 'image/png', 'presentation']) {
        expect(everything).not.toContain(text);
      }
    });

    test('a screen left without an Approve tap has signed nothing', async () => {
      await withPage(pageName, 'app', claim({ displayName: 'Acme Notes', reason: 'To sync.' }), async () => {
        await settle();
        expect(shared().signCalls).toEqual([]);
      });
      await settle();
      expect(shared().signCalls).toEqual([]);
    });
  });
}
