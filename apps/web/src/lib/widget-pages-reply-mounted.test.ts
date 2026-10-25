// Mounts the production popup page (widget/sign) and embed page (widget/embed/sign),
// sends each a sign request through the widget transport, and answers the
// server calls. The sign answer is a 200 that lacks a field the SDK needs, or
// carries one in the wrong shape: each page shows the refusal of string 20,
// reports the failure to the host once, and sends no success.
//
// The signing adapters are replaced by a component that hands the page's own
// transport callbacks to the test; everything else is the page as built.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const win = new Window({ url: 'http://openkey.test/' });
const posted: Array<Record<string, unknown>> = [];
(win as unknown as { postMessage: (message: Record<string, unknown>) => void }).postMessage = (message) => { posted.push(message); };
Object.assign(globalThis, {
  window: win,
  document: win.document,
  HTMLElement: win.HTMLElement,
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-replies.'));
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

type Sent = Record<string, unknown>;
type Shared = { sent: Sent[]; adapter: Adapter | null; options: TransportOptions | null };
type Adapter = {
  canUseAuthorizeSign: boolean;
  previewReady: boolean;
  requestPreview: () => Promise<void>;
  approveAndSign: () => Promise<void>;
};
type TransportOptions = { onRequest: (request: unknown) => void };
const shared = (): Shared => (globalThis as unknown as { __pages: Shared }).__pages;
const reset = () => { (globalThis as unknown as { __pages: Shared }).__pages = { sent: [], adapter: null, options: null }; };
reset();

const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };

// The adapter keeps the page's transport where the test can call it.
const ADAPTER_SOURCE = `<script>
  let { transport } = $props();
  $effect(() => { globalThis.__pages.adapter = transport; });
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
    export const authClient = { useSession: () => ({ subscribe(run) { run({ data: { user: { id: 'user_1' } }, isPending: false }); return () => {}; } }) };`,
  '$lib/api': `export const api = { getKey: async () => ({ key: ${JSON.stringify(KEY)} }), listKeys: async () => ({ keys: [${JSON.stringify(KEY)}] }) };`,
  '$lib/embed-passkey': `export const isEmbedContext = () => true; export const getSessionToken = () => 'session-token';`,
  '$lib/widget-transport': `export const createWidgetTransport = (options) => {
      globalThis.__pages.options = options;
      return { emitReady() {}, emitResize() {}, emitLayoutSignal() {}, destroy() {}, respond(message) { globalThis.__pages.sent.push(message); } };
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

type Reply = { status: number; text: string };
const reply = (body: unknown): Reply => ({ status: 200, text: JSON.stringify(body) });

const GRANT = { service: 'tinycloud.kv', space: SPACE, path: 'notes/', actions: ['tinycloud.kv/get'] };
const SIGNED = { signature: `0x${'11'.repeat(65)}`, address: ADDR, signedMessage: 'signed', selectedActionKeys: ['key-1'], permissions: [GRANT] };
const without = (field: string) => { const { [field]: _removed, ...rest } = SIGNED as Record<string, unknown>; return rest; };

async function run(pageName: 'popup' | 'embed', sign: Reply) {
  reset();
  posted.length = 0;
  const called: string[] = [];
  const realFetch = globalThis.fetch;
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const name = String(input).split('/').pop() ?? '';
    called.push(name);
    let answer: Reply = { status: 500, text: '{"error":"unexpected"}' };
    if (name === 'authorize-sign-prepare') answer = reply({ authorizationContextToken: 'context-token' });
    if (name === 'authorize-sign-preview') {
      const ids = (JSON.parse(String(init?.body)) as { selectedActionIds: string[] }).selectedActionIds;
      const permissions = ids.map((id) => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      });
      answer = reply({ signedMessage: 'signed', previewApprovalToken: 'approval', selectedActionKeys: ids, permissions });
    }
    if (name === 'authorize-sign') answer = sign;
    return { ok: answer.status >= 200 && answer.status < 300, status: answer.status, json: async () => JSON.parse(answer.text) };
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Pages[pageName], { target, props: {} });
  try {
    await until(() => shared().options !== null, 'the transport');
    shared().options!.onRequest({
      requestId: 'req-1',
      protocolVersion: 1,
      data: { message: siwe(), keyId: KEY.id, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz' },
    });
    await until(() => shared().adapter?.canUseAuthorizeSign === true, 'the review');
    await shared().adapter!.requestPreview();
    await until(() => shared().adapter?.previewReady === true, 'the preview');
    await shared().adapter!.approveAndSign();
    flushSync();
    const refusal = target.querySelector('[data-testid="server-reply-refusal"]');
    const visible = (() => {
      if (!refusal) return '';
      const clone = refusal.cloneNode(true) as HTMLElement;
      clone.querySelectorAll('details, button').forEach((node) => node.remove());
      return clone.textContent?.replace(/\s+/g, ' ').trim() ?? '';
    })();
    return { called, sent: [...shared().sent], posted: [...posted], shown: refusal !== null, visible };
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
    Object.assign(console, realConsole);
  }
}

const TITLE = "OpenKey couldn't finish this request";
const BODY = "OpenKey couldn't read the server's reply, so nothing was approved. Please try again. If it keeps happening, contact the app.";
const FAILURE = { code: 'UNKNOWN', message: 'SERVER_REPLY_UNREADABLE' };

const successes = (messages: Sent[]) => messages.filter((message) => message.success === true);

for (const { name } of PAGES) {
  describe(`the ${name} page when the sign answer is a 200 that cannot be used`, () => {
    const bad: Array<[string, Reply]> = [
      ['no selectedActionKeys', reply(without('selectedActionKeys'))],
      ['no permissions', reply(without('permissions'))],
      ['selectedActionKeys that is not a list', reply({ ...SIGNED, selectedActionKeys: 'key-1' })],
      ['permissions that is not a list', reply({ ...SIGNED, permissions: { service: 'tinycloud.kv' } })],
      ['a permission that is not a grant', reply({ ...SIGNED, permissions: [1] })],
      ['a permission without actions', reply({ ...SIGNED, permissions: [{ service: 'tinycloud.kv', space: SPACE, path: 'notes/' }] })],
      ['no signature', reply(without('signature'))],
      ['an empty body', { status: 200, text: '' }],
    ];
    for (const [label, answer] of bad) {
      test(`${label}: string 20, one failure to the host, no success`, async () => {
        const result = await run(name, answer);
        expect(result.called).toContain('authorize-sign');
        expect(result.shown).toBe(true);
        expect(result.visible).toBe(`${TITLE} ${BODY}`);
        expect(successes(result.sent)).toEqual([]);
        expect(successes(result.posted)).toEqual([]);
        const failures = result.sent.filter((message) => message.type === 'openkey:sign:response' && message.success === false);
        expect(failures).toHaveLength(1);
        expect(failures[0]!.error).toEqual(FAILURE);
      });
    }

    test('a complete answer: no refusal, the signature goes to the host once', async () => {
      const result = await run(name, reply(SIGNED));
      expect(result.shown).toBe(false);
      const successful = successes(result.sent);
      expect(successful).toHaveLength(1);
      expect(successful[0]!.data).toMatchObject({ signature: SIGNED.signature, selectedActionKeys: SIGNED.selectedActionKeys, permissions: SIGNED.permissions });
      expect(result.sent.filter((message) => message.success === false)).toEqual([]);
    });

    test('empty lists are a complete answer', async () => {
      const result = await run(name, reply({ ...SIGNED, selectedActionKeys: [], permissions: [] }));
      expect(result.shown).toBe(false);
      expect(successes(result.sent)).toHaveLength(1);
    });
  });
}
