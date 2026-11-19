// Mounts the production popup page (widget/sign) and embed page (widget/embed/sign) and drives a sign-in whose app
// asked for renewal (TC-2933). The pages send the ask at prepare; only when the prepare answer offers the box do
// they show it, seal its state in every preview, and pass the sign answer's renewalChoice/renewal to the app.
// Without an offer nothing about renewal reaches the preview, the sign call or the app.
//
// The signing adapters are replaced by a component that hands the page's own transport to the test; everything
// else is the page as built.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const win = new Window({ url: 'http://openkey.test/' });
(win as unknown as { postMessage: () => void }).postMessage = () => {};
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'page-renewal.'));
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
type RenewalTransport = { leaseMs: number | null; maxLeaseMs: number; onChange: (ms: number | null, windowMs?: number | null) => void };
type Adapter = {
  canUseAuthorizeSign: boolean;
  previewReady: boolean;
  approveAndSign: () => Promise<void>;
  renewal?: RenewalTransport;
};
type Shared = { sent: Sent[]; adapter: Adapter | null; options: { onRequest: (request: unknown) => void } | null };
const store = globalThis as unknown as { __renewalPages: Shared };
const shared = (): Shared => store.__renewalPages;
const reset = () => { store.__renewalPages = { sent: [], adapter: null, options: null }; };
reset();

const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };

const ADAPTER_SOURCE = `<script>
  let { transport } = $props();
  $effect(() => { globalThis.__renewalPages.adapter = transport; });
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
  '$lib/embed-passkey': `export const isEmbedContext = () => true; export const getSessionToken = () => 'session-token';
    export const withSessionCredential = (init) => init; export const clearSessionToken = () => {};`,
  '$lib/widget-transport': `export const createWidgetTransport = (options) => {
      globalThis.__renewalPages.options = options;
      return { emitReady() {}, emitResize() {}, emitLayoutSignal() {}, destroy() {}, respond(message) { globalThis.__renewalPages.sent.push(message); } };
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

const D = 24 * 60 * 60 * 1000;
const GRANT = { service: 'tinycloud.kv', space: SPACE, path: 'notes/', actions: ['tinycloud.kv/get'] };
const RECEIPT = { version: 1, receipt: { leaseAuthorization: 'lease', originalCid: 'cid' } };

interface Scenario {
  /** The sign request's renewal fields; none when the app did not ask. */
  ask?: Record<string, unknown>;
  /** The prepare answer's offer; none when the server does not offer the box. */
  offer?: { leaseLifetimeSeconds: number };
  /** Extra fields of the sign answer. */
  signExtra?: Record<string, unknown>;
  /** What the owner does once the first preview is ready. */
  act?: (adapter: Adapter) => void;
}

type Call = { name: string; body: Record<string, unknown> };

async function run(pageName: 'popup' | 'embed', scenario: Scenario) {
  reset();
  const calls: Call[] = [];
  const realFetch = globalThis.fetch;
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const name = String(input).split('/').pop() ?? '';
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    calls.push({ name, body });
    let answer: unknown = { error: 'unexpected' };
    let status = 500;
    if (name === 'authorize-sign-prepare') {
      status = 200;
      answer = {
        authorizationContextToken: 'context-token',
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
        ...(scenario.offer ? { renewal: scenario.offer } : {}),
      };
    }
    if (name === 'authorize-sign-preview') {
      const ids = body.selectedActionIds as string[];
      const permissions = ids.map((id) => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      });
      status = 200;
      answer = {
        signedMessage: 'signed', previewApprovalToken: 'approval', previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        authorizationContextToken: 'context-token', selectedActionKeys: ids, permissions,
        ...(body.renewal ? { renewal: body.renewal } : {}),
      };
    }
    if (name === 'authorize-sign') {
      status = 200;
      answer = { signature: `0x${'11'.repeat(65)}`, address: ADDR, signedMessage: 'signed', selectedActionKeys: ['key-1'], permissions: [GRANT], ...scenario.signExtra };
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
        host: 'https://node.tinycloud.xyz', ...scenario.ask,
      },
    });
    await until(() => shared().adapter?.canUseAuthorizeSign === true, 'the review');
    await until(() => shared().adapter?.previewReady === true, 'the preview');
    const offered = shared().adapter!.renewal ?? null;
    if (scenario.act) {
      const previews = calls.filter((call) => call.name === 'authorize-sign-preview').length;
      scenario.act(shared().adapter!);
      await until(() => calls.filter((call) => call.name === 'authorize-sign-preview').length > previews && shared().adapter?.previewReady === true, 'the new preview');
    }
    const afterAct = shared().adapter!.renewal ?? null;
    await shared().adapter!.approveAndSign();
    flushSync();
    return {
      calls,
      offered: offered && { leaseMs: offered.leaseMs, maxLeaseMs: offered.maxLeaseMs },
      afterAct: afterAct && { leaseMs: afterAct.leaseMs, maxLeaseMs: afterAct.maxLeaseMs },
      successes: shared().sent.filter((message) => message.success === true),
    };
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
    Object.assign(console, realConsole);
  }
}

const bodiesOf = (calls: Call[], name: string) => calls.filter((call) => call.name === name).map((call) => call.body);

for (const { name } of PAGES) {
  describe(`the ${name} page and the renewal box`, () => {
    test('an app that did not ask: nothing about renewal is sent anywhere', async () => {
      const result = await run(name, { ask: { expiryChangeable: true } });
      expect(result.offered).toBeNull();
      for (const call of result.calls) expect('renewal' in call.body).toBe(false);
      expect(result.successes).toHaveLength(1);
      const data = result.successes[0]!.data as Record<string, unknown>;
      expect('renewalChoice' in data || 'renewal' in data).toBe(false);
    });

    test('an ask the server does not offer: only prepare carries it, and no box shows', async () => {
      const result = await run(name, { ask: { expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 7_776_000, purpose: 'standing' } } });
      expect(bodiesOf(result.calls, 'authorize-sign-prepare')[0]!.renewal).toEqual({ version: 1, leaseLifetimeSeconds: 7_776_000 });
      expect(result.offered).toBeNull();
      for (const body of [...bodiesOf(result.calls, 'authorize-sign-preview'), ...bodiesOf(result.calls, 'authorize-sign')]) {
        expect('renewal' in body).toBe(false);
      }
    });

    test('standing access starts ticked and the lease is sealed in the preview; the receipt reaches the app', async () => {
      const result = await run(name, {
        ask: { expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 7_776_000, purpose: 'standing' } },
        offer: { leaseLifetimeSeconds: 7_776_000 },
        signExtra: { renewalChoice: 'leased', renewal: RECEIPT },
      });
      expect(result.offered).toEqual({ leaseMs: 90 * D, maxLeaseMs: 90 * D });
      const previews = bodiesOf(result.calls, 'authorize-sign-preview');
      expect(previews.at(-1)!.renewal).toEqual({ choice: 'leased', leaseLifetimeSeconds: 7_776_000 });
      for (const preview of previews) expect(preview.renewal).toBeDefined();
      expect(result.successes).toHaveLength(1);
      expect(result.successes[0]!.data).toMatchObject({ renewalChoice: 'leased', renewal: RECEIPT });
    });

    test('a task starts unticked and the preview says finite', async () => {
      const result = await run(name, {
        ask: { expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 7_776_000, purpose: 'task' } },
        offer: { leaseLifetimeSeconds: 7_776_000 },
        signExtra: { renewalChoice: 'finite' },
      });
      expect(result.offered).toEqual({ leaseMs: null, maxLeaseMs: 90 * D });
      expect(bodiesOf(result.calls, 'authorize-sign-preview').at(-1)!.renewal).toEqual({ choice: 'finite' });
      expect(result.successes[0]!.data).toMatchObject({ renewalChoice: 'finite' });
      expect('renewal' in (result.successes[0]!.data as Record<string, unknown>)).toBe(false);
    });

    test('unticking re-previews with finite', async () => {
      const result = await run(name, {
        ask: { expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 7_776_000, purpose: 'standing' } },
        offer: { leaseLifetimeSeconds: 7_776_000 },
        act: (adapter) => adapter.renewal!.onChange(null),
      });
      expect(result.afterAct).toEqual({ leaseMs: null, maxLeaseMs: 90 * D });
      expect(bodiesOf(result.calls, 'authorize-sign-preview').at(-1)!.renewal).toEqual({ choice: 'finite' });
    });

    test('turning renewal on from the sensitive-access step re-previews with the lease and the new window', async () => {
      const result = await run(name, {
        ask: { expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 7_776_000, purpose: 'task' } },
        offer: { leaseLifetimeSeconds: 7_776_000 },
        act: (adapter) => adapter.renewal!.onChange(30 * D, 7 * D),
      });
      const last = bodiesOf(result.calls, 'authorize-sign-preview').at(-1)!;
      expect(last.renewal).toEqual({ choice: 'leased', leaseLifetimeSeconds: 30 * 24 * 60 * 60 });
      const window = Date.parse(String(last.expirationTime)) - Date.now();
      expect(window).toBeGreaterThan(7 * D - 60_000);
      expect(window).toBeLessThanOrEqual(7 * D);
    });
  });
}
