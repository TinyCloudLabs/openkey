// Mounted check for the org-key consent page (routes/widget/org/sign/+page.svelte).
// The page must render the `text` the server returns for the requested statement,
// unchanged: that text is what the org key signs (K1 D4). The server text comes from
// the API's renderIssuerStatement; this test compares the page's <pre> against it.
//
// The page's SvelteKit and passkey imports ($app/stores, $lib/api,
// @simplewebauthn/browser) are replaced with generated stubs. The API is stubbed at
// the boundary only: the statement text is produced by the real renderer.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { canonicalJson, parseIssuerStatement, renderIssuerStatement } from '../../../api/src/services/org-issuer-statement';
import { ORG_SIGN_REQUEST_TYPE } from './org-sign-widget';

// happy-dom globals must exist before the Svelte client runtime loads (it reads them at import time).
if (!(globalThis as any).document) {
  const win = new Window({ url: 'http://openkey.test/' });
  (globalThis as any).window = win;
  (globalThis as any).document = win.document;
  (globalThis as any).HTMLElement = win.HTMLElement;
  (globalThis as any).Element = win.Element;
  (globalThis as any).Node = win.Node;
  (globalThis as any).Text = win.Text;
  (globalThis as any).Comment = win.Comment;
  (globalThis as any).CustomEvent = win.CustomEvent;
  (globalThis as any).Event = win.Event;
  (globalThis as any).MessageEvent = win.MessageEvent;
  (globalThis as any).navigator = win.navigator;
  (globalThis as any).getComputedStyle = win.getComputedStyle.bind(win);
  (globalThis as any).requestAnimationFrame = win.requestAnimationFrame.bind(win);
  (globalThis as any).cancelAnimationFrame = win.cancelAnimationFrame.bind(win);
}

// Loaded dynamically: the Svelte runtime must come after the DOM globals above.
// The client entry is loaded by file path because the package root resolves to the server build under Bun.
const { compile } = await import('svelte/compiler');
const require = createRequire(import.meta.url);
const svelteClient = (await import(
  pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href
)) as { mount: (c: unknown, o: unknown) => unknown; unmount: (c: unknown) => void; flushSync: () => void };
const { mount, unmount, flushSync } = svelteClient;

const THIS_FILE = fileURLToPath(import.meta.url);
const WEB_ROOT = join(dirname(THIS_FILE), '..', '..');
const OUT_DIR = join(WEB_ROOT, '.svelte-kit', '_dom-parity', 'org-sign-page');
mkdirSync(OUT_DIR, { recursive: true });

// Values mirror apps/api/src/__tests__/org-keys-fixtures.ts and org-issuer-statement-fixtures.ts.
const PAGE_ORIGIN = 'https://partner.example';
const AUDIENCE = 'https://credentials.org';
const ORG_ID = 'oceirceirceirceirceirceirce';
const ISSUER_DID = `did:web:${ORG_ID}.orgs.credentials.org`;
const SLUG = 'acme';
const CONTROLLER = 'did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';

// Stub modules. The page's imports are rewritten to these files at compile time.
const pageUrl = `https://openkey.test/widget/org/sign?origin=${encodeURIComponent(PAGE_ORIGIN)}`;
const STUB_SOURCES = {
  appStores: `export const page = { subscribe(run) { run({ url: new URL(${JSON.stringify(pageUrl)}) }); return () => {}; } };\n`,
  api: `export const api = {
  orgKeySignChallenge(keyId, body) {
    globalThis.__orgSignStub.calls.push({ keyId, body });
    return globalThis.__orgSignStub.challenge;
  },
};
`,
  simplewebauthn: `export function startAuthentication() { throw new Error('not used by this test'); }\n`,
} as const;
const stubUrl = (name: keyof typeof STUB_SOURCES): string => {
  const file = join(OUT_DIR, `stub-${name}.mjs`);
  writeFileSync(file, STUB_SOURCES[name]);
  return pathToFileURL(file).href;
};
const SPECIFIER_MAP: Record<string, string> = {
  '$app/stores': stubUrl('appStores'),
  '$lib/api': stubUrl('api'),
  '@simplewebauthn/browser': stubUrl('simplewebauthn'),
};

const compiledLib = new Map<string, string>();

// Compiles a `$lib/*.svelte` child (Button, Card) to a client module, recursively.
function compileLibSvelte(rel: string): string {
  const cached = compiledLib.get(rel);
  if (cached) return cached;
  const source = readFileSync(join(WEB_ROOT, 'src/lib', rel), 'utf8');
  const compiled = compile(source, { generate: 'client', dev: false, filename: `src/lib/${rel}` });
  const file = join(OUT_DIR, `lib-${rel.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(file, rewriteImports(compiled.js.code));
  const url = pathToFileURL(file).href;
  compiledLib.set(rel, url);
  return url;
}

function libTsUrl(rel: string): string {
  const base = join(WEB_ROOT, 'src/lib', rel);
  return pathToFileURL(existsSync(`${base}.ts`) ? `${base}.ts` : base).href;
}

function resolveSpecifier(spec: string): string {
  const mapped = SPECIFIER_MAP[spec];
  if (mapped) return mapped;
  if (spec.startsWith('$lib/')) {
    const rel = spec.slice('$lib/'.length);
    return rel.endsWith('.svelte') ? compileLibSvelte(rel) : libTsUrl(rel);
  }
  return spec;
}

function rewriteImports(code: string): string {
  return code.replace(/from\s+(['"])([^'"]+)\1/g, (_m, quote: string, spec: string) => `from ${quote}${resolveSpecifier(spec)}${quote}`);
}

const compiledPage = compile(readFileSync(join(WEB_ROOT, 'src/routes/widget/org/sign/+page.svelte'), 'utf8'), {
  generate: 'client',
  dev: false,
  name: 'OrgSignPage',
  filename: 'src/routes/widget/org/sign/+page.svelte',
});
const pageFile = join(OUT_DIR, 'org-sign-page.mjs');
writeFileSync(pageFile, rewriteImports(compiledPage.js.code));
const PageComponent = ((await import(pathToFileURL(pageFile).href)) as { default: unknown }).default;

// The statement the org key signs. Field values mirror the route fixture (statementFor).
function statementMessage(): string {
  return canonicalJson({
    action: 'authorize',
    alg: 'EdDSA',
    audience: AUDIENCE,
    controller: CONTROLLER,
    issuerDid: ISSUER_DID,
    kid: `${ISSUER_DID}#issuing-1`,
    nonce: '00112233445566778899aabbccddeeff',
    notBefore: '2026-10-20T09:00:00Z',
    orgId: ORG_ID,
    profiles: ['tinycloud.org-membership/v1'],
    publicKey: 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI',
    seq: 1,
    slug: SLUG,
    type: 'tinycloud.org-issuer-authorization/v1',
    vcts: ['opencredentials.org-membership/v1', 'tinycloud.org-badge/v1'],
  });
}

function signRequest(message: string) {
  return { type: ORG_SIGN_REQUEST_TYPE, requestId: 'req-1', keyId: 'org-key-1', message, protocolVersion: 1 };
}

const win = (): any => (globalThis as any).window;

// Drains pending microtasks so the page's awaited API call settles. The stub resolves
// immediately, so no wall-clock timer is involved.
async function settle(): Promise<void> {
  for (let i = 0; i < 10; i += 1) await Promise.resolve();
  flushSync();
}

interface Mounted {
  container: HTMLElement;
  posted: Array<{ message: unknown; targetOrigin: string }>;
  counterparty: { postMessage: (message: unknown, targetOrigin: string) => void };
  dispatchRequest: (event: { origin: string; data: unknown }) => void;
  teardown: () => void;
}

// The page treats window.opener as the counterparty and accepts requests only from it.
// happy-dom marks Window.opener readonly, so it is redefined as a configurable own property.
function mountPage(): Mounted {
  const posted: Mounted['posted'] = [];
  const counterparty = {
    postMessage(message: unknown, targetOrigin: string) {
      posted.push({ message, targetOrigin });
    },
  };
  Object.defineProperty(win(), 'opener', { value: counterparty, configurable: true, writable: true });
  const container = win().document.createElement('div');
  win().document.body.appendChild(container);
  const component = mount(PageComponent, { target: container });
  flushSync();
  return {
    container,
    posted,
    counterparty,
    dispatchRequest({ origin, data }) {
      const w = win();
      w.dispatchEvent(new w.MessageEvent('message', { data, origin, source: counterparty }));
    },
    teardown() {
      unmount(component);
      container.remove();
      Object.defineProperty(win(), 'opener', { value: undefined, configurable: true, writable: true });
    },
  };
}

const mounts: Mounted[] = [];
afterAll(() => {
  for (const handle of mounts) handle.teardown();
});

describe('org sign consent page (mounted)', () => {
  test('renders the exact text the server returns for the statement', async () => {
    const message = statementMessage();
    const serverText = renderIssuerStatement(parseIssuerStatement(message, [AUDIENCE]), message);
    (globalThis as any).__orgSignStub = {
      calls: [],
      challenge: {
        nonce: 'nonce-1',
        challenge: 'challenge-1',
        expiresAt: '2026-10-20T09:05:00Z',
        kind: 1,
        text: serverText,
        rpId: 'credentials.org',
        allowCredentials: [],
      },
    };

    const handle = mountPage();
    mounts.push(handle);
    handle.dispatchRequest({ origin: PAGE_ORIGIN, data: signRequest(message) });
    await settle();

    expect(handle.container.querySelector('pre')?.textContent).toBe(serverText);
    expect((globalThis as any).__orgSignStub.calls).toEqual([
      { keyId: 'org-key-1', body: { message, requestingOrigin: PAGE_ORIGIN } },
    ]);
  });

  test('ignores a signing request from an origin other than the widget origin', async () => {
    const message = statementMessage();
    (globalThis as any).__orgSignStub = { calls: [], challenge: null };

    const handle = mountPage();
    mounts.push(handle);
    handle.dispatchRequest({ origin: 'https://evil.example', data: signRequest(message) });
    await settle();

    expect((globalThis as any).__orgSignStub.calls).toEqual([]);
    expect(handle.container.querySelector('pre')).toBeNull();
  });
});
