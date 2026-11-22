// The root layout holds a window's page until the Terms read resolves: the pop-up (widget/connect) and the dashboard make
// no account call, and the pop-up posts no `openkey:ready`, before GET /api/account/terms answers. An account that has
// agreed gets its page's calls after the answer; one that owes the Terms gets none. A later check (a refused call) keeps
// the shown page mounted, and a sign-in made on the pop-up itself loads its keys only after the read.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, beforeEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { writable } from 'svelte/store';

const win = new Window({ url: 'https://openkey.test/' });
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
// The dev build's per-page switch for a Terms release (`openkey_dev_terms_release`) is read under `import.meta.env.DEV`.
(process.env as Record<string, string>).DEV = 'true';

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'terms-read.'));
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

type Session = { data: { user: { id: string; email: string } } | null; isPending: boolean };
interface Scene {
  url: string;
  session: ReturnType<typeof writable<Session>>;
  posts: unknown[];
}
const scene = (): Scene => (globalThis as unknown as { __scene: Scene }).__scene;

const SIGNED_IN: Session = { data: { user: { id: 'user_1', email: 'sam@example.test' } }, isPending: false };
const SIGNED_OUT: Session = { data: null, isPending: false };
const PENDING: Session = { data: null, isPending: true };

const EMPTY_SOURCE = '<div data-testid="stub"></div>';
const STUBS: Record<string, string> = {
  '$app/environment': 'export const browser = true; export const dev = false;',
  '$app/navigation': 'export const goto = () => {};',
  '$app/stores': `export const page = { subscribe(run) {
    run({ url: new URL(globalThis.__scene.url), route: { id: null } });
    return () => {};
  } };`,
  '$lib/auth-client': `export const authErrorMessage = (e, fallback) => fallback;
    export const authClient = {
      useSession: () => globalThis.__scene.session,
      signIn: { passkey: async () => ({}) },
      signOut: async () => {},
    };`,
};

function compileSource(source: string, name: string): string {
  const out = compile(source, { generate: 'client', dev: false, name: 'Stub', filename: `${name}.svelte` }).js.code;
  const file = join(OUT_DIR, `${name}.mjs`);
  writeFileSync(file, out);
  return pathToFileURL(file).href;
}

const emptyUrl = compileSource(EMPTY_SOURCE, 'empty');
const termsStepUrl = compileSource('<div data-testid="terms-step"></div>', 'terms-step');
const stubs: Record<string, string> = {
  ...STUBS,
  '$lib/components/admin-console-link.svelte': `export { default } from '${emptyUrl}';`,
  '$lib/renewal-leases': "export const renewalLeaseCopy = { signOutKeepsRenewing: '', stopRenewalsLink: '' };",
  // The bound on a session that does not answer, shortened.
  '$lib/terms': `export * from '${pathToFileURL(join(WEB_ROOT, 'src/lib/terms.ts')).href}'; export const TERMS_CHECK_TIMEOUT_MS = 200;`,
  '$lib/components/auth/terms-step.svelte': `export { default } from '${termsStepUrl}';`,
  '$lib/components/auth/terms-check-failed.svelte': `export { default } from '${emptyUrl}';`,
};

const compiledFiles = new Map<string, string>();
function compileComponent(file: string): string {
  const cached = compiledFiles.get(file);
  if (cached) return cached;
  const compiled = compile(readFileSync(file, 'utf8'), { generate: 'client', dev: false, name: 'Subject', filename: file });
  let code = '';
  let cursor = 0;
  for (const match of compiled.js.code.matchAll(/(?:from\s+|import\s+)['"]([^'"]+)['"]/g)) {
    code += compiled.js.code.slice(cursor, match.index);
    const spec = match[1]!;
    let target = spec;
    if (spec in stubs) {
      const stubFile = join(OUT_DIR, `stub-${spec.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
      writeFileSync(stubFile, stubs[spec]!);
      target = pathToFileURL(stubFile).href;
    } else if (spec === 'svelte') target = SVELTE_CLIENT;
    else if (spec.endsWith('.css')) target = emptyModule();
    else if (spec.startsWith('$lib/') && spec.endsWith('.svelte')) target = compileComponent(join(WEB_ROOT, 'src/lib', spec.slice(5)));
    else if (spec.startsWith('$lib/')) target = pathToFileURL(join(WEB_ROOT, 'src/lib', spec.slice(5))).href;
    code += match[0].replace(spec, target);
    cursor = match.index! + match[0].length;
  }
  code += compiled.js.code.slice(cursor);
  const out = join(OUT_DIR, `${file.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, code);
  const url = pathToFileURL(out).href;
  compiledFiles.set(file, url);
  return url;
}
function emptyModule(): string {
  const file = join(OUT_DIR, 'empty-module.mjs');
  writeFileSync(file, 'export {};');
  return pathToFileURL(file).href;
}

const LAYOUT = compileComponent(join(WEB_ROOT, 'src/routes/+layout.svelte'));
const PAGES = {
  connect: {
    url: 'https://openkey.test/widget/connect?origin=https%3A%2F%2Fcli.tinycloud.xyz',
    // Calls the page makes on its own once its account is known to have agreed.
    calls: ['GET /api/keys'],
    Component: (await import(compileComponent(join(WEB_ROOT, 'src/routes/widget/connect/+page.svelte')))).default,
  },
  dashboard: {
    url: 'https://openkey.test/dashboard',
    calls: ['GET /api/keys', 'GET /api/account/renewal-leases'],
    Component: (await import(compileComponent(join(WEB_ROOT, 'src/routes/dashboard/+page.svelte')))).default,
  },
} as const;
const Layout = (await import(LAYOUT)).default;
const wrapperUrl = (page: keyof typeof PAGES) => {
  const pageUrl = compiledFiles.get(join(WEB_ROOT, page === 'connect' ? 'src/routes/widget/connect/+page.svelte' : 'src/routes/dashboard/+page.svelte'))!;
  return compileSource(
    `<script>import Layout from '${LAYOUT}'; import Page from '${pageUrl}';</script><Layout><Page /></Layout>`,
    `wrapper-${page}`,
  );
};
void Layout;
const Wrappers = {
  connect: (await import(wrapperUrl('connect'))).default,
  dashboard: (await import(wrapperUrl('dashboard'))).default,
};

const { termsGate, termsRefused } = (await import(pathToFileURL(join(WEB_ROOT, 'src/lib/terms-gate.ts')).href)) as {
  termsGate: { follow: (subject: string | null) => void };
  termsRefused: () => void;
};

// ---- the run ------------------------------------------------------------------

const STATUS = {
  version: '2026-11-22', effective: '2026-11-22', whatChanged: null, privacyChanged: false, requiresAcceptance: false, previouslyAccepted: true,
};

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}
const settle = async () => {
  for (let i = 0; i < 20; i++) {
    flushSync();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
};

interface Run {
  /** `METHOD /path` for every request made, in order. */
  requests: string[];
  /** Answers the held Terms status read: whether the Terms are owed, or a credential that no longer signs anyone in. */
  answer: (result: boolean | 'signed-out') => void;
  target: HTMLElement;
  session: Scene['session'];
  /** `openkey:ready` posts to the opener. */
  ready: () => number;
  checking: () => boolean;
}

async function withPage(
  page: keyof typeof PAGES,
  options: { session: Session; release?: 'on' | 'off' },
  act: (run: Run) => Promise<void>,
): Promise<void> {
  termsGate.follow(null);
  const session = writable<Session>(options.session);
  const posts: unknown[] = [];
  (globalThis as unknown as { __scene: Scene }).__scene = { url: PAGES[page].url, session, posts };
  sessionStorage.setItem('openkey_dev_terms_release', options.release ?? 'on');
  Object.defineProperty(win, 'opener', { value: { postMessage: (data: unknown) => posts.push(data) }, configurable: true });

  const requests: string[] = [];
  const held = Promise.withResolvers<boolean | 'signed-out'>();
  const realFetch = globalThis.fetch;
  const realConsole = { error: console.error, log: console.log, warn: console.warn };
  console.error = () => {};
  console.log = () => {};
  console.warn = () => {};
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), 'https://openkey.test').pathname;
    requests.push(`${init?.method ?? 'GET'} ${path}`);
    if (path === '/api/account/terms') {
      return held.promise.then((result) => result === 'signed-out'
        ? new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 })
        : new Response(JSON.stringify({ ...STATUS, requiresAcceptance: result }), { status: 200 }));
    }
    return new Response(JSON.stringify({ keys: [], leases: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;

  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Wrappers[page], { target, props: {} });
  try {
    await act({
      requests,
      answer: (result) => held.resolve(result),
      target,
      session,
      ready: () => posts.filter((post) => (post as { type?: string }).type === 'openkey:ready').length,
      checking: () => target.querySelector('[data-testid="terms-checking"]') !== null,
    });
  } finally {
    unmount(app);
    target.remove();
    termsGate.follow(null);
    globalThis.fetch = realFetch;
    Object.assign(console, realConsole);
    sessionStorage.removeItem('openkey_dev_terms_release');
  }
}

const accountCalls = (requests: string[]) => requests.filter((request) => !request.endsWith('/api/account/terms'));

beforeEach(() => {
  document.body.innerHTML = '';
});

for (const name of ['connect', 'dashboard'] as const) {
  describe(`the ${name} page`, () => {
    test('a reload with the session pending makes no account call before the Terms read resolves', async () => {
      await withPage(name, { session: PENDING }, async ({ requests, session, answer, ready, checking }) => {
        await settle();
        expect(checking()).toBe(true);
        expect(requests).toEqual([]);
        expect(ready()).toBe(0);

        session.set(SIGNED_IN);
        await until(() => requests.includes('GET /api/account/terms'), 'the Terms read');
        await settle();
        expect(requests).toEqual(['GET /api/account/terms']);
        expect(checking()).toBe(true);
        expect(ready()).toBe(0);

        answer(false);
        await until(() => PAGES[name].calls.every((call) => requests.includes(call)), 'the page calls');
        await settle();
        expect(checking()).toBe(false);
        expect(accountCalls(requests).sort()).toEqual([...PAGES[name].calls].sort());
        expect(requests.filter((request) => request.endsWith('/api/account/terms'))).toHaveLength(1);
        expect(ready()).toBe(name === 'connect' ? 1 : 0);
      });
    });

    test('an account that owes the Terms gets the Terms and no account call', async () => {
      await withPage(name, { session: PENDING }, async ({ requests, session, answer, target }) => {
        session.set(SIGNED_IN);
        await until(() => requests.includes('GET /api/account/terms'), 'the Terms read');
        answer(true);
        await until(() => target.querySelector('[data-testid="terms-step"]') !== null, 'the Terms');
        await settle();
        expect(requests).toEqual(['GET /api/account/terms']);
      });
    });

    test('a later check keeps the shown page mounted', async () => {
      await withPage(name, { session: SIGNED_IN }, async ({ requests, answer, target, ready, checking }) => {
        await until(() => requests.includes('GET /api/account/terms'), 'the Terms read');
        answer(false);
        await until(() => PAGES[name].calls.every((call) => requests.includes(call)), 'the page calls');
        await settle();
        const before = target.querySelector('main, button');
        expect(before).not.toBeNull();
        const readyBefore = ready();

        termsRefused();
        await settle();
        expect(checking()).toBe(false);
        expect(target.querySelector('main, button')).toBe(before);
        expect(before!.isConnected).toBe(true);
        expect(ready()).toBe(readyBefore);
      });
    });

    test('a status read that finds the credential signed out releases the page instead of holding it', async () => {
      await withPage(name, { session: SIGNED_IN }, async ({ requests, answer, ready, checking }) => {
        await until(() => requests.includes('GET /api/account/terms'), 'the Terms read');
        expect(checking()).toBe(true);
        answer('signed-out');
        await until(() => !checking(), 'the page');
        await settle();
        expect(checking()).toBe(false);
        expect(ready()).toBe(name === 'connect' ? 1 : 0);
      });
    });

    test('a session that never answers stops holding the page after the bound', async () => {
      await withPage(name, { session: PENDING }, async ({ requests, ready, checking }) => {
        await settle();
        expect(checking()).toBe(true);
        await until(() => !checking(), 'the page, once the session has not answered within the bound');
        expect(requests).toEqual([]);
        expect(ready()).toBe(name === 'connect' ? 1 : 0);
      });
    });
  });
}

describe('with no Terms release', () => {
  test('the pop-up loads its keys with no Terms read', async () => {
    await withPage('connect', { session: SIGNED_IN, release: 'off' }, async ({ requests, ready, checking }) => {
      await until(() => requests.includes('GET /api/keys'), 'the keys');
      await settle();
      expect(requests).toEqual(['GET /api/keys']);
      expect(checking()).toBe(false);
      expect(ready()).toBe(1);
    });
  });
});

describe('a sign-in made on the pop-up', () => {
  test('loads its keys only after the Terms read, on the page that stays mounted', async () => {
    await withPage('connect', { session: SIGNED_OUT }, async ({ requests, session, answer, ready, checking }) => {
      await settle();
      expect(checking()).toBe(false);
      expect(ready()).toBe(1);
      expect(requests).toEqual([]);

      session.set(SIGNED_IN);
      await until(() => requests.includes('GET /api/account/terms'), 'the Terms read');
      await settle();
      expect(requests).toEqual(['GET /api/account/terms']);
      expect(checking()).toBe(false);

      answer(false);
      await until(() => requests.includes('GET /api/keys'), 'the keys');
      await settle();
      expect(requests).toEqual(['GET /api/account/terms', 'GET /api/keys']);
      expect(ready()).toBe(1);
    });
  });
});
