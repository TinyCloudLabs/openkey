// A login page restored from the back-forward cache after a passkey sign-in (the page navigated to the
// authorize URL and the person came Back) is a fresh sign-in: the passkey button works again.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, afterEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const win = new Window({ url: 'https://openkey.test/auth/login' });
Object.assign(globalThis, {
  window: win,
  document: win.document,
  HTMLElement: win.HTMLElement,
  HTMLInputElement: win.HTMLInputElement,
  HTMLFormElement: win.HTMLFormElement,
  Element: win.Element,
  HTMLMediaElement: win.HTMLMediaElement,
  HTMLButtonElement: win.HTMLButtonElement,
  HTMLSelectElement: win.HTMLSelectElement,
  HTMLTextAreaElement: win.HTMLTextAreaElement,
  DocumentFragment: win.DocumentFragment,
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'login-restored.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
const SVELTE_CLIENT = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = (await import(SVELTE_CLIENT)) as {
  unmount: (app: unknown) => void;
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  flushSync: () => void;
};

type Shared = {
  passkeyCalls: number; gotos: string[]; termsChecks: number; redirects: string[]; url: string; native: unknown;
};
const shared = () => (globalThis as unknown as { __login: Shared }).__login;
(globalThis as unknown as { __login: Shared }).__login = {
  passkeyCalls: 0, gotos: [], termsChecks: 0, redirects: [], url: 'https://openkey.test/auth/login', native: null,
};

const emptyFile = join(OUT_DIR, 'empty.mjs');
writeFileSync(emptyFile, compile('<div></div>', { generate: 'client', dev: false, name: 'Stub', filename: 'empty.svelte' }).js.code);
const emptyUrl = pathToFileURL(emptyFile).href;
const emptyComponent = `export { default } from '${emptyUrl}';`;

const shellFile = join(OUT_DIR, 'shell.mjs');
writeFileSync(shellFile, compile('<script>let { children } = $props();</script>{@render children?.()}', { generate: 'client', dev: false, name: 'Shell', filename: 'shell.svelte' }).js.code);
const shellUrl = pathToFileURL(shellFile).href;

const stubs: Record<string, string> = {
  '$app/navigation': `export const goto = async (url) => { globalThis.__login.gotos.push(String(url)); };`,
  '$app/stores': `export const page = { subscribe(run) { run({ url: new URL(globalThis.__login.url) }); return () => {}; } };`,
  '$lib/auth-client': `export const API_BASE = 'https://api.test'; export const authErrorMessage = (e, fallback) => fallback;
    export const confirmEmailSignUp = async () => ({});
    export const authClient = {
      getSession: async () => ({ data: null }),
      signIn: { passkey: async () => { globalThis.__login.passkeyCalls++; return {}; } },
      $store: { notify() {} },
      $fetch: async (_path, options) => { options.onSuccess({ data: { redirect: true, url: 'https://openkey.test/previous-account-redirect' } }); return {}; },
    };`,
  '$lib/api': 'export const api = {};',
  '$lib/social-auth': 'export const loadConfiguredSocialProviders = async () => []; export const signInWithSocialPopup = async () => {}; export const signInWithSocialRedirect = async () => {};',
  '$lib/native-mode': `export const nativeSignIn = () => globalThis.__login.native; export const nativeOtpSentKey = () => ''; export const nativeReentryKey = () => '';
    export const nativeSocialReturnUrls = () => ({});`,
  '$lib/web-sign-flow': 'export const popupSignFlowForLogin = () => null; export const webSignFlowHeaders = () => ({});',
  '$lib/social-continuation': `export const accountExistsMessage = () => ''; export const confirmSocialContinuation = async () => ({});
    export const loadSocialContinuation = async () => ({}); export const relayNotice = () => ''; export const socialErrorMessage = () => '';
    export const socialProviderName = (p) => p;`,
  '$lib/terms': `export const checkTerms = async () => { globalThis.__login.termsChecks++; return { state: 'accepted' }; }; export const oauthClientName = async () => null;`,
  '$lib/terms-release': 'export const termsCheckedFirst = () => true;',
  '$lib/email-signup': 'export const newAccountSignupToken = () => null;',
  '$lib/passkey-step-up': 'export const passkeyStepUpMethods = () => [];',
  '$lib/send-code-error': 'export const sendCodeErrorMessage = () => "";',
  '$lib/components/auth/native-shell.svelte': `export { default } from '${shellUrl}';`,
  '$lib/components/auth/social-buttons.svelte': emptyComponent,
  '$lib/components/auth/new-account-confirmation.svelte': emptyComponent,
  '$lib/components/auth/passkey-step-up-dialog.svelte': emptyComponent,
  '$lib/components/auth/terms-check-failed.svelte': emptyComponent,
  '$lib/components/auth/terms-step.svelte': emptyComponent,
};

const built = new Map<string, string>();
function build(file: string): string {
  const known = built.get(file);
  if (known) return known;
  const compiled = compile(readFileSync(file, 'utf8'), { generate: 'client', dev: false, name: 'Subject', filename: file });
  let code = '';
  let cursor = 0;
  for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    code += compiled.js.code.slice(cursor, match.index);
    const spec = match[1]!;
    let target = spec;
    if (spec in stubs) {
      const stub = join(OUT_DIR, `${spec.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
      writeFileSync(stub, stubs[spec]!);
      target = pathToFileURL(stub).href;
    } else if (spec === 'svelte') target = SVELTE_CLIENT;
    else if (spec.startsWith('$lib/') && spec.endsWith('.svelte')) target = build(join(WEB_ROOT, 'src/lib', spec.slice(5)));
    else if (spec.startsWith('$lib/')) target = pathToFileURL(join(WEB_ROOT, 'src/lib', spec.slice(5))).href;
    code += `from '${target}'`;
    cursor = match.index! + match[0].length;
  }
  code += compiled.js.code.slice(cursor);
  const out = join(OUT_DIR, `${file.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, code);
  const url = pathToFileURL(out).href;
  built.set(file, url);
  return url;
}
const pageFile = build(join(WEB_ROOT, 'src/routes/auth/login/+page.svelte'));
const Login = (await import(pageFile)).default;

async function settle() {
  for (let i = 0; i < 20; i++) {
    flushSync();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

const WEB_URL = 'https://openkey.test/auth/login';
const OAUTH_URL = `${WEB_URL}?client_id=client_1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&response_type=code`;
const NATIVE = { requestId: 'req_1', clientId: 'client_1', signedQuery: 'client_id=client_1', method: null, hint: null, socialError: null };

// Records navigation instead of performing it.
Object.defineProperty(win.location, 'assign', { configurable: true, value: (url: string) => shared().redirects.push(`assign ${url}`) });
Object.defineProperty(win.location, 'href', { configurable: true, get: () => WEB_URL, set: (url: string) => shared().redirects.push(`href ${url}`) });

let app: unknown;
function open(options: { url?: string; native?: unknown } = {}) {
  Object.assign(shared(), { passkeyCalls: 0, gotos: [], termsChecks: 0, redirects: [], url: options.url ?? WEB_URL, native: options.native ?? null });
  const target = document.createElement('div');
  document.body.appendChild(target);
  app = mount(Login, { target, props: {} });
}
afterEach(() => {
  unmount(app);
  document.body.innerHTML = '';
});
const button = (text: string) => [...document.querySelectorAll('button')].find((b) => b.textContent?.includes(text)) as HTMLButtonElement | undefined;
const passkeyButton = () => button('passkey');
function restore() {
  const event = new win.Event('pageshow') as Event & { persisted: boolean };
  Object.defineProperty(event, 'persisted', { value: true });
  window.dispatchEvent(event);
}
function type(id: string, value: string) {
  const input = document.getElementById(id) as HTMLInputElement;
  input.value = value;
  input.dispatchEvent(new win.Event('input', { bubbles: true }));
}
const submit = (id: string) => (document.getElementById(id) as HTMLElement).closest('form')!.dispatchEvent(new win.Event('submit', { cancelable: true, bubbles: true }));

describe('login page restored from the back-forward cache', () => {
  test.each([
    ['web', WEB_URL, null, 'passkey'],
    ['native', WEB_URL, NATIVE, 'passkey'],
  ])('%s: the passkey button works again after a passkey sign-in and a persisted pageshow', async (_mode, url, native) => {
    open({ url, native });
    await settle();
    expect(passkeyButton()).toBeTruthy();

    passkeyButton()!.click();
    await settle();
    expect(shared().passkeyCalls).toBe(1);

    // The sign-in left for the authorize URL; Back restores this page as it was.
    passkeyButton()!.click();
    await settle();
    expect(shared().passkeyCalls).toBe(1);

    restore();
    await settle();

    passkeyButton()!.click();
    await settle();
    expect(shared().passkeyCalls).toBe(2);
  });

  test('a restored page checks the Terms again for whoever signs in next', async () => {
    open();
    await settle();
    passkeyButton()!.click();
    await settle();
    expect(shared().termsChecks).toBe(1);

    restore();
    await settle();
    passkeyButton()!.click();
    await settle();
    expect(shared().termsChecks).toBe(2);
  });

  test('a restored page does not follow the previous sign-in\'s OAuth redirect', async () => {
    open({ url: OAUTH_URL });
    await settle();
    type('email', 'openai-review@tinycloud.xyz');
    submit('email');
    await settle();
    type('review-email', 'openai-review@tinycloud.xyz');
    type('review-code', '123456');
    submit('review-code');
    await settle();
    expect(shared().redirects).toEqual(['assign https://openkey.test/previous-account-redirect']);

    restore();
    await settle();
    passkeyButton()!.click();
    await settle();
    expect(shared().redirects.filter((r) => r.includes('previous-account-redirect'))).toHaveLength(1);
    expect(shared().redirects.at(-1)).toStartWith('href https://api.test/api/auth/oauth2/authorize?');
  });
});
