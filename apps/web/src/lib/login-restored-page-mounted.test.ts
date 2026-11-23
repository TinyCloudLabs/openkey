// A login page restored from the back-forward cache after a passkey sign-in (the page navigated to the
// authorize URL and the person came Back) is a fresh sign-in: the passkey button works again.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
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
const { mount, flushSync } = (await import(SVELTE_CLIENT)) as {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  flushSync: () => void;
};

type Shared = { passkeyCalls: number; gotos: string[] };
const shared = () => (globalThis as unknown as { __login: Shared }).__login;
(globalThis as unknown as { __login: Shared }).__login = { passkeyCalls: 0, gotos: [] };

const emptyFile = join(OUT_DIR, 'empty.mjs');
writeFileSync(emptyFile, compile('<div></div>', { generate: 'client', dev: false, name: 'Stub', filename: 'empty.svelte' }).js.code);
const emptyUrl = pathToFileURL(emptyFile).href;
const emptyComponent = `export { default } from '${emptyUrl}';`;

const stubs: Record<string, string> = {
  '$app/navigation': `export const goto = async (url) => { globalThis.__login.gotos.push(String(url)); };`,
  '$app/stores': `export const page = { subscribe(run) { run({ url: new URL('https://openkey.test/auth/login') }); return () => {}; } };`,
  '$lib/auth-client': `export const API_BASE = 'https://api.test'; export const authErrorMessage = (e, fallback) => fallback;
    export const confirmEmailSignUp = async () => ({});
    export const authClient = {
      getSession: async () => ({ data: null }),
      signIn: { passkey: async () => { globalThis.__login.passkeyCalls++; return {}; } },
      $store: { notify() {} },
    };`,
  '$lib/api': 'export const api = {};',
  '$lib/social-auth': 'export const loadConfiguredSocialProviders = async () => []; export const signInWithSocialPopup = async () => {}; export const signInWithSocialRedirect = async () => {};',
  '$lib/native-mode': `export const nativeSignIn = () => null; export const nativeOtpSentKey = () => ''; export const nativeReentryKey = () => '';
    export const nativeSocialReturnUrls = () => ({});`,
  '$lib/web-sign-flow': 'export const popupSignFlowForLogin = () => null; export const webSignFlowHeaders = () => ({});',
  '$lib/social-continuation': `export const accountExistsMessage = () => ''; export const confirmSocialContinuation = async () => ({});
    export const loadSocialContinuation = async () => ({}); export const relayNotice = () => ''; export const socialErrorMessage = () => '';
    export const socialProviderName = (p) => p;`,
  '$lib/terms': `export const checkTerms = async () => ({ state: 'accepted' }); export const oauthClientName = async () => null;`,
  '$lib/terms-release': 'export const termsCheckedFirst = () => true;',
  '$lib/email-signup': 'export const newAccountSignupToken = () => null;',
  '$lib/passkey-step-up': 'export const passkeyStepUpMethods = () => [];',
  '$lib/send-code-error': 'export const sendCodeErrorMessage = () => "";',
  '$lib/components/auth/native-shell.svelte': emptyComponent,
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

describe('login page restored from the back-forward cache', () => {
  test('the passkey button works again after a passkey sign-in and a persisted pageshow', async () => {
    const target = document.createElement('div');
    document.body.appendChild(target);
    mount(Login, { target, props: {} });
    await settle();
    const passkeyButton = () =>
      [...document.querySelectorAll('button')].find((b) => b.textContent?.includes('passkey')) as HTMLButtonElement;
    expect(passkeyButton()).toBeTruthy();

    passkeyButton().click();
    await settle();
    expect(shared().passkeyCalls).toBe(1);

    // The sign-in left for the authorize URL; Back restores this page as it was.
    passkeyButton().click();
    await settle();
    expect(shared().passkeyCalls).toBe(1);

    const restore = new win.Event('pageshow') as Event & { persisted: boolean };
    Object.defineProperty(restore, 'persisted', { value: true });
    window.dispatchEvent(restore);
    await settle();

    passkeyButton().click();
    await settle();
    expect(shared().passkeyCalls).toBe(2);
  });
});
