// Mounts the real embedded sign-in (the signed-out face of the iframe pages) with a controllable provider request.
// The face lives in a frame whose host animates the height, so a row inserted late moves Passkey under a tap that was
// aimed at it. The choices render once the provider list is known, bounded at one second; until then the face shows
// reserved rows that hold the layout of the settled choices, so what the reply adds is the content of rows already
// there. happy-dom has no layout engine: the proof here is the row structure; the pixel trace is a browser run.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const win = new Window({ url: 'https://openkey.test/widget/embed/sign' });
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
});

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'sign-in-settle.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
interface SvelteClient {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
}
const SVELTE_CLIENT = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = (await import(SVELTE_CLIENT)) as SvelteClient;

type Provider = 'google' | 'apple';
type Shared = { load: () => Promise<Provider[]> };
const store = globalThis as unknown as { __settle: Shared };

const STUBS: Record<string, string> = {
  '$lib/auth-client': `export const authErrorMessage = (e, fallback) => fallback; export const authClient = { signIn: { passkey: async () => ({}) } };`,
  '$lib/embed-passkey': `export const isEmbedContext = () => true; export const embedSignInPasskey = async () => ({});
    export const embedSendEmailOtp = async () => {}; export const embedVerifyEmailOtp = async () => ({}); export const embedCreateAccount = async () => '';`,
  '$lib/social-auth': `export const loadConfiguredSocialProviders = () => globalThis.__settle.load(); export const signInWithSocialPopup = async () => {};`,
};

const compiledFiles = new Map<string, string>();
function compileComponent(file: string, stubs: Record<string, string>): string {
  const cached = compiledFiles.get(file);
  if (cached) return cached;
  const compiled = compile(readFileSync(file, 'utf8'), { generate: 'client', dev: false, name: 'Subject', filename: file });
  let code = '';
  let cursor = 0;
  for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    code += compiled.js.code.slice(cursor, match.index);
    const spec = match[1]!;
    let target = spec;
    if (spec in stubs) {
      const stubFile = join(OUT_DIR, `stub-${spec.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
      writeFileSync(stubFile, stubs[spec]!);
      target = pathToFileURL(stubFile).href;
    } else if (spec === 'svelte') target = SVELTE_CLIENT;
    else if (spec.startsWith('$lib/') && spec.endsWith('.svelte')) target = compileComponent(join(WEB_ROOT, 'src/lib', spec.slice(5)), stubs);
    else if (spec.startsWith('$lib/')) target = pathToFileURL(join(WEB_ROOT, 'src/lib', spec.slice(5))).href;
    code += `from '${target}'`;
    cursor = match.index! + match[0].length;
  }
  code += compiled.js.code.slice(cursor);
  const out = join(OUT_DIR, `${file.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, code);
  const url = pathToFileURL(out).href;
  compiledFiles.set(file, url);
  return url;
}

const AUTH_DIR = join(WEB_ROOT, 'src/lib/components/auth');
const socialButtonsUrl = compileComponent(join(AUTH_DIR, 'social-buttons.svelte'), STUBS);
const emptyFile = join(OUT_DIR, 'empty.mjs');
writeFileSync(emptyFile, compile('<div></div>', { generate: 'client', dev: false, name: 'Empty', filename: 'empty.svelte' }).js.code);
const EmbeddedSignIn = (await import(compileComponent(join(AUTH_DIR, 'embedded-sign-in.svelte'), {
  ...STUBS,
  './social-buttons.svelte': `export { default } from '${socialButtonsUrl}';`,
  './new-account-confirmation.svelte': `export { default } from '${pathToFileURL(emptyFile).href}';`,
}))).default;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await sleep(0);
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

/** The face's rows: the reserved ones while the providers are pending, the buttons once they are settled. */
function rows(target: HTMLElement): { reserved: number; buttons: string[] } {
  const pending = target.querySelector('[data-testid="sign-in-choices-pending"]');
  return {
    reserved: pending ? pending.querySelectorAll('.h-10').length : 0,
    buttons: [...target.querySelectorAll('button')].map((button) => button.getAttribute('aria-label') ?? button.textContent!.trim()),
  };
}

async function withFace(
  load: () => Promise<Provider[]>,
  act: (target: HTMLElement) => Promise<void>,
  props: Record<string, unknown> = {},
) {
  store.__settle = { load };
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(EmbeddedSignIn, { target, props: { prompt: 'Sign in', onauthenticated: () => {}, ...props } });
  try {
    flushSync();
    await act(target);
  } finally {
    unmount(app);
    target.remove();
  }
}

const FULL = ['Continue with email', 'Continue with Google', 'Continue with Apple', 'Passkey'];

describe('the embedded sign-in choices', () => {
  test('first paint shows reserved rows and no choices while the provider list is pending', async () => {
    await withFace(() => new Promise<Provider[]>(() => {}), async (target) => {
      const first = rows(target);
      expect(first.buttons).toEqual([]);
      expect(first.reserved).toBe(4);
      expect(target.textContent).not.toContain('Passkey');
      expect(target.textContent).not.toContain('Continue with email');
    });
  });

  test('a reply after 500 ms fills the reserved rows: same row count, Passkey in the same row', async () => {
    let reply!: (providers: Provider[]) => void;
    await withFace(() => new Promise<Provider[]>((resolve) => { reply = resolve; }), async (target) => {
      const first = rows(target);
      await sleep(500);
      flushSync();
      expect(rows(target)).toEqual(first);
      reply(['google', 'apple']);
      await until(() => rows(target).buttons.length > 0, 'the choices');
      const settled = rows(target);
      expect(settled.buttons).toEqual(FULL);
      expect(settled.reserved).toBe(0);
      expect(settled.buttons.length).toBe(first.reserved);
      expect(settled.buttons.indexOf('Passkey')).toBe(first.reserved - 1);
    });
  });

  test('a reply with no providers renders email and Passkey', async () => {
    await withFace(async () => [], async (target) => {
      await until(() => rows(target).buttons.length > 0, 'the choices');
      expect(rows(target).buttons).toEqual(['Continue with email', 'Passkey']);
    });
  });

  test('a failed provider request renders email and Passkey', async () => {
    await withFace(() => Promise.reject(new Error('offline')), async (target) => {
      await until(() => rows(target).buttons.length > 0, 'the choices');
      expect(rows(target).buttons).toEqual(['Continue with email', 'Passkey']);
    });
  });

  test('a request that never replies renders email and Passkey after the bound, and a late reply adds no row', async () => {
    let reply!: (providers: Provider[]) => void;
    await withFace(() => new Promise<Provider[]>((resolve) => { reply = resolve; }), async (target) => {
      await sleep(900);
      flushSync();
      expect(rows(target).buttons).toEqual([]);
      await sleep(300);
      flushSync();
      expect(rows(target).buttons).toEqual(['Continue with email', 'Passkey']);
      expect(rows(target).reserved).toBe(0);
      reply(['google', 'apple']);
      await sleep(20);
      flushSync();
      expect(rows(target).buttons).toEqual(['Continue with email', 'Passkey']);
    });
  });

  test('with passkeys unsupported the reserved rows and the settled rows still match', async () => {
    let reply!: (providers: Provider[]) => void;
    await withFace(() => new Promise<Provider[]>((resolve) => { reply = resolve; }), async (target) => {
      const first = rows(target);
      expect(first.reserved).toBe(3);
      reply(['google', 'apple']);
      await until(() => rows(target).buttons.length > 0, 'the choices');
      expect(rows(target).buttons).toEqual(['Continue with email', 'Continue with Google', 'Continue with Apple']);
    }, { passkeysSupported: false });
  });
});
