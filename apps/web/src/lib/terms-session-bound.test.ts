// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { expect, test, vi } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { writable } from 'svelte/store';

test('a pending session store update keeps the original Terms timeout', async () => {
  const win = new Window({ url: 'https://openkey.test/' });
  const globals = {
    window: win,
    document: win.document,
    Element: win.Element,
    Node: win.Node,
    Text: win.Text,
    Comment: win.Comment,
  };
  const previousGlobals = Object.fromEntries(
    Object.keys(globals).map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]),
  );
  Object.assign(globalThis, globals);

  const webRoot = fileURLToPath(new URL('../../', import.meta.url));
  const kitDir = join(webRoot, '.svelte-kit');
  mkdirSync(kitDir, { recursive: true });
  const outDir = mkdtempSync(join(kitDir, 'terms-session-bound.'));
  try {
    function writeModule(name: string, source: string): string {
      const file = join(outDir, `${name}.mjs`);
      writeFileSync(file, source);
      return pathToFileURL(file).href;
    }

    const modules: Record<string, string> = {
      '$lib/components/auth/terms-step.svelte': writeModule('terms-step', 'export default () => {};'),
      '$lib/components/auth/terms-check-failed.svelte': writeModule('terms-check-failed',
        compile('<button>Try again</button>', { generate: 'client' }).js.code),
      '$lib/terms-gate': writeModule('terms-store',
        "import { writable } from 'svelte/store'; export const termsGate = writable({ phase: 'idle' });"),
      '$lib/terms-release': writeModule('terms-release', 'export const termsCheckedFirst = () => true;'),
      '$lib/terms': pathToFileURL(join(webRoot, 'src/lib/terms.ts')).href,
    };
    const gateFile = join(webRoot, 'src/lib/components/auth/terms-gate.svelte');
    const gate = writeModule('terms-gate', compile(readFileSync(gateFile, 'utf8'), {
      filename: gateFile, generate: 'client',
    }).js.code.replace(/from\s+['"](\$lib\/[^'"]+)['"]/g, (_match, spec: string) => `from '${modules[spec]}'`));

    const wrapper = writeModule('wrapper', compile(`
      <script>
        import TermsGate from '${gate}';
        let { session } = $props();
      </script>
      <TermsGate surface="web" sessionPending={$session.isPending}>
        <main>Account</main>
      </TermsGate>
    `, { generate: 'client' }).js.code);

    const require = createRequire(import.meta.url);
    const svelteClient = join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js');
    const { mount, unmount, flushSync } = await import(pathToFileURL(svelteClient).href);
    const { default: Wrapper } = await import(wrapper);
    const session = writable({ isPending: true, isRefetching: false });
    const target = win.document.body;

    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const app = mount(Wrapper, { target, props: { session } });
    try {
      flushSync();
      expect(target.querySelector('[data-testid="terms-checking"]')).not.toBeNull();

      vi.advanceTimersByTime(5_000);
      flushSync(() => session.set({ isPending: true, isRefetching: true }));
      vi.advanceTimersByTime(4_999);
      flushSync();
      expect(target.querySelector('[data-testid="terms-checking"]')).not.toBeNull();

      vi.advanceTimersByTime(1);
      flushSync();
      expect(target.querySelector('button')?.textContent).toBe('Try again');
      expect(target.querySelector('main')).toBeNull();
    } finally {
      unmount(app);
    }
  } finally {
    vi.useRealTimers();
    rmSync(outDir, { recursive: true, force: true });
    for (const [key, descriptor] of Object.entries(previousGlobals)) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  }
});
