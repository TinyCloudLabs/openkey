import { expect, test } from 'bun:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_REGISTRATION_PREVIEW_CHILD !== '1') {
  test('the actual consent page clears preview intents before any API request', async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', 'test', import.meta.path], {
      cwd: root, env: { ...process.env, OPENKEY_REGISTRATION_PREVIEW_CHILD: '1' }, stdout: 'pipe', stderr: 'pipe',
    });
    const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(code, stdout + stderr).toBe(0);
  }, 30_000);
} else {
  test('an unsupported preview origin makes no network request and retains no intent', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'org-registration-preview-'));
    const win = new Window({ url: 'https://tc128-preview.openkey-49x.pages.dev/org-registration/consent' });
    const calls: Array<{ host: string; path: string }> = [];
    const navigations: string[] = [];
    const denyFetch = async (input: string | URL | Request) => {
      const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
      calls.push({ host: url.hostname, path: url.pathname });
      return Response.json(null, { status: 401 });
    };
    Object.assign(globalThis, {
      window: win, document: win.document, HTMLElement: win.HTMLElement, Element: win.Element,
      Node: win.Node, Text: win.Text, Comment: win.Comment, navigator: win.navigator,
      CustomEvent: win.CustomEvent, Event: win.Event, MouseEvent: win.MouseEvent,
      getComputedStyle: win.getComputedStyle.bind(win), requestAnimationFrame: win.requestAnimationFrame.bind(win),
      cancelAnimationFrame: win.cancelAnimationFrame.bind(win), location: win.location,
      sessionStorage: win.sessionStorage, localStorage: win.localStorage, fetch: denyFetch,
    });
    // Navigation is observed inside this fixture, never allowed to leave its process.
    Object.defineProperty(win.location, 'replace', { value: (url: string) => { navigations.push(new URL(url, win.location.href).pathname); } });
    Object.defineProperty(win, 'fetch', { value: denyFetch });
    const storageKey = 'openkey.org-registration.intent.v1';
    const payload = { registrationId: '0ad181c0-5eea-4944-80ab-65ac5c68e53d', orgId: `o${'a'.repeat(26)}`, nonce: 'Z8M4jtvo7k2rnPGn1hFpQwzyOYpjdREsucYvgd_HXWk', handle: 'preview-fixture', displayName: 'Preview fixture', exp: Math.floor(Date.now() / 1000) + 600 };
    // Tab data is untrusted input; this test denies the origin before authorizing or displaying it.
    win.sessionStorage.setItem(storageKey, JSON.stringify({ intentJws: `e30.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.AA`, capturedAt: Date.now(), expiresAt: Date.now() + 600_000 }));
    win.document.documentElement.dataset.orgRegistration = 'ready';
    const require = createRequire(import.meta.url);
    const svelteClient = join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js');
    let mounted: unknown;
    let unmount: ((subject: unknown) => Promise<void>) | undefined;
    try {
      const web = join(root, 'apps/web');
      const entry = join(directory, 'entry.ts');
      // Bundle the component and its own client runtime together. Browser-only Svelte
      // exports must resolve under Bun.build's browser conditions, not Node require.
      await Bun.write(entry, `import Subject from ${JSON.stringify(join(web, 'src/routes/org-registration/consent/+page.svelte'))};\nexport { mount, unmount, flushSync } from ${JSON.stringify(svelteClient)};\nexport default Subject;\n`);
      const build = await Bun.build({
        // Do not let the runtime resolve generated entry.js back to its sibling entry.ts.
        entrypoints: [entry], outdir: join(directory, 'compiled'),
        target: 'browser', format: 'esm', conditions: ['browser'],
        loader: { '.svelte': 'js' },
        define: { 'import.meta.env.VITE_API_URL': '"https://api.openkey.so"' },
        plugins: [{ name: 'actual-svelte-consent', setup(builder) {
          builder.onResolve({ filter: /^\$lib\// }, args => {
            const base = join(web, 'src/lib', args.path.slice(5));
            const path = [base, `${base}.ts`, `${base}.js`].find(value => existsSync(value));
            if (!path) throw new Error('Unknown local consent import');
            return { path };
          });
          builder.onLoad({ filter: /\.svelte$/ }, async args => ({ contents: compile(await readFile(args.path, 'utf8'), { generate: 'client', dev: false, filename: args.path }).js.code, loader: 'js' }));
        } }],
      });
      if (!build.success) throw new Error(build.logs.map(log => log.message).join('\n'));
      const runtime = await import(pathToFileURL(build.outputs[0]!.path).href) as {
        default: unknown;
        mount(subject: unknown, options: { target: HTMLElement }): unknown;
        unmount(subject: unknown): Promise<void>;
        flushSync(): void;
      };
      unmount = runtime.unmount;
      const target = document.createElement('div'); document.body.append(target);
      mounted = runtime.mount(runtime.default, { target });
      runtime.flushSync();
      for (let turn = 0; turn < 8; turn += 1) { await new Promise<void>(resolve => setImmediate(resolve)); runtime.flushSync(); }
      expect(win.sessionStorage.getItem(storageKey)).toBeNull();
      expect(calls).toEqual([]);
      expect(navigations).toEqual([]);
    } finally {
      if (mounted) await unmount?.(mounted);
      await win.happyDOM.abort();
      await rm(directory, { recursive: true, force: true });
    }
  });
}
