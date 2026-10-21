// Mounts the production hint component and checks only that the status
// element is rendered when `show` is true and absent when false. The copy
// itself is not pinned here.
// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';

// happy-dom globals must exist before the Svelte client runtime is imported.
// Reuse them if another test file already installed them.
if (!globalThis.document) {
  const win = new Window({ url: 'http://openkey.test/' });
  const globalNames = [
    'window', 'document', 'HTMLElement', 'Element', 'Node', 'Text', 'Comment',
    'navigator', 'CustomEvent', 'Event', 'KeyboardEvent', 'MouseEvent',
  ];
  for (const name of globalNames) {
    Reflect.set(globalThis, name, Reflect.get(win, name));
  }
  Reflect.set(globalThis, 'getComputedStyle', win.getComputedStyle.bind(win));
  Reflect.set(globalThis, 'requestAnimationFrame', win.requestAnimationFrame.bind(win));
  Reflect.set(globalThis, 'cancelAnimationFrame', win.cancelAnimationFrame.bind(win));
}

// The compiler and client runtime are loaded at runtime, after the DOM globals
// above are in place. Static imports would evaluate before the globals exist.
const { compile } = await import('svelte/compiler');
const require = createRequire(import.meta.url);
const svelteClientEntry = join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js');

interface SvelteClient {
  mount: (component: unknown, options: { target: Element; props: Record<string, unknown> }) => unknown;
  unmount: (component: unknown) => void;
  flushSync: () => void;
}
const svelteClient: SvelteClient = await import(pathToFileURL(svelteClientEntry).href);

const THIS_FILE = fileURLToPath(import.meta.url);
const WEB_ROOT = join(dirname(THIS_FILE), '..', '..');
const COMPONENT = join(dirname(THIS_FILE), 'components', 'signing', 'delegate-signing-hint.svelte');
const OUT_DIR = join(WEB_ROOT, '.svelte-kit', '_dom-hint');
const OUT_FILE = join(OUT_DIR, `hint-${process.pid}.js`);

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT_FILE, compile(readFileSync(COMPONENT, 'utf8'), { generate: 'client', filename: COMPONENT }).js.code);
// Compiled output is generated at test time, so its module type is only known at runtime.
const hintModule: { default: unknown } = await import(pathToFileURL(OUT_FILE).href);

afterAll(() => {
  rmSync(OUT_FILE, { force: true });
});

function renderHint(show: boolean): { statusCount: number; cleanup: () => void } {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const component = svelteClient.mount(hintModule.default, { target, props: { show } });
  svelteClient.flushSync();
  return {
    statusCount: target.querySelectorAll('[role="status"]').length,
    cleanup() {
      svelteClient.unmount(component);
      target.remove();
    },
  };
}

describe('delegate signing hint element', () => {
  test('is rendered when show is true', () => {
    const rendered = renderHint(true);
    expect(rendered.statusCount).toBe(1);
    rendered.cleanup();
  });

  test('is absent when show is false', () => {
    const rendered = renderHint(false);
    expect(rendered.statusCount).toBe(0);
    rendered.cleanup();
  });
});
