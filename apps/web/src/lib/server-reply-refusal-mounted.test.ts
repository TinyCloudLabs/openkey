// Mounts the refusal the widget pages show when the server's reply to prepare,
// preview or sign cannot be read (string 20): the title and body, the status in
// Advanced details only, and a Close control. The popup and the embedded page
// render this one component.

// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const win = new Window({ url: 'http://openkey.test/' });
const browserGlobals: Record<string, unknown> = {
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
  getComputedStyle: win.getComputedStyle.bind(win),
  requestAnimationFrame: win.requestAnimationFrame.bind(win),
  cancelAnimationFrame: win.cancelAnimationFrame.bind(win),
};
Object.assign(globalThis, browserGlobals);

// HOME and the tool homes point at a temp dir for this file.
const TEST_HOME = mkdtempSync('/var/tmp/tc1777.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc1777.'));
afterAll(() => {
  rmSync(OUT_DIR, { recursive: true, force: true });
  rmSync(TEST_HOME, { recursive: true, force: true });
  for (const [name, value] of savedHomes) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

const require = createRequire(import.meta.url);
interface SvelteClient {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
}
const { mount, unmount, flushSync } = (await import(
  pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href
)) as SvelteClient;

// Compile a $lib svelte file, pointing its imports at on-disk sources.
const compiled = new Map<string, string>();
async function compileSvelte(libRel: string): Promise<string> {
  const cached = compiled.get(libRel);
  if (cached) return cached;
  const result = compile(readFileSync(join(WEB_ROOT, 'src/lib', libRel), 'utf8'), {
    generate: 'client',
    dev: false,
    name: 'Subject',
    filename: `src/lib/${libRel}`,
  });
  let code = '';
  let cursor = 0;
  const importRe = /from\s+['"]([^'"]+)['"]/g;
  for (let match = importRe.exec(result.js.code); match; match = importRe.exec(result.js.code)) {
    code += result.js.code.slice(cursor, match.index);
    const spec = match[1]!;
    let target = spec;
    if (spec === '@openkey/capability-review') {
      target = pathToFileURL(join(WEB_ROOT, '..', '..', 'packages', 'capability-review', 'src', 'index.ts')).href;
    } else if (spec.startsWith('$lib/')) {
      const rel = spec.slice('$lib/'.length);
      target = rel.endsWith('.svelte')
        ? await compileSvelte(rel)
        : pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
    } else if (spec.startsWith('.')) {
      target = pathToFileURL(join(dirname(join(WEB_ROOT, 'src/lib', libRel)), spec)).href;
    }
    code += `from '${target}'`;
    cursor = match.index + match[0].length;
  }
  code += result.js.code.slice(cursor);
  const out = join(OUT_DIR, `${libRel.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, code);
  const url = pathToFileURL(out).href;
  compiled.set(libRel, url);
  return url;
}

const Refusal = (await import(await compileSvelte('components/signing/server-reply-refusal.svelte'))).default;

const TITLE = "OpenKey couldn't finish this request";
const BODY = "OpenKey couldn't read the server's reply, so nothing was approved. Please try again. If it keeps happening, contact the app.";

function render(status: number) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  let closed = 0;
  const app = mount(Refusal, { target, props: { status, onclose: () => { closed += 1; } } });
  flushSync();
  return { target, closed: () => closed, cleanup: () => { unmount(app); target.remove(); } };
}

const clean = (text: string | null | undefined) => (text ?? '').replace(/\s+/g, ' ').trim();

describe('the refusal for a reply that cannot be read', () => {
  test('shows the exact title and body', () => {
    const { target, cleanup } = render(200);
    const paragraphs = [...target.querySelectorAll('[role="alert"] p')].map((node) => clean(node.textContent));
    expect(paragraphs).toEqual([TITLE, BODY]);
    cleanup();
  });

  test('the status is in Advanced details only, and the visible text does not contain it', () => {
    const { target, cleanup } = render(200);
    const alert = clean(target.querySelector('[role="alert"]')?.textContent);
    expect(alert).toBe(`${TITLE} ${BODY}`);
    expect(alert).not.toMatch(/HTTP|<status>|200/);
    const advanced = target.querySelector('details');
    expect(clean(advanced?.querySelector('summary')?.textContent)).toBe('Advanced details');
    expect(clean(advanced?.querySelector('.row')?.textContent)).toBe('Server reply HTTP 200');
    cleanup();
  });

  test('shows the status it was given', () => {
    const { target, cleanup } = render(204);
    expect(clean(target.querySelector('details .value')?.textContent)).toBe('HTTP 204');
    cleanup();
  });

  test('Close calls onclose and nothing else is offered', () => {
    const { target, closed, cleanup } = render(200);
    const buttons = [...target.querySelectorAll('button')];
    expect(buttons.map((button) => clean(button.textContent))).toEqual(['Close']);
    buttons[0]!.click();
    flushSync();
    expect(closed()).toBe(1);
    cleanup();
  });
});
