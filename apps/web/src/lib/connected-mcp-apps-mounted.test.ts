// @ts-expect-error bun:test is supplied by the web test runner
import { afterAll, expect, test } from 'bun:test';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const out = mkdtempSync(join(tmpdir(), 'mcp-apps-'));
mkdirSync(join(out, 'compiled'));
afterAll(() => rmSync(out, { recursive: true, force: true }));

const win = new Window({ url: 'http://localhost:5173/dashboard/settings' });
Object.assign(globalThis, {
  window: win, document: win.document, HTMLElement: win.HTMLElement, Element: win.Element,
  Node: win.Node, Text: win.Text, Comment: win.Comment, navigator: win.navigator,
  CustomEvent: win.CustomEvent, Event: win.Event, MouseEvent: win.MouseEvent, KeyboardEvent: win.KeyboardEvent,
  getComputedStyle: win.getComputedStyle.bind(win), requestAnimationFrame: win.requestAnimationFrame.bind(win),
  cancelAnimationFrame: win.cancelAnimationFrame.bind(win), location: win.location,
});
const require = createRequire(import.meta.url);
const svelteClient = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = await import(svelteClient) as {
  mount: (subject: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (subject: unknown) => void;
  flushSync: () => void;
};

type DisconnectHook = (consentId: string) => Promise<void>;
const hooks = globalThis as typeof globalThis & { __disconnectMcpApp?: DisconnectHook };
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const stubApi = join(out, 'api-stub.mjs');
writeFileSync(stubApi, 'export const api = { disconnectMcpApp: (id) => globalThis.__disconnectMcpApp(id) };');
const component = join(root, 'src/routes/dashboard/settings/ConnectedMcpApps.svelte');
const compiled = compile(readFileSync(component, 'utf8'), { generate: 'client', dev: false, filename: component });
let source = '';
let cursor = 0;
for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
  source += compiled.js.code.slice(cursor, match.index);
  const specifier = match[1]!;
  const target = specifier === '$lib/api' ? pathToFileURL(stubApi).href
    : specifier === 'svelte' ? svelteClient
    : specifier.startsWith('svelte/') ? pathToFileURL(require.resolve(specifier)).href
    : specifier === '$lib/connected-mcp-apps' ? pathToFileURL(join(root, 'src/lib/connected-mcp-apps.ts')).href
    : specifier;
  source += `from '${target}'`;
  cursor = match.index! + match[0].length;
}
source += compiled.js.code.slice(cursor);
source = source.replace("import 'svelte/internal/disclose-version';", `import '${pathToFileURL(require.resolve('svelte/internal/disclose-version')).href}';`);
const output = join(out, 'compiled', 'connected-mcp-apps.mjs');
writeFileSync(output, source);
const Subject = (await import(pathToFileURL(output).href)).default;

const apps = [
  { kind: 'mcp', consentId: 'consent-1', clientId: 'client-1', name: 'Research Assistant', uri: 'https://mcp.example.test/app', host: 'mcp.example.test', icon: null, connectedAt: '2026-10-20T12:00:00.000Z', scopes: ['openid', 'tinycloud:mcp'] },
  { kind: 'mcp', consentId: 'consent-2', clientId: 'client-2', name: 'Notes Helper', uri: null, host: null, icon: null, connectedAt: '2026-10-21T12:00:00.000Z', scopes: ['tinycloud:mcp'] },
];

async function until(check: () => boolean, step: string) {
  for (let i = 0; i < 200; i++) {
    flushSync();
    if (check()) return;
    await Promise.resolve();
  }
  throw new Error(`Timed out at ${step}: ${document.body.textContent}`);
}
const button = (target: HTMLElement, label: string) => [...target.querySelectorAll('button')].find((item) => item.textContent?.trim() === label || item.getAttribute('aria-label') === label);

function render(props: { apps: unknown[]; onchanged?: () => void | Promise<void> }) {
  const target = document.createElement('div');
  document.body.append(target);
  const app = mount(Subject, { target, props: { onchanged: () => {}, ...props } });
  return { target, done: () => { unmount(app); target.remove(); } };
}

test('lists each connected MCP app with its host, scope in plain words and connection time', () => {
  const { target, done } = render({ apps });
  try {
    flushSync();
    const items = [...target.querySelectorAll('li')];
    expect(items.length).toBe(2);
    expect(items[0]!.textContent).toContain('Research Assistant');
    expect(items[0]!.textContent).toContain('mcp.example.test');
    expect(items[0]!.textContent).toContain('Lets this app use your TinyCloud through the MCP server.');
    expect(items[0]!.textContent!.indexOf('MCP server')).toBeLessThan(items[0]!.textContent!.indexOf('recognize your account'));
    expect(items[0]!.querySelector('time')?.getAttribute('datetime')).toBe('2026-10-20T12:00:00.000Z');
    expect(items[1]!.textContent).toContain('Notes Helper');
  } finally { done(); }
});

test('shows an empty state when no MCP app is connected', () => {
  const { target, done } = render({ apps: [] });
  try {
    flushSync();
    expect(target.textContent).toContain('No MCP apps are connected.');
    expect(target.querySelector('li')).toBeNull();
  } finally { done(); }
});

test('Disconnect asks first, cancel changes nothing, confirm deletes that consent and reports it', async () => {
  const calls: string[] = [];
  hooks.__disconnectMcpApp = async (id) => { calls.push(id); };
  let changed = 0;
  const { target, done } = render({ apps, onchanged: () => { changed++; } });
  try {
    flushSync();
    button(target, 'Disconnect Notes Helper')!.click();
    await until(() => !!target.querySelector('[role="dialog"]'), 'confirmation');
    expect(target.querySelector('[role="dialog"]')!.textContent).toContain('Disconnect Notes Helper?');
    expect(calls).toEqual([]);

    button(target, 'Cancel')!.click();
    await until(() => !target.querySelector('[role="dialog"]'), 'cancel');
    expect(calls).toEqual([]);
    expect(changed).toBe(0);

    button(target, 'Disconnect Notes Helper')!.click();
    await until(() => !!button(target, 'Disconnect app'), 'second confirmation');
    button(target, 'Disconnect app')!.click();
    await until(() => !!target.querySelector('[role="status"]'), 'disconnected notice');
    expect(calls).toEqual(['consent-2']);
    expect(changed).toBe(1);
    expect(target.querySelector('[role="status"]')!.textContent).toBe('Disconnected. The app will soon no longer be able to use your TinyCloud through MCP.');
  } finally { done(); }
});

test('a failed disconnect shows the server message and does not claim success', async () => {
  hooks.__disconnectMcpApp = async () => { throw new Error('Connected MCP app not found'); };
  let changed = 0;
  const { target, done } = render({ apps, onchanged: () => { changed++; } });
  try {
    flushSync();
    button(target, 'Disconnect Research Assistant')!.click();
    await until(() => !!button(target, 'Disconnect app'), 'confirmation');
    button(target, 'Disconnect app')!.click();
    await until(() => !!target.querySelector('[role="alert"]'), 'failure');
    expect(target.querySelector('[role="alert"]')!.textContent).toBe('Connected MCP app not found');
    expect(target.querySelector('[role="status"]')).toBeNull();
    expect(changed).toBe(0);
  } finally { done(); }
});
