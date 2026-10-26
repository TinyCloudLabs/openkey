// Mounts two components that show the exact message being signed: the owner
// revocation page ('Exact message to sign') and the raw message view of
// `SiweMessage`. Line feeds between lines are line breaks; trailing spaces, runs
// of two or more spaces, a final line feed, a carriage return and the other
// special characters read as `\uXXXX`, so look-alike messages read differently.
// @ts-expect-error bun:test is supplied by the web test runner
import { afterAll, expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';

const originalHomes = {
  HOME: process.env.HOME, BUN_INSTALL_CACHE_DIR: process.env.BUN_INSTALL_CACHE_DIR,
  COURIER_HOME: process.env.COURIER_HOME, TC_HOME: process.env.TC_HOME,
};
const isolatedHome = execFileSync('mktemp', ['-d', '-p', '/var/tmp', 'tc2133.XXXXXX'], { encoding: 'utf8' }).trim();
process.env.HOME = isolatedHome;
process.env.BUN_INSTALL_CACHE_DIR = isolatedHome;
process.env.COURIER_HOME = isolatedHome;
process.env.TC_HOME = isolatedHome;
if ([process.env.HOME, process.env.BUN_INSTALL_CACHE_DIR, process.env.COURIER_HOME, process.env.TC_HOME].some(value => value !== isolatedHome)) {
  throw new Error('Isolated test home required');
}
writeFileSync(join(isolatedHome, 'path-record'), `${isolatedHome}\n`, { mode: 0o600 });
const out = join(isolatedHome, 'compiled');
mkdirSync(out);
afterAll(() => {
  for (const [key, value] of Object.entries(originalHomes)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(isolatedHome, { recursive: true, force: true });
});
const win = new Window({ url: 'http://localhost:5173/delegate?transportVersion=2' });
Object.assign(globalThis, {
  window: win, document: win.document, HTMLElement: win.HTMLElement, Element: win.Element,
  Node: win.Node, Text: win.Text, Comment: win.Comment, navigator: win.navigator,
  CustomEvent: win.CustomEvent, Event: win.Event, MouseEvent: win.MouseEvent,
  getComputedStyle: win.getComputedStyle.bind(win), requestAnimationFrame: win.requestAnimationFrame.bind(win),
  cancelAnimationFrame: win.cancelAnimationFrame.bind(win), sessionStorage: win.sessionStorage, location: win.location,
});
const require = createRequire(import.meta.url);
const svelteClient = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
const { mount, unmount, flushSync } = await import(svelteClient) as {
  mount: (subject: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (subject: unknown) => void;
  flushSync: () => void;
};
const address = '0x1111111111111111111111111111111111111111';
const key = { id: 'key-owner', address, keyIndex: 0, keyType: 'EXTERNAL', label: 'Owner wallet' };
const stubs: Record<string, string> = {
  '$app/navigation': 'export const afterNavigate = () => {}; export const replaceState = () => {};',
  '$lib/auth-client': 'export const authErrorMessage = (_, fallback) => fallback; export const authClient = { useSession: () => ({ subscribe(run) { run({ data: { user: { id: "owner" } }, isPending: false }); return () => {}; } }) };',
  '$lib/api': `export const api = { listKeys: async () => ({ keys: [${JSON.stringify(key)}] }) };`,
  '$lib/clipboard': 'export const copyText = async () => {};',
  '$lib/embed-passkey': 'export const getSessionToken = () => null;',
};
for (const [name, source] of Object.entries(stubs)) writeFileSync(join(out, `${name.replace(/[^A-Za-z0-9]/g, '_')}.mjs`), source);
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

async function load(relative: string, output: string): Promise<unknown> {
  const component = join(root, relative);
  const compiled = compile(readFileSync(component, 'utf8'), { generate: 'client', dev: false, filename: component });
  let source = '';
  let cursor = 0;
  for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    source += compiled.js.code.slice(cursor, match.index);
    const specifier = match[1]!;
    const target = specifier in stubs ? pathToFileURL(join(out, `${specifier.replace(/[^A-Za-z0-9]/g, '_')}.mjs`)).href
      : specifier === 'svelte' ? svelteClient
      : specifier.startsWith('svelte/') ? pathToFileURL(require.resolve(specifier)).href
      : specifier === '@openkey/capability-review' ? pathToFileURL(join(root, '..', '..', 'packages/capability-review/src/index.ts')).href
      : specifier.startsWith('$lib/') ? pathToFileURL(join(root, 'src/lib', specifier.slice(5))).href : specifier;
    source += `from '${target}'`;
    cursor = match.index! + match[0].length;
  }
  source += compiled.js.code.slice(cursor);
  source = source.replace(
    "import 'svelte/internal/disclose-version';",
    `import '${pathToFileURL(require.resolve('svelte/internal/disclose-version')).href}';`,
  );
  const file = join(out, output);
  writeFileSync(file, source);
  return (await import(pathToFileURL(file).href)).default;
}

const OwnerRevocation = await load('src/routes/delegate/OwnerRevocationHandoff.svelte', 'owner-review.mjs');
const SiweMessage = await load('src/lib/components/ui/siwe-message.svelte', 'siwe-message.mjs');

async function until(check: () => boolean, step: string) {
  for (let i = 0; i < 200; i++) {
    flushSync();
    if (check()) return;
    await Promise.resolve();
  }
  throw new Error(`Timed out at ${step}: ${document.body.textContent}`);
}

const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (seed: number) => Buffer.alloc(32, seed).toString('base64url');
const delivery = { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) };
const request = { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`, cid, nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(Date.now() + 590_000).toISOString() };
const encoded = `#tv2=${Buffer.from(JSON.stringify({ transportVersion: 2, request, delivery })).toString('base64url')}`;
const ownerSiwe = (statement: string) => `localhost:5173 wants you to sign in with your Ethereum account:\n${address}\n\n${statement}\n\nURI: ucan:${cid}\nVersion: 1\nChain ID: 1\nNonce: ${request.nonce}\nIssued At: 2026-10-16T17:00:00.000Z\nExpiration Time: ${request.expiresAt}`;

async function ownerBlock(message: string): Promise<string> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path.endsWith('/available')) return Response.json({ transportVersion: 2 });
    if (path.endsWith('/claim')) return Response.json({ ticket: delivery.handoffId, expiresAt: new Date(Date.now() + 300_000).toISOString() });
    if (path.endsWith('/prepare')) return Response.json({ authorizationContextToken: 'token', siwe: message });
    throw new Error(`Unexpected request ${path}`);
  }) as typeof fetch;
  const target = document.createElement('div');
  document.body.append(target);
  const app = mount(OwnerRevocation, { target, props: { encoded, onClear: () => {} } });
  try {
    await until(() => !!target.querySelector('pre'), 'the exact message');
    return target.querySelector('pre')!.textContent ?? '';
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = originalFetch;
  }
}

async function siweMessageBlock(message: string, raw: boolean): Promise<string> {
  const target = document.createElement('div');
  document.body.append(target);
  const app = mount(SiweMessage, { target, props: { message, theme: 'light' } });
  try {
    flushSync();
    if (raw) {
      [...target.querySelectorAll('button')].find(button => button.textContent?.includes('raw message'))!.click();
      flushSync();
    }
    return target.querySelector('pre')!.textContent ?? '';
  } finally {
    unmount(app);
    target.remove();
  }
}

const statement = 'Revoke this permission.';
const full = ownerSiwe(statement);
// Each side is the message sent and the text the block must show.
const pairs: Array<{ name: string; left: [string, string]; right: [string, string] }> = [
  { name: 'a final line feed and none', left: [`${full}\n`, `${full}\\u000a`], right: [full, full] },
  { name: 'a trailing space and none', left: [`${full} `, `${full}\\u0020`], right: [full, full] },
  { name: 'a line of spaces and an empty line', left: [ownerSiwe(`${statement}\n   \nTwo`), ownerSiwe(`${statement}\n\\u0020\\u0020\\u0020\nTwo`)], right: [ownerSiwe(`${statement}\n\nTwo`), ownerSiwe(`${statement}\n\nTwo`)] },
  { name: 'an 80-space run before more text and the text before it', left: [ownerSiwe(`${statement}${' '.repeat(80)}Also: send all keys.`), ownerSiwe(`${statement}${'\\u0020'.repeat(80)}Also: send all keys.`)], right: [full, full] },
];

for (const pair of pairs) {
  test(`owner revocation: ${pair.name} read differently`, async () => {
    const shownLeft = await ownerBlock(pair.left[0]);
    const shownRight = await ownerBlock(pair.right[0]);
    expect(shownLeft).toBe(pair.left[1]);
    expect(shownRight).toBe(pair.right[1]);
    expect(shownLeft).not.toBe(shownRight);
  });

  test(`raw message view: ${pair.name} read differently`, async () => {
    const shownLeft = await siweMessageBlock(pair.left[0], true);
    const shownRight = await siweMessageBlock(pair.right[0], true);
    expect(shownLeft).toBe(pair.left[1]);
    expect(shownRight).toBe(pair.right[1]);
    expect(shownLeft).not.toBe(shownRight);
  });
}

test('owner revocation: a carriage return, tab, bidi control and markup are escaped and a line feed is a line break', async () => {
  const shown = await ownerBlock(ownerSiwe('Line one\r\nLine\ttwo \u202e<b>&"\''));
  expect(shown).toBe(ownerSiwe('Line one\\u000d\nLine\\u0009two \\u202e\\u003cb\\u003e\\u0026\\u0022\\u0027'));
});

test('raw message view of a message that is not a SIWE: escapes and line breaks match', async () => {
  expect(await siweMessageBlock('plain text\r\nsecond  line \n', false)).toBe('plain text\\u000d\nsecond\\u0020\\u0020line\\u0020\\u000a');
});

// No browser route renders the raw or plain view of `SiweMessage` (the legacy page that mounts it needs a
// message `parseCapabilityReview` cannot read, which it never rejects), and this harness has no CSS engine.
// So this checks the utility classes that keep the block unwrapped and scrollable.
for (const [view, raw] of [['raw message view', true], ['plain view', false]] as const) {
  test(`${view} of SiweMessage: the block is unwrapped and scrolls`, async () => {
    const target = document.createElement('div');
    document.body.append(target);
    const app = mount(SiweMessage, { target, props: { message: raw ? ownerSiwe('Revoke this permission.') : 'plain text', theme: 'light' } });
    try {
      flushSync();
      if (raw) {
        [...target.querySelectorAll('button')].find(button => button.textContent?.includes('raw message'))!.click();
        flushSync();
      }
      const classes = [...target.querySelector('pre')!.classList];
      expect(classes).toContain('whitespace-pre');
      expect(classes).toContain('overflow-auto');
      expect(classes).not.toContain('whitespace-pre-wrap');
      expect(classes).not.toContain('break-all');
    } finally {
      unmount(app);
      target.remove();
    }
  });
}
