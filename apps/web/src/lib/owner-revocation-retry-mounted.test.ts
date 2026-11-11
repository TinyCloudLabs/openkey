// Mounts the owner-revocation handoff page after a refused signing (TC-2382): Approve and Cancel come back.
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
const isolatedHome = execFileSync('mktemp', ['-d', '-p', '/var/tmp', 'revoke-retry.XXXXXX'], { encoding: 'utf8' }).trim();
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
import { privateKeyToAccount } from 'viem/accounts';
const owner = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const address = owner.address;
const key = { id: 'key-owner', address, keyIndex: 0, keyType: 'MANAGED', label: 'Owner wallet' };
const stubs: Record<string, string> = {
  '$app/navigation': 'export const afterNavigate = () => {}; export const replaceState = () => {};',
  '$lib/auth-client': 'export const authErrorMessage = (_, fallback) => fallback; export const authClient = { useSession: () => ({ subscribe(run) { run({ data: { user: { id: "owner" } }, isPending: false }); return () => {}; } }), signIn: { passkey: async () => ({}) } };',
  '$lib/api': `export const api = { listKeys: async () => ({ keys: [${JSON.stringify(key)}] }) };`,
  '$lib/clipboard': 'export const copyText = async () => {};',
  '$lib/embed-passkey': 'export const getSessionToken = () => null; export const isEmbedContext = () => false;',
};
for (const [name, source] of Object.entries(stubs)) writeFileSync(join(out, `${name.replace(/[^A-Za-z0-9]/g, '_')}.mjs`), source);
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const component = join(root, 'src/routes/delegate/OwnerRevocationHandoff.svelte');
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
const output = join(out, 'owner-review.mjs');
writeFileSync(output, source);
const Subject = (await import(pathToFileURL(output).href)).default;
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (seed: number) => Buffer.alloc(32, seed).toString('base64url');
const delivery = { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) };
const request = { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`, cid, nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(Date.now() + 590_000).toISOString() };
const encoded = `#tv2=${Buffer.from(JSON.stringify({ transportVersion: 2, request, delivery })).toString('base64url')}`;

async function until(check: () => boolean, step: string) {
  for (let i = 0; i < 200; i++) {
    flushSync();
    if (check()) return;
    await Promise.resolve();
  }
  throw new Error(`Timed out at ${step}: ${document.body.textContent}`);
}


const SIWE = `localhost:5173 wants you to sign in with your Ethereum account:\n${address}\n\n\nURI: ucan:${cid}\nVersion: 1\nChain ID: 1\nNonce: ${request.nonce}\nIssued At: ${new Date().toISOString()}\nExpiration Time: ${request.expiresAt}`;

const SIGNATURE = await owner.signMessage({ message: SIWE });

test('a refused signing shows the error, gives Revoke and Cancel back, and the next Revoke signs', async () => {
  const signReplies: Response[] = [
    Response.json({ error: 'Signing failed', code: 'sign_failed' }, { status: 500 }),
    Response.json({ siwe: SIWE, signature: SIGNATURE, deliveryState: delivery.state, selectedKeyId: key.id, protocolVersion: 1 }),
  ];
  const calls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const path = String(input);
    calls.push(path);
    if (path.endsWith('/available')) return Response.json({ transportVersion: 2 });
    if (path.endsWith('/claim')) return Response.json({ ticket: delivery.handoffId, expiresAt: new Date(Date.now() + 300_000).toISOString() });
    if (path.endsWith('/prepare')) return Response.json({ authorizationContextToken: 'token', siwe: SIWE });
    if (path.endsWith('/owner-revocation/sign')) return signReplies.shift()!;
    if (path.endsWith('/cancel-claimed')) return Response.json({ cancelled: true });
    throw new Error(`Unexpected request ${path}`);
  }) as typeof fetch;
  const target = document.createElement('div');
  document.body.append(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  const button = (label: string) => [...target.querySelectorAll('button')].find(b => b.textContent?.trim() === label) as HTMLButtonElement | undefined;
  try {
    await until(() => !!button('Revoke') && !button('Revoke')!.disabled, 'the Revoke button');
    button('Revoke')!.click();
    await until(() => !!target.querySelector('[role="alert"]'), 'the refusal');
    expect(target.querySelector('[role="alert"]')?.textContent).toContain('Signing failed');
    expect(button('Revoke')!.disabled).toBe(false);
    expect(button('Cancel')!.disabled).toBe(false);
    button('Revoke')!.click();
    await until(() => target.textContent!.includes('Paste this response into the CLI'), 'the signed result');
    expect(calls.filter(path => path.endsWith('/owner-revocation/sign'))).toHaveLength(2);
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = originalFetch;
  }
});

test('after a refused signing the owner can cancel', async () => {
  const calls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const path = String(input);
    calls.push(path);
    if (path.endsWith('/available')) return Response.json({ transportVersion: 2 });
    if (path.endsWith('/claim')) return Response.json({ ticket: delivery.handoffId, expiresAt: new Date(Date.now() + 300_000).toISOString() });
    if (path.endsWith('/prepare')) return Response.json({ authorizationContextToken: 'token', siwe: SIWE });
    if (path.endsWith('/owner-revocation/sign')) return Response.json({ error: 'Signing failed', code: 'sign_failed' }, { status: 500 });
    if (path.endsWith('/cancel-claimed')) return Response.json({ cancelled: true });
    throw new Error(`Unexpected request ${path}`);
  }) as typeof fetch;
  const target = document.createElement('div');
  document.body.append(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  const button = (label: string) => [...target.querySelectorAll('button')].find(b => b.textContent?.trim() === label) as HTMLButtonElement | undefined;
  try {
    await until(() => !!button('Revoke') && !button('Revoke')!.disabled, 'the Revoke button');
    button('Revoke')!.click();
    await until(() => !!target.querySelector('[role="alert"]'), 'the refusal');
    button('Cancel')!.click();
    await until(() => calls.some(path => path.endsWith('/cancel-claimed')), 'the cancel request');
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = originalFetch;
  }
});
