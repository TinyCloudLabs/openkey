// Mounts the production prepared CLI handoff page and checks that, before the claim, whether the CLI's
// request is still fresh is decided on the server's clock (the `Date` header of its first reply), not the
// device clock (TC-2382).
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test, vi } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { defaultSelection, parseCapabilityReview } from '../../../../packages/capability-review/src/index';

const win = new Window({ url: 'http://openkey.test/' });
Object.assign(globalThis, {
  window: win,
  document: win.document,
  HTMLElement: win.HTMLElement,
  Element: win.Element,
  Node: win.Node,
  HTMLMediaElement: win.HTMLMediaElement,
  HTMLInputElement: win.HTMLInputElement,
  HTMLSelectElement: win.HTMLSelectElement,
  HTMLTextAreaElement: win.HTMLTextAreaElement,
  HTMLFormElement: win.HTMLFormElement,
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
  sessionStorage: win.sessionStorage,
  location: win.location,
});

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'handoff-preclaim-clock.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
interface SvelteClient {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
}
const { mount, unmount, flushSync } = (await import(
  pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href
)) as SvelteClient;

// The page's outside world: the router, the session, the key list and the clipboard.
const KEY = { id: 'key_1', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Key' };
const stubs: Record<string, string> = {
  '$app/navigation': 'export const afterNavigate = () => {}; export const replaceState = () => {};',
  '$lib/auth-client': `export const authErrorMessage = (e, fallback) => fallback;
    export const authClient = { useSession: () => ({ subscribe(run) { run({ data: { user: { id: 'user_1' } }, isPending: false }); return () => {}; } }), signIn: { passkey: async () => ({}) } };`,
  '$lib/api': `export const api = { listKeys: async () => ({ keys: [${JSON.stringify(KEY)}] }) };`,
  '$lib/clipboard': 'export const copyText = async () => {};',
};
function stubUrl(name: string): string {
  const file = join(OUT_DIR, `${name.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(file, stubs[name]!);
  return pathToFileURL(file).href;
}

const COMPONENT = join(WEB_ROOT, 'src/routes/delegate/PreparedHandoff.svelte');
const compiled = compile(readFileSync(COMPONENT, 'utf8'), { generate: 'client', dev: false, name: 'Subject', filename: COMPONENT });
let code = '';
let cursor = 0;
for (const match of compiled.js.code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
  code += compiled.js.code.slice(cursor, match.index);
  const spec = match[1]!;
  let target = spec;
  if (spec in stubs) target = stubUrl(spec);
  // `svelte` resolves to its server build here, where onMount does nothing: use the client build.
  else if (spec === 'svelte') target = pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href;
  else if (spec === '@openkey/capability-review') {
    target = pathToFileURL(join(WEB_ROOT, '..', '..', 'packages', 'capability-review', 'src', 'index.ts')).href;
  } else if (spec.startsWith('$lib/')) target = pathToFileURL(join(WEB_ROOT, 'src/lib', spec.slice(5))).href;
  code += `from '${target}'`;
  cursor = match.index! + match[0].length;
}
code += compiled.js.code.slice(cursor);
const componentFile = join(OUT_DIR, 'prepared-handoff-preclaim-clock.mjs');
writeFileSync(componentFile, code);
const Subject = (await import(pathToFileURL(componentFile).href)).default as unknown;

// ---- the prepared request -------------------------------------------------

const ADDR = KEY.address;
const OWNER = `did:pkh:eip155:1:${ADDR}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDR}:default`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;

const opaque = (seed: string) => Buffer.from(seed.padEnd(32, '0')).toString('base64url').slice(0, 43);

function siweIssuedAt(issuedAt: Date): string {
  return [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:',
    ADDR,
    '',
    'TinyCloud delegation',
    '',
    'URI: https://cli.tinycloud.xyz',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    `Issued At: ${issuedAt.toISOString()}`,
    `Expiration Time: ${new Date(issuedAt.getTime() + 3_600_000).toISOString()}`,
    'Resources:',
    `- urn:recap:${Buffer.from(JSON.stringify({ att: { [SPACE]: { 'tinycloud.capabilities/read': [{}] } }, prf: [] })).toString('base64url')}`,
  ].join('\n');
}

/** Mount the page for a request issued at `issuedAt` while the server's clock reads `serverNow`. */
async function mountPage(issuedAt: Date, serverNow: Date) {
  const claim = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe: siweIssuedAt(issuedAt), jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:z6Mk' },
    delivery: { handoffId: opaque('handoff'), state: opaque('state'), cancelSecret: opaque('cancel') },
  };
  const encoded = `#tv2=${Buffer.from(JSON.stringify(claim)).toString('base64url')}`;
  const calls: string[] = [];
  const answer = (status: number, body: unknown) => ({
    ok: status >= 200 && status < 300, status,
    headers: { get: (name: string) => (name.toLowerCase() === 'date' ? serverNow.toUTCString() : null) },
    json: async () => body,
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const name = String(input).split('/').pop() ?? '';
    calls.push(name);
    if (name === 'available') return answer(200, { transportVersion: 2 });
    if (name === 'claim') return answer(200, { transportVersion: 2, ticket: claim.delivery.handoffId, expiresAt: new Date(serverNow.getTime() + 240_000).toISOString() });
    return answer(500, { error: 'unexpected' });
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  return {
    target, calls,
    alert: () => target.querySelector('[role="alert"]')?.textContent?.replace(/\s+/g, ' ').trim() ?? null,
    close() { unmount(app); target.remove(); globalThis.fetch = realFetch; },
  };
}

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

const EXPIRED = 'Prepared sign-in request expired. Restart the CLI command.';

describe('the prepared handoff page before the claim', () => {
  test('a fresh request is claimed when the device clock is an hour ahead of the server', async () => {
    const serverNow = new Date(Date.now() - 3_600_000);
    // Issued a minute ago on the server's clock; on this device's clock it is over an hour old.
    const page = await mountPage(new Date(serverNow.getTime() - 60_000), serverNow);
    await until(() => page.calls.includes('claim'), 'the claim request');
    expect(page.alert()).toBeNull();
    page.close();
  });

  test('a stale request is refused when the device clock is behind the server, and is not claimed', async () => {
    const serverNow = new Date(Date.now() + 3_600_000);
    // Issued a minute ago on this device's clock; the server's clock puts it over an hour back.
    const page = await mountPage(new Date(Date.now() - 60_000), serverNow);
    await until(() => page.alert() !== null, 'the expiry message');
    expect(page.alert()).toBe(EXPIRED);
    expect(page.calls).not.toContain('claim');
    page.close();
  });
});
