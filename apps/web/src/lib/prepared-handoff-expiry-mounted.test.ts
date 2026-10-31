// Mounts the production prepared CLI handoff page and drives its "Approval expires" control (TC-2274):
// the default, a pick up to what the CLI asked for, a pick past it, and the lock once the preview is sealed.
// and the HTTP status is only in Advanced details.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'handoff-expiry.'));
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
const componentFile = join(OUT_DIR, 'prepared-handoff-expiry.mjs');
writeFileSync(componentFile, code);
const Subject = (await import(pathToFileURL(componentFile).href)).default as unknown;

// ---- the prepared request -------------------------------------------------

const ADDR = KEY.address;
const OWNER = `did:pkh:eip155:1:${ADDR}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDR}:default`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;
const opaque = (seed: string) => Buffer.from(seed.padEnd(32, '0')).toString('base64url').slice(0, 43);

type Recap = Record<string, Record<string, unknown[]>>;

function recap(att: Recap): string {
  return `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;
}

function siweFor(att: Recap): string {
  const now = new Date();
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
    `Issued At: ${now.toISOString()}`,
    `Expiration Time: ${new Date(now.getTime() + 3_600_000).toISOString()}`,
    'Resources:',
    `- ${recap(att)}`,
  ].join('\n');
}

const KV_REPLICATION: Recap = {
  [`${SPACE}/notes/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/sync': [{}] },
  [SPACE]: { 'tinycloud.capabilities/read': [{}] },
};

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

/** Open the page with a 1 hour request and give back helpers to drive it; `previews` collects the preview request bodies. */
async function open() {
  const siwe = siweFor(KV_REPLICATION);
  const claim = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:z6Mk' },
    delivery: { handoffId: opaque('handoff'), state: opaque('state'), cancelSecret: opaque('cancel') },
  };
  const encoded = `#tv2=${Buffer.from(JSON.stringify(claim)).toString('base64url')}`;
  const previews: Array<Record<string, unknown>> = [];
  const asResponse = (body: unknown) => ({ ok: true, status: 200, json: async () => body });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const name = String(input).split('/').pop() ?? '';
    if (name === 'available') return asResponse({ transportVersion: 2 });
    if (name === 'claim') return asResponse({ transportVersion: 2, ticket: claim.delivery.handoffId, expiresAt: new Date(Date.now() + 240_000).toISOString() });
    if (name === 'authorize-sign-prepare') return asResponse({ authorizationContextToken: 'context-token' });
    if (name === 'authorize-sign-preview') {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      previews.push(body);
      const ids = (body.selectedActionIds as string[]);
      const permissions = ids.map((id) => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      });
      return asResponse({ signedMessage: 'signed', previewApprovalToken: 'approval', selectedActionKeys: ids, permissions });
    }
    return { ok: false, status: 500, json: async () => ({ error: 'unexpected' }) };
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  const button = (label: string) => [...target.querySelectorAll('button')].find((b) => b.textContent?.trim() === label) as HTMLButtonElement | undefined;
  const line = () => target.querySelector('[aria-label="Approval expiry"] p')?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
  const typeInto = (value: string) => {
    const input = target.querySelector<HTMLInputElement>('#approval-expiry-custom')!;
    input.value = value;
    input.dispatchEvent(new win.Event('input', { bubbles: true }) as unknown as Event);
    flushSync();
    target.querySelector('#approval-expiry-custom')!.closest('form')!.dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }) as unknown as Event);
    flushSync();
  };
  await until(() => button('Preview signing message') !== undefined && !button('Preview signing message')!.disabled, 'the Preview button');
  return {
    target, previews, button, line, typeInto, asked: Date.parse(/^Expiration Time: (.+)$/m.exec(siwe)![1]!),
    preview: async () => {
      button('Preview signing message')!.click();
      await until(() => previews.length > 0, 'the preview request');
    },
    close() { unmount(app); target.remove(); globalThis.fetch = realFetch; },
  };
}

describe('the prepared handoff page: Approval expires', () => {
  test('shows what the CLI asked for, and previews without an expiry when nothing is picked', async () => {
    const page = await open();
    expect(page.line()).toBe('Approval expires: 1h (Change)');
    await page.preview();
    expect(page.previews[0]).not.toHaveProperty('expirationTime');
    page.close();
  });

  test('a shorter pick shows and is what the preview asks the server to sign', async () => {
    const page = await open();
    page.button('(Change)')!.click();
    flushSync();
    page.typeInto('30m');
    expect(page.line()).toBe('Approval expires: 30m (Change)');
    const before = Date.now();
    await page.preview();
    const asked = Date.parse(String(page.previews[0]!.expirationTime));
    expect(asked).toBeGreaterThanOrEqual(before + 30 * 60_000 - 1000);
    expect(asked).toBeLessThanOrEqual(Date.now() + 30 * 60_000 + 1000);
    page.close();
  });

  test('a pick up to the CLI\'s own time never goes past it, even after time has passed', async () => {
    const page = await open();
    page.button('(Change)')!.click();
    flushSync();
    page.typeInto('59m');
    await page.preview();
    expect(Date.parse(String(page.previews[0]!.expirationTime))).toBeLessThanOrEqual(page.asked);
    page.close();
  });

  test('a pick past what the CLI asked for is refused with the note, and nothing changes', async () => {
    const page = await open();
    page.button('(Change)')!.click();
    flushSync();
    page.typeInto('2h');
    expect(page.target.querySelector('[role="alert"]')?.textContent).toBe(
      'This app asked for up to 1h. To allow longer, start the request again with a longer expiry.',
    );
    expect(page.line()).toBe('Approval expires: 1h (Change)');
    await page.preview();
    expect(page.previews[0]).not.toHaveProperty('expirationTime');
    page.close();
  });

  test('the presets stop at what the CLI asked for', async () => {
    const page = await open();
    page.button('(Change)')!.click();
    flushSync();
    expect(['1 hr', '24 hr', '7d', '30d'].filter((label) => page.button(label) !== undefined)).toEqual(['1 hr']);
    page.close();
  });

  test('once the preview is sealed the control is locked', async () => {
    const page = await open();
    page.button('(Change)')!.click();
    flushSync();
    await page.preview();
    await until(() => page.button('Approve') !== undefined, 'the Approve button');
    expect(page.button('(Change)')!.disabled).toBe(true);
    expect(page.target.querySelector('#approval-expiry-custom')).toBeNull();
    page.close();
  });
});
