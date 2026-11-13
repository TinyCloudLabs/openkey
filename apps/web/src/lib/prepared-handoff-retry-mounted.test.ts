// Mounts the production prepared CLI handoff page and drives a refused or failed signing (TC-2382): the
// Approve and Cancel buttons come back so the owner can try again, and the page expires on the server's
// clock, whatever the device clock says.
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'handoff-retry.'));
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

// The page mounts `$lib` components (the expiry line, TC-2933): compile them, and theirs, the same way.
function compileChild(file: string): string {
  const code = compile(readFileSync(file, 'utf8'), { generate: 'client', dev: false, name: 'Child', filename: file }).js.code
    .replace(/from\s+['"](\$lib\/[^'"]+)['"]/g, (_match, spec: string) => `from '${spec.endsWith('.svelte')
      ? compileChild(join(WEB_ROOT, 'src/lib', spec.slice(5)))
      : pathToFileURL(join(WEB_ROOT, 'src/lib', spec.slice(5))).href}'`);
  const out = join(OUT_DIR, `${file.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, code);
  return pathToFileURL(out).href;
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
  } else if (spec.startsWith('$lib/') && spec.endsWith('.svelte')) target = compileChild(join(WEB_ROOT, 'src/lib', spec.slice(5)));
  else if (spec.startsWith('$lib/')) target = pathToFileURL(join(WEB_ROOT, 'src/lib', spec.slice(5))).href;
  code += `from '${target}'`;
  cursor = match.index! + match[0].length;
}
code += compiled.js.code.slice(cursor);
const componentFile = join(OUT_DIR, 'prepared-handoff-retry.mjs');
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

type Reply = { status: number; body?: unknown; text?: string; wait?: Promise<void> } | 'network-failure';
const GOOD_SIGN = {
  protocolVersion: 1, address: ADDR, signature: '0xsigned', signedMessage: 'signed',
  selectedActionKeys: [] as string[], permissions: [] as unknown[], selectedKeyId: KEY.id, deliveryState: opaque('state'),
};

/**
 * Open the page and drive it to the Approve button. `signReplies` answers each press of Approve in order;
 * `serverDate` is the `Date` header of every answer and `claimExpiresInMs` how long the server gives the handoff.
 */
async function open(options: { signReplies?: Reply[]; serverDate?: () => string; claimExpiresInMs?: number } = {}) {
  const siwe = siweFor(KV_REPLICATION);
  const claim = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:z6Mk' },
    delivery: { handoffId: opaque('handoff'), state: opaque('state'), cancelSecret: opaque('cancel') },
  };
  const encoded = `#tv2=${Buffer.from(JSON.stringify(claim)).toString('base64url')}`;
  const signReplies = [...(options.signReplies ?? [])];
  const calls: string[] = [];
  const serverDate = options.serverDate ?? (() => new Date().toUTCString());
  const answer = (status: number, body: unknown, text?: string) => ({
    ok: status >= 200 && status < 300, status,
    headers: { get: (name: string) => (name.toLowerCase() === 'date' ? serverDate() : null) },
    json: async () => (text !== undefined ? JSON.parse(text) : body),
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const name = String(input).split('/').pop() ?? '';
    calls.push(name);
    if (name === 'available') return answer(200, { transportVersion: 2 });
    if (name === 'claim') return answer(200, { transportVersion: 2, ticket: claim.delivery.handoffId, expiresAt: new Date(Date.parse(serverDate()) + (options.claimExpiresInMs ?? 240_000)).toISOString() });
    if (name === 'authorize-sign-prepare') return answer(200, { authorizationContextToken: 'context-token' });
    if (name === 'authorize-sign-preview') {
      const ids = (JSON.parse(String(init?.body)) as { selectedActionIds: string[] }).selectedActionIds;
      const permissions = ids.map((id) => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      });
      return answer(200, { signedMessage: 'signed', previewApprovalToken: 'approval', selectedActionKeys: ids, permissions });
    }
    if (name === 'authorize-sign') {
      const reply = signReplies.shift() ?? { status: 500, body: { error: 'unexpected' } };
      if (reply === 'network-failure') throw new TypeError('Failed to fetch');
      if (reply.wait) await reply.wait;
      return answer(reply.status, reply.body, reply.text);
    }
    if (name === 'cancel-claimed') return answer(200, { cancelled: true });
    return answer(500, { error: 'unexpected' });
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  const button = (label: string) => [...target.querySelectorAll('button')].find((b) => b.textContent?.trim() === label) as HTMLButtonElement | undefined;
  await until(() => button('Preview signing message') !== undefined && !button('Preview signing message')!.disabled, 'the Preview button');
  button('Preview signing message')!.click();
  await until(() => button('Approve') !== undefined, 'the Approve button');
  return {
    target, button, calls,
    alert: () => target.querySelector('[role="alert"]')?.textContent?.replace(/\s+/g, ' ').trim() ?? null,
    approve: async (settled: () => boolean) => {
      button('Approve')!.click();
      await until(settled, 'the answer to Approve');
    },
    close() { unmount(app); target.remove(); globalThis.fetch = realFetch; },
  };
}

describe('the prepared handoff page after a signing that fails', () => {
  test('a refused signing shows the error and gives Approve and Cancel back; the next Approve signs', async () => {
    const page = await open({ signReplies: [{ status: 500, body: { error: 'TEE unavailable', code: 'sign_failed' } }, { status: 200, body: GOOD_SIGN }] });
    await page.approve(() => page.alert() !== null);
    expect(page.alert()).toBe('TEE unavailable');
    expect(page.button('Approve')!.disabled).toBe(false);
    expect(page.button('Cancel')!.disabled).toBe(false);
    await page.approve(() => page.target.textContent!.includes('Paste this response in your CLI'));
    expect(page.alert()).toBeNull();
    page.close();
  });

  test('a refused signing can be cancelled instead of retried', async () => {
    const page = await open({ signReplies: [{ status: 500, body: { error: 'TEE unavailable', code: 'sign_failed' } }] });
    await page.approve(() => page.alert() !== null);
    page.button('Cancel')!.click();
    await until(() => page.calls.includes('cancel-claimed'), 'the cancel request');
    page.close();
  });

  test('a request that never reaches the server gives Approve back too', async () => {
    const page = await open({ signReplies: ['network-failure', { status: 200, body: GOOD_SIGN }] });
    await page.approve(() => page.alert() !== null);
    expect(page.button('Approve')!.disabled).toBe(false);
    page.close();
  });

  test('an unreadable reply may have been signed by the server, so Approve stays off', async () => {
    const page = await open({ signReplies: [{ status: 200, text: '{}' }] });
    await page.approve(() => page.target.querySelector('[data-testid="server-reply-refusal"]') !== null);
    expect(page.button('Approve')!.disabled).toBe(true);
    page.close();
  });
});

describe('the prepared handoff page and the server clock', () => {
  test('expires when the server says it does, even if the device clock is an hour off', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      // The server is an hour behind this device. Read against the device clock the handoff
      // would already be over; on the server's clock it has 80 ms left.
      const skewMs = -3_600_000;
      const page = await open({ serverDate: () => new Date(Date.now() + skewMs).toUTCString(), claimExpiresInMs: 80_000 });
      expect(page.button('Approve')).toBeDefined();
      vi.advanceTimersByTime(79_000);
      flushSync();
      expect(page.button('Approve')).toBeDefined();
      vi.advanceTimersByTime(2_000);
      flushSync();
      expect(page.button('Approve')).toBeUndefined();
      expect(page.alert()).toBe('Prepared sign-in request expired. Restart the CLI command.');
      page.close();
    } finally {
      vi.useRealTimers();
    }
  });

  test('an expiry while a signing is in flight does not throw the handoff away: the signature that comes back is still delivered', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const signing = Promise.withResolvers<void>();
      const page = await open({ signReplies: [{ status: 200, body: GOOD_SIGN, wait: signing.promise }], claimExpiresInMs: 80_000 });
      page.button('Approve')!.click();
      flushSync();
      // The handoff's deadline passes while the server is still signing.
      vi.advanceTimersByTime(81_000);
      flushSync();
      expect(page.alert()).toBeNull();
      signing.resolve();
      await until(() => page.target.textContent!.includes('Paste this response in your CLI'), 'the signed result');
      expect(page.alert()).toBeNull();
      page.close();
    } finally {
      vi.useRealTimers();
    }
  });
});
