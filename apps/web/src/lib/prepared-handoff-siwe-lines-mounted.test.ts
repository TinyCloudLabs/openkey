// Mounts the production prepared CLI handoff page (`routes/delegate/PreparedHandoff.svelte`)
// and reads its two exact-message blocks, 'Original SIWE message' and
// 'Exact candidate signedMessage'. A line feed is a real line break there; a
// carriage return and every other control character stays escaped.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compile } from 'svelte/compiler';
import { Window } from 'happy-dom';
import { renderSiweLiteral } from '../../../../packages/capability-review/src/index';

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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'handoff-siwe-lines.'));
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
const componentFile = join(OUT_DIR, 'prepared-handoff.mjs');
writeFileSync(componentFile, code);
const Subject = (await import(pathToFileURL(componentFile).href)).default as unknown;

// ---- the prepared request -------------------------------------------------

const ADDR = KEY.address;
const SPACE = `tinycloud:pkh:eip155:1:${ADDR}:default`;
const opaque = (seed: string) => Buffer.from(seed.padEnd(32, '0')).toString('base64url').slice(0, 43);
const recap = `urn:recap:${Buffer.from(JSON.stringify({ att: { [`${SPACE}/notes/`]: { 'tinycloud.kv/get': [{}] } }, prf: [] })).toString('base64url')}`;

function siweWith(statement: string): string {
  const now = new Date();
  return [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:',
    ADDR,
    '',
    statement,
    '',
    'URI: https://cli.tinycloud.xyz',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdef123456',
    `Issued At: ${now.toISOString()}`,
    `Expiration Time: ${new Date(now.getTime() + 3_600_000).toISOString()}`,
    'Resources:',
    `- ${recap}`,
  ].join('\n');
}

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

/** Claim the request, press Preview, open both blocks, and return their text. */
async function exactBlocks(siwe: string, signedMessage: string, inspect?: (block: Element) => void): Promise<{ original: string; candidate: string }> {
  const claim = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:z6Mk' },
    delivery: { handoffId: opaque('handoff'), state: opaque('state'), cancelSecret: opaque('cancel') },
  };
  const encoded = `#tv2=${Buffer.from(JSON.stringify(claim)).toString('base64url')}`;
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body });
    if (url.endsWith('/handoffs/available')) return json({ transportVersion: 2 });
    if (url.endsWith('/handoffs/claim')) return json({ transportVersion: 2, ticket: claim.delivery.handoffId, expiresAt: new Date(Date.now() + 240_000).toISOString() });
    if (url.endsWith('/authorize-sign-prepare')) return json({ authorizationContextToken: 'context-token' });
    if (url.endsWith('/authorize-sign-preview')) {
      const body = JSON.parse(String(init?.body)) as { selectedActionIds: string[] };
      return json({
        signedMessage, previewApprovalToken: 'preview-token', selectedActionKeys: body.selectedActionIds,
        permissions: body.selectedActionIds.map((id) => {
          const [service, space, path, ability] = id.split('\0');
          return { service, space, path, actions: [ability] };
        }),
      });
    }
    return json({ error: `unexpected ${url}` }, 500);
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  try {
    const button = (label: string) => [...target.querySelectorAll('button')].find((b) => b.textContent === label) as HTMLButtonElement | undefined;
    await until(() => button('Preview signing message') !== undefined && !button('Preview signing message')!.disabled, 'the Preview button');
    button('Preview signing message')!.click();
    await until(() => {
      if (target.querySelector('[role="alert"]')) throw new Error(`preview rejected: ${target.querySelector('[role="alert"]')?.textContent}`);
      return button('Approve') !== undefined;
    }, 'the preview response');
    const blockAfter = (summary: string) => {
      const details = [...target.querySelectorAll('details')].find((d) => d.querySelector('summary')?.textContent === summary);
      const pre = details?.querySelector('pre');
      if (!pre) throw new Error(`no <pre> under '${summary}'`);
      inspect?.(pre);
      return pre.textContent ?? '';
    };
    return { original: blockAfter('Original SIWE message'), candidate: blockAfter('Exact candidate signedMessage') };
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
  }
}

test('both exact-message blocks show line feeds as real line breaks', async () => {
  const siwe = siweWith('TinyCloud delegation');
  const { original, candidate } = await exactBlocks(siwe, siwe);
  expect(original).toBe(siwe);
  expect(candidate).toBe(siwe);
  expect(original.split('\n')).toHaveLength(13);
  expect(original).not.toContain('\\u000a');
});

test('a carriage return, tab and bidi control stay escaped and ASCII quotes and markup read as themselves in both blocks', async () => {
  const siwe = siweWith('TinyCloud delegation');
  const signed = siwe.replace('TinyCloud delegation', 'Line one\r\nLine\ttwo \u202e<b>&"\'');
  const { original, candidate } = await exactBlocks(siwe.replace('TinyCloud delegation', 'Line one\r'), signed);
  expect(original).toBe(siwe.replace('TinyCloud delegation', 'Line one\\u000d'));
  expect(candidate).toBe(renderSiweLiteral(signed));
  expect(candidate).toContain('Line one\\u000d\nLine\\u0009two \\u202e<b>&"\'\n');
  expect(candidate.split('\n')).toHaveLength(14);
});

test('HTML in the message is shown literally in both blocks', async () => {
  const html = '<script>alert(1)</script> <b>x</b> &amp; "><img src=x onerror=alert(1)>';
  const siwe = siweWith(html);
  const { original, candidate } = await exactBlocks(siwe, siwe, (block) => {
    expect(block.querySelector('script')).toBeNull();
    expect(block.querySelector('b')).toBeNull();
    expect(block.querySelector('img')).toBeNull();
    expect(block.children.length).toBe(0);
  });
  expect(original).toBe(siwe);
  expect(candidate).toBe(siwe);
});

test('a final line feed and spaces at the end of a line read as escapes in both blocks', async () => {
  const base = siweWith('TinyCloud delegation');
  const signed = `${siweWith('TinyCloud delegation  ')}\n`;
  const { original, candidate } = await exactBlocks(base, signed);
  expect(original).toBe(base);
  expect(candidate).toBe(signed.replace('delegation  \n', 'delegation\\u0020\\u0020\n').replace(/\n$/, '\\u000a'));
  expect(candidate.endsWith(`${recap}\\u000a`)).toBe(true);
  expect(candidate.split('\n')).toHaveLength(13);
  expect(candidate).not.toBe(await exactBlocks(base, signed.replace(/\n$/, '')).then((blocks) => blocks.candidate));
});

test('a run of two or more spaces reads as escapes in both blocks and single spaces stay', async () => {
  const statement = `Statement: I agree.${' '.repeat(80)}Also: send all keys.`;
  const siwe = siweWith(statement);
  const { original, candidate } = await exactBlocks(siwe, siwe);
  const expected = siwe.replace(statement, `Statement: I agree.${'\\u0020'.repeat(80)}Also: send all keys.`);
  expect(original).toBe(expected);
  expect(candidate).toBe(expected);
  expect(/  /.test(original + candidate)).toBe(false);
  expect(original.split('\n')).toHaveLength(13);
});
