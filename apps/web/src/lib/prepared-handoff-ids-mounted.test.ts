// Mounts the production prepared CLI handoff page (`routes/delegate/PreparedHandoff.svelte`)
// with a prepared request, lets it claim, choose the key and preview, and reads
// the action ids it sends to /authorize-sign-preview. The ids are checked
// against the spelling the server holds for the same entries: for a raw
// encryption network entry the server's id is
// `service\0encryption\0<urn>\0ability`, the review model's is
// `service\0<urn>\0\0ability`.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { actionId, defaultSelection, parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { prepareSession, parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';

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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'handoff-ids.'));
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
const ENCRYPTION: Recap = { [NETWORK]: { 'tinycloud.encryption/decrypt': [{}] } };

/** The review model's ids for the request, as the page builds them. */
function reviewIds(siwe: string): string[] {
  const model = parseCapabilityReview({
    message: siwe,
    signer: { label: 'Key', address: ADDR, chainId: 1, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'No verified manifest supplied' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'cli.tinycloud.xyz', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none',
      manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  } as never);
  const selection = defaultSelection(model);
  return model.permissions.flatMap((grant) => grant.actions.filter((a) => selection.has(a.id)).map((a) => a.id));
}

// The page's awaits are all on the stubbed fetch below, which answers with
// plain objects, so yielding to the microtask queue is enough to let it advance.
async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 500; i++) {
    flushSync();
    if (condition()) return;
    await Promise.resolve();
  }
  throw new Error(`timed out waiting for ${what}: ${document.body.textContent?.slice(0, 300)}`);
}

function selectedActionIdsOf(body: string): string[] {
  const parsed: unknown = JSON.parse(body);
  if (!parsed || typeof parsed !== 'object' || !('selectedActionIds' in parsed) || !Array.isArray(parsed.selectedActionIds)) {
    throw new Error('the preview request has no selectedActionIds');
  }
  return parsed.selectedActionIds.map(String);
}

/** Open the handoff page for a request, claim it, and press Preview; returns what the page sent. */
async function previewRequest(siwe: string, successful = false): Promise<{ previewIds: string[]; status: string; approveVisible: boolean; summary: string; fullGrantCollapsed: boolean }> {
  const claim = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:z6Mk' },
    delivery: { handoffId: opaque('handoff'), state: opaque('state'), cancelSecret: opaque('cancel') },
  };
  const encoded = `#tv2=${Buffer.from(JSON.stringify(claim)).toString('base64url')}`;
  let previewIds: string[] = [];
  let status = 'no preview request';
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown, code = 200) => ({ ok: code < 400, status: code, json: async () => body });
    if (url.endsWith('/handoffs/available')) return json({ transportVersion: 2 });
    if (url.endsWith('/handoffs/claim')) return json({ transportVersion: 2, ticket: claim.delivery.handoffId, expiresAt: new Date(Date.now() + 240_000).toISOString() });
    if (url.endsWith('/authorize-sign-prepare')) return json({ authorizationContextToken: 'context-token' });
    if (url.endsWith('/authorize-sign-preview')) {
      previewIds = selectedActionIdsOf(String(init?.body));
      status = 'previewed';
      if (!successful) return json({ error: 'stop here' }, 400);
      const entries = parseRecapFromSiwe(siwe) as Array<{ service: string; space: string; path: string; actions: string[] }>;
      const permissions = entries.map((entry) => {
        const service = entry.service.startsWith('tinycloud.') ? entry.service : `tinycloud.${entry.service}`;
        return {
          service, space: entry.space, path: entry.path,
          actions: entry.actions.filter((ability) => previewIds.includes(actionId(service, entry.space, entry.path, ability))),
        };
      }).filter((entry) => entry.actions.length > 0);
      return json({ signedMessage: siwe, previewApprovalToken: 'preview-token', selectedActionKeys: previewIds, permissions });
    }
    return json({ error: `unexpected ${url}` }, 500);
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  try {
    const button = () => [...target.querySelectorAll('button')].find((b) => b.textContent?.includes('Preview signing message')) as HTMLButtonElement | undefined;
    await until(() => button() !== undefined && !button()!.disabled, 'the Preview button');
    button()!.click();
    await until(() => {
      if (successful && target.querySelector('[role="alert"]')) throw new Error(`preview rejected: ${target.querySelector('[role="alert"]')?.textContent}`);
      return status === 'previewed' && (!successful || [...target.querySelectorAll('button')].some((b) => b.textContent === 'Approve'));
    }, 'the preview response');
    return {
      previewIds,
      status,
      approveVisible: [...target.querySelectorAll('button')].some((b) => b.textContent === 'Approve' && !b.disabled),
      summary: target.textContent ?? '',
      fullGrantCollapsed: [...target.querySelectorAll('details')].filter((details) => details.querySelector('summary')?.textContent === 'Full grant').every((details) => !details.open),
    };
  } finally {
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
  }
}

const SERVER_DECRYPT = `tinycloud.encryption\0encryption\0${NETWORK}\0tinycloud.encryption/decrypt`;
const REVIEW_DECRYPT = `tinycloud.encryption\0${NETWORK}\0\0tinycloud.encryption/decrypt`;

describe('the prepared CLI handoff page sends the ids the server holds', () => {
  test('replication prefix with a raw encryption entry: the encryption id is in the server spelling, the others are unchanged', async () => {
    const siwe = siweFor({ ...KV_REPLICATION, ...ENCRYPTION });
    const review = reviewIds(siwe);
    expect(review).toContain(REVIEW_DECRYPT);
    const { previewIds } = await previewRequest(siwe);
    expect(previewIds).toHaveLength(review.length);
    expect(previewIds).toContain(SERVER_DECRYPT);
    expect(previewIds).not.toContain(REVIEW_DECRYPT);
    expect(previewIds.filter((id) => id !== SERVER_DECRYPT).sort()).toEqual(review.filter((id) => id !== REVIEW_DECRYPT).sort());
  });

  test('replication prefix with kv entries only: the ids are the review ids', async () => {
    const siwe = siweFor(KV_REPLICATION);
    const review = reviewIds(siwe);
    expect(review.length).toBeGreaterThan(0);
    const { previewIds } = await previewRequest(siwe);
    expect([...previewIds].sort()).toEqual([...review].sort());
  });
});

test('CLI --keys qa consent names the folder and unlocks Approve after a valid preview', async () => {
  const folder = `${NETWORK}/qa/`;
  const now = new Date();
  const siwe = prepareSession({
    address: ADDR, chainId: 1, domain: 'cli.tinycloud.xyz', spaceId: SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    issuedAt: now.toISOString(), expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    abilities: { kv: { '': ['tinycloud.kv/get'] }, capabilities: { '': ['tinycloud.capabilities/read'] } },
    rawAbilities: {
      [NETWORK]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create'],
      [folder]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'],
    },
  }).siwe;
  const rendered = await previewRequest(siwe, true);
  expect(rendered.previewIds).toContain(`tinycloud.encryption\0encryption\0${folder}\0tinycloud.encryption/key.create`);
  expect(rendered.previewIds).toContain(`tinycloud.encryption\0encryption\0${folder}\0tinycloud.encryption/decrypt`);
  expect(rendered.approveVisible).toBe(true);
  expect(rendered.summary).toContain('Your own encryption keys in qa/');
  expect(rendered.summary).toContain('Create encryption keys of your own in the folder `qa/`');
  expect(rendered.summary).toContain('Decrypt data locked with your own keys in the folder `qa/`');
  expect(rendered.fullGrantCollapsed).toBe(true);
});
