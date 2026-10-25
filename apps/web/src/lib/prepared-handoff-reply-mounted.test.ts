// Mounts the production prepared CLI handoff page and feeds it replies from
// authorize-sign-prepare, -preview and -sign that cannot be read: nothing is
// approved, the page shows the title and body of string 20 without the status,
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


type Scenario = { prepare?: Reply; preview?: Reply; sign?: Reply };
type Reply = { status: number; text: string };
const GOOD_PREPARE: Reply = { status: 200, text: JSON.stringify({ authorizationContextToken: 'context-token' }) };
/** The preview the server would give for these ids: they come back as the selection, grouped as permissions. */
function goodPreview(ids: string[]): Reply {
  const permissions = ids.map((id) => {
    const [service, space, path, ability] = id.split('\0');
    return { service, space, path, actions: [ability] };
  });
  return { status: 200, text: JSON.stringify({ signedMessage: 'signed', previewApprovalToken: 'approval', selectedActionKeys: ids, permissions }) };
}

/** Open the handoff page, answer each call from `scenario`, press Preview (and Approve when previewed). */
async function run(scenario: Scenario) {
  const siwe = siweFor(KV_REPLICATION);
  const claim = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:z6Mk' },
    delivery: { handoffId: opaque('handoff'), state: opaque('state'), cancelSecret: opaque('cancel') },
  };
  const encoded = `#tv2=${Buffer.from(JSON.stringify(claim)).toString('base64url')}`;
  const called: string[] = [];
  const asResponse = (reply: Reply) => ({
    ok: reply.status >= 200 && reply.status < 300,
    status: reply.status,
    json: async () => JSON.parse(reply.text),
  });
  const realFetch = globalThis.fetch;
  const errors: string[] = [];
  const realConsoleError = console.error;
  console.error = (...args: unknown[]) => { errors.push(args.map(String).join(' ')); };
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const name = url.split('/').pop() ?? url;
    called.push(name);
    const json = (body: unknown) => asResponse({ status: 200, text: JSON.stringify(body) });
    if (name === 'available') return json({ transportVersion: 2 });
    if (name === 'claim') return json({ transportVersion: 2, ticket: claim.delivery.handoffId, expiresAt: new Date(Date.now() + 240_000).toISOString() });
    if (name === 'authorize-sign-prepare') return asResponse(scenario.prepare ?? GOOD_PREPARE);
    if (name === 'authorize-sign-preview') return asResponse(scenario.preview ?? goodPreview(selectedActionIdsOf(String(init?.body))));
    if (name === 'authorize-sign') return asResponse(scenario.sign ?? { status: 500, text: '{"error":"unexpected"}' });
    return asResponse({ status: 500, text: '{"error":"unexpected"}' });
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  const button = (label: string) => [...target.querySelectorAll('button')].find((b) => b.textContent?.includes(label)) as HTMLButtonElement | undefined;
  const refusal = () => target.querySelector('[data-testid="server-reply-refusal"]');
  try {
    await until(() => button('Preview signing message') !== undefined && !button('Preview signing message')!.disabled, 'the Preview button');
    button('Preview signing message')!.click();
    await until(() => refusal() !== null || button('Approve') !== undefined, 'the preview answer');
    if (refusal() === null && scenario.sign !== undefined) {
      button('Approve')!.click();
      await until(() => refusal() !== null, 'the sign answer');
    }
  } finally {
    const result = {
      called,
      errors,
      shown: refusal() !== null,
      text: refusal()?.textContent?.replace(/\s+/g, ' ').trim() ?? '',
      alert: target.querySelector('[role="alert"]:not([data-testid])')?.textContent?.trim() ?? null,
      advanced: refusal()?.querySelector('details')?.textContent?.replace(/\s+/g, ' ').trim() ?? '',
      visibleOutsideAdvanced: (() => {
        const node = refusal();
        if (!node) return '';
        const clone = node.cloneNode(true) as HTMLElement;
        clone.querySelector('details')?.remove();
        return clone.textContent?.replace(/\s+/g, ' ').trim() ?? '';
      })(),
    };
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
    console.error = realConsoleError;
    return result;
  }
}

const TITLE = "OpenKey couldn't finish this request";
const BODY = "OpenKey couldn't read the server's reply, so nothing was approved. Please try again. If it keeps happening, contact the app.";

describe('the prepared CLI handoff page when a reply cannot be read', () => {
  const bad: Array<[string, Reply]> = [
    ['an empty body', { status: 200, text: '' }],
    ['an object without the fields', { status: 200, text: '{}' }],
  ];

  for (const [label, reply] of bad) {
    test(`prepare answers 200 with ${label}: refusal shown, nothing previewed or signed`, async () => {
      const result = await run({ prepare: reply });
      expect(result.shown).toBe(true);
      expect(result.visibleOutsideAdvanced).toBe(`${TITLE} ${BODY}`);
      expect(result.advanced).toContain('HTTP 200');
      expect(result.called).not.toContain('authorize-sign-preview');
      expect(result.called).not.toContain('authorize-sign');
      expect(result.errors.join(' ')).toContain('HTTP 200');
    });
  }

  test('prepare answers 200 with text that is not JSON', async () => {
    const result = await run({ prepare: { status: 200, text: 'not json' } });
    expect(result.shown).toBe(true);
    expect(result.visibleOutsideAdvanced).toBe(`${TITLE} ${BODY}`);
    expect(result.called).not.toContain('authorize-sign-preview');
  });

  test('preview answers 200 without a preview approval token', async () => {
    const result = await run({ preview: { status: 200, text: '{"signedMessage":"signed"}' } });
    expect(result.shown).toBe(true);
    expect(result.visibleOutsideAdvanced).toBe(`${TITLE} ${BODY}`);
    expect(result.called).not.toContain('authorize-sign');
  });

  test('sign answers 200 with an object without a signature: refusal shown', async () => {
    const result = await run({ sign: { status: 200, text: '{}' } });
    expect(result.shown).toBe(true);
    expect(result.visibleOutsideAdvanced).toBe(`${TITLE} ${BODY}`);
    expect(result.advanced).toContain('HTTP 200');
  });

  const SIGNED = { protocolVersion: 1, signature: `0x${'11'.repeat(65)}`, address: ADDR, signedMessage: 'signed', deliveryState: 'state', selectedKeyId: KEY.id, selectedActionKeys: ['key-1'], permissions: [] };
  const withoutField = (field: string) => { const { [field]: _removed, ...rest } = SIGNED as Record<string, unknown>; return rest; };
  const incomplete: Array<[string, unknown]> = [
    ['no selectedActionKeys', withoutField('selectedActionKeys')],
    ['no permissions', withoutField('permissions')],
    ['selectedActionKeys that is not a list', { ...SIGNED, selectedActionKeys: 'key-1' }],
    ['a permission that is not a grant', { ...SIGNED, permissions: [1] }],
  ];
  for (const [label, body] of incomplete) {
    test(`sign answers 200 with ${label}: string 20, nothing delivered`, async () => {
      const result = await run({ sign: { status: 200, text: JSON.stringify(body) } });
      expect(result.shown).toBe(true);
      expect(result.visibleOutsideAdvanced).toBe(`${TITLE} ${BODY}`);
      expect(result.alert).toBeNull();
    });
  }

  test('the status and the words of the refusal never meet in the visible text', async () => {
    const result = await run({ prepare: { status: 200, text: '{}' } });
    expect(result.visibleOutsideAdvanced).not.toMatch(/HTTP|<status>|\b200\b/);
    expect(result.text).toContain('Server reply');
  });

  test('a refusal with the server\'s own text keeps that text and shows no unreadable-reply refusal', async () => {
    const result = await run({ prepare: { status: 403, text: '{"error":"This website doesn\'t list the key this app asked for, so OpenKey didn\'t approve it."}' } });
    expect(result.shown).toBe(false);
    expect(result.alert).toBe("This website doesn't list the key this app asked for, so OpenKey didn't approve it.");
  });

  test('readable replies still reach the approval step', async () => {
    const result = await run({});
    expect(result.shown).toBe(false);
    expect(result.called).toContain('authorize-sign-preview');
  });
});
