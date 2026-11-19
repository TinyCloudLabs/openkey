// Mounts the production prepared CLI handoff page and answers its API calls
// with the statuses an owner meets mid-approval. Any 409 and any 410 on these
// sign paths is shown in the owner's words, never the server's text; other
// statuses keep the server text.
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
  HTMLMediaElement: win.HTMLMediaElement,
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
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'handoff-busy.'));
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
const componentFile = join(OUT_DIR, 'prepared-handoff.mjs');
writeFileSync(componentFile, code);
const Subject = (await import(pathToFileURL(componentFile).href)).default as unknown;

// ---- the prepared request -------------------------------------------------

const ADDR = KEY.address;
const OWNER = `did:pkh:eip155:1:${ADDR}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDR}:default`;
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

type Reply = { status: number; text: string };
type Scenario = { call: 'prepare' | 'preview' | 'sign' | 'cancel'; reply: Reply };
const GOOD_PREPARE: Reply = { status: 200, text: JSON.stringify({ authorizationContextToken: 'context-token' }) };
/** The preview the server would give for these ids: they come back as the selection, grouped as permissions. */
function goodPreview(ids: string[]): Reply {
  const permissions = ids.map((id) => {
    const [service, space, path, ability] = id.split('\0');
    return { service, space, path, actions: [ability] };
  });
  return { status: 200, text: JSON.stringify({ signedMessage: 'signed', previewApprovalToken: 'approval', selectedActionKeys: ids, permissions }) };
}
const SIGNED: Reply = {
  status: 200,
  text: JSON.stringify({ protocolVersion: 1, signature: `0x${'11'.repeat(65)}`, address: ADDR, signedMessage: 'signed', deliveryState: 'state', selectedKeyId: KEY.id, selectedActionKeys: ['key-1'], permissions: [] }),
};

const BUSY = 'This request is already being approved. Wait a moment.';
const ENDED = 'This request has already been answered or has ended.';

/**
 * Open the handoff page, drive it to the scenario's call, and answer that call
 * with the scenario's reply. Returns the alert text the owner reads.
 */
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
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const name = url.split('/').pop() ?? url;
    called.push(name);
    const json = (body: unknown) => asResponse({ status: 200, text: JSON.stringify(body) });
    if (name === 'available') return json({ transportVersion: 2 });
    if (name === 'claim') return json({ transportVersion: 2, ticket: claim.delivery.handoffId, expiresAt: new Date(Date.now() + 240_000).toISOString() });
    if (name === 'cancel-claimed') return scenario.call === 'cancel' ? asResponse(scenario.reply) : json({ cancelled: true });
    if (name === 'authorize-sign-prepare') return scenario.call === 'prepare' ? asResponse(scenario.reply) : asResponse(GOOD_PREPARE);
    if (name === 'authorize-sign-preview') return scenario.call === 'preview' ? asResponse(scenario.reply) : asResponse(goodPreview(selectedActionIdsOf(String(init?.body))));
    if (name === 'authorize-sign') return scenario.call === 'sign' ? asResponse(scenario.reply) : asResponse(SIGNED);
    return asResponse({ status: 500, text: '{"error":"unexpected"}' });
  }) as unknown as typeof fetch;
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Subject, { target, props: { encoded, onClear: () => {} } });
  const button = (label: string) => [...target.querySelectorAll('button')].find((b) => b.textContent?.includes(label)) as HTMLButtonElement | undefined;
  try {
    if (scenario.call === 'cancel') {
      // The review screen's Cancel posts cancel-claimed.
      await until(() => [...target.querySelectorAll('button')].some((b) => b.textContent?.trim() === 'Cancel'), 'the Cancel button');
      [...target.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Cancel')!.click();
    } else {
      await until(() => button('Preview signing message') !== undefined && !button('Preview signing message')!.disabled, 'the Preview button');
      button('Preview signing message')!.click();
      if (scenario.call === 'sign') {
        await until(() => button('Approve') !== undefined, 'the preview');
        button('Approve')!.click();
      }
    }
    await until(() => target.querySelector('[role="alert"]') !== null || button('Preview signing message')?.disabled === false, 'the answer');
  } finally {
    const result = {
      called,
      alert: target.querySelector('[role="alert"]:not([data-testid])')?.textContent?.trim() ?? null,
      text: target.textContent?.replace(/\s+/g, ' ').trim() ?? '',
    };
    unmount(app);
    target.remove();
    globalThis.fetch = realFetch;
    return result;
  }
}

const replies = {
  inProgress: { status: 409, text: '{"code":"approval_in_progress","error":"Approval request is being approved"}' } satisfies Reply,
  signing: { status: 409, text: '{"code":"handoff_signing","error":"Handoff is being signed"}' } satisfies Reply,
  bareConflict: { status: 409, text: '{"error":"Conflict"}' } satisfies Reply,
  gone: { status: 410, text: '{"code":"expired_request","error":"Approval request is no longer pending"}' } satisfies Reply,
};

describe('the prepared CLI handoff page when the request is already moving', () => {
  for (const call of ['prepare', 'preview', 'sign'] as const) {
    for (const [label, reply] of Object.entries(replies)) {
      if (label === 'gone') continue;
      test(`${call} answers 409 (${label}): the owner sees the busy wording, not the server text`, async () => {
        const result = await run({ call, reply });
        expect(result.alert).toBe(BUSY);
        expect(result.text).not.toContain('Handoff is being signed');
        expect(result.text).not.toContain('Approval request is being approved');
        expect(result.text).not.toContain('Conflict');
      });
    }
  }

  test('a 410 during signing is told in the owner\'s words, not the server text', async () => {
    const result = await run({ call: 'sign', reply: replies.gone });
    expect(result.alert).toBe(ENDED);
    expect(result.text).not.toContain('Approval request is no longer pending');
  });

  test('a 410 on cancel uses the same owner wording', async () => {
    const result = await run({ call: 'cancel', reply: { status: 410, text: '{"error":"Handoff expired"}' } });
    expect(result.alert).toBe(ENDED);
    expect(result.text).not.toContain('Handoff expired');
  });

  test('a 409 on cancel still tells the owner the request is being approved', async () => {
    const result = await run({ call: 'cancel', reply: replies.signing });
    expect(result.alert).toBe(BUSY);
  });

  test('other statuses keep the server text', async () => {
    const forbidden = await run({ call: 'prepare', reply: { status: 403, text: '{"error":"This website doesn\'t list the key this app asked for, so OpenKey didn\'t approve it."}' } });
    expect(forbidden.alert).toBe("This website doesn't list the key this app asked for, so OpenKey didn't approve it.");
    const failed = await run({ call: 'sign', reply: { status: 500, text: '{"error":"signing service unavailable"}' } });
    expect(failed.alert).toBe('signing service unavailable');
  });
});
