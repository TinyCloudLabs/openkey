// Mounts the production approval view: how long the access lasts, the line that says so on every screen, and
// which requests start at one hour (access to all secrets or all encrypted data) or at the app's own length.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import type { CapabilityReviewModel } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';

const win = new Window({ url: 'http://openkey.test/' });
const browserGlobals: Record<string, unknown> = {
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
};
Object.assign(globalThis, browserGlobals);

// HOME and the tool homes point at a temp dir for this file.
const TEST_HOME = mkdtempSync('/var/tmp/access-length.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'access-length.'));
afterAll(() => {
  rmSync(OUT_DIR, { recursive: true, force: true });
  rmSync(TEST_HOME, { recursive: true, force: true });
  for (const [name, value] of savedHomes) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

const require = createRequire(import.meta.url);
interface SvelteClient {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
}
const { mount, unmount, flushSync } = (await import(
  pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href
)) as SvelteClient;
// A parent's choices are shared state the component reads reactively.
const { SvelteMap } = (await import(
  pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/reactivity/index-client.js')).href
)) as { SvelteMap: new <K, V>() => Map<K, V> };

// Compile a $lib svelte file, pointing its imports at on-disk sources.
const compiled = new Map<string, string>();
async function compileSvelte(libRel: string): Promise<string> {
  const cached = compiled.get(libRel);
  if (cached) return cached;
  const result = compile(readFileSync(join(WEB_ROOT, 'src/lib', libRel), 'utf8'), {
    generate: 'client',
    dev: false,
    name: 'Subject',
    filename: `src/lib/${libRel}`,
  });
  let code = '';
  let cursor = 0;
  const importRe = /from\s+['"]([^'"]+)['"]/g;
  for (let match = importRe.exec(result.js.code); match; match = importRe.exec(result.js.code)) {
    code += result.js.code.slice(cursor, match.index);
    const spec = match[1]!;
    let target = spec;
    if (spec === '@openkey/capability-review') {
      target = pathToFileURL(join(WEB_ROOT, '..', '..', 'packages', 'capability-review', 'src', 'index.ts')).href;
    } else if (spec.startsWith('$lib/')) {
      const rel = spec.slice('$lib/'.length);
      target = rel.endsWith('.svelte')
        ? await compileSvelte(rel)
        : pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
    } else if (spec.startsWith('.')) {
      target = pathToFileURL(join(dirname(join(WEB_ROOT, 'src/lib', libRel)), spec)).href;
    }
    code += `from '${target}'`;
    cursor = match.index + match[0].length;
  }
  code += result.js.code.slice(cursor);
  const out = join(OUT_DIR, `${libRel.replace(/[^A-Za-z0-9]/g, '_')}.mjs`);
  writeFileSync(out, code);
  const url = pathToFileURL(out).href;
  compiled.set(libRel, url);
  return url;
}

const Approval = (await import(await compileSvelte('components/signing/signing-approval.svelte'))).default;

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const S = 1000;
const M = 60 * S;
const H = 60 * M;
const D = 24 * H;

type Attenuations = Record<string, Record<string, unknown[]>>;
const decrypt = (rest: string): Attenuations => ({ [urn(rest)]: { [`${E}decrypt`]: [{}] } });
const kvGet = (path: string): Attenuations => ({ [`${FIXTURE_META.ownSpace}/kv/${path}`]: { 'tinycloud.kv/get': [{}] } });

/** A request issued now that asks for `askMs`, so the length is the same from either end. */
function modelOf(att: Attenuations, askMs = 7 * D, now = Date.now()): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)], {
      issuedAt: new Date(now).toISOString(),
      expirationTime: new Date(now + askMs).toISOString(),
    }),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'listen.tinycloud.xyz', verifiedOrigin: 'https://listen.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}
const allIds = (m: CapabilityReviewModel) =>
  new Set(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));

/** A surface that writes the chosen time into the signed message and applies each choice at once. */
function mounted(m: CapabilityReviewModel, props: Record<string, unknown> = {}) {
  const state = new SvelteMap<string, unknown>();
  state.set('expiry', null);
  const calls: Array<number | null> = [];
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Approval, {
    target,
    props: {
      model: m,
      selection: allIds(m),
      get expiryMs() { return state.get('expiry') as number | null; },
      editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {},
      onExpiryChange: (ms: number | null) => { calls.push(ms); state.set('expiry', ms); },
      onceExpiryDefault: true,
      ...props,
    },
  });
  flushSync();
  return { target, calls, cleanup: () => { unmount(app); target.remove(); } };
}

/** A surface that signs the message as written: no expiry control. */
function signedAsWritten(m: CapabilityReviewModel) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Approval, {
    target,
    props: {
      model: m, selection: allIds(m), editing: false,
      onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {},
    },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const line = (t: HTMLElement) => text(t.querySelector('[data-testid="approval-expiry-line"]'));
const staticLine = (t: HTMLElement) => text(t.querySelector('[data-testid="approval-access-line"]'));
const note = (t: HTMLElement) => t.querySelector('[data-testid="approval-expiry-once-note"]');
// Over two days the line also names the owner's day it ends.
const SEVEN_DAYS = /^This app's access to your data lasts 7 days, until [A-Z][a-z]{2} \d{1,2}(, \d{4})?\.$/;

describe('one named secret starts at what the app asked for', () => {
  test('a 7-day request for one named secret starts at 7 days, with no one-hour note', () => {
    const { target, calls, cleanup } = mounted(modelOf(kvGet('vault/secrets/DEPLOY_KEY')));
    expect(calls).toEqual([]);
    expect(line(target)).toMatch(SEVEN_DAYS);
    expect(note(target)).toBeNull();
    cleanup();
  });

  test('turning renewal on for it still asks first', () => {
    const leases: Array<number | null> = [];
    const renewal = { leaseMs: null, maxLeaseMs: 365 * D, onChange: (ms: number | null) => { leases.push(ms); } };
    const { target, calls, cleanup } = mounted(modelOf(kvGet('vault/secrets/DEPLOY_KEY')), { renewal });
    expect(calls).toEqual([]);
    const box = target.querySelector<HTMLInputElement>('.renewal-box')!;
    expect(box.checked).toBe(false);
    box.checked = true;
    box.dispatchEvent(new win.Event('change', { bubbles: true }) as unknown as Event);
    flushSync();
    expect(leases).toEqual([]);
    expect(text(target.querySelector('.renewal-confirm-heading'))).toBe('Renew sensitive access?');
    cleanup();
  });
});

describe('access to all secrets or all encrypted data starts at one hour', () => {
  test.each([
    ['the whole network', decrypt('')],
    ['every app\'s keys (apps/)', decrypt('/apps/')],
    ['a one-segment prefix (shared/)', decrypt('/shared/')],
    ['a deeper prefix outside apps/ (shared/team/)', decrypt('/shared/team/')],
    ['every secret (vault/secrets/)', kvGet('vault/secrets/')],
  ])('%s', (_name: string, att: Attenuations) => {
    const { target, calls, cleanup } = mounted(modelOf(att));
    expect(calls).toEqual([H]);
    expect(line(target)).toBe("This app's access to your data lasts 1 hour.");
    expect(text(note(target))).toBe(
      'listen.tinycloud.xyz asked for 7 days. Access that can open all your secrets or all your encrypted data starts at 1 hour. You can choose longer under How long it lasts.',
    );
    cleanup();
  });

  test.each([
    ['one app\'s keys (apps/<appId>/)', decrypt('/apps/xyz.tinycloud.listen/')],
    ['a prefix inside one app', decrypt('/apps/xyz.tinycloud.listen/notes/')],
    ['one exact key', decrypt('/shared/team/key')],
    ['a secret sub-prefix', kvGet('vault/secrets/scoped/dev/')],
  ])('%s keeps what the app asked for', (_name: string, att: Attenuations) => {
    const { target, calls, cleanup } = mounted(modelOf(att));
    expect(calls).toEqual([]);
    expect(line(target)).toMatch(SEVEN_DAYS);
    expect(note(target)).toBeNull();
    cleanup();
  });
});

describe('a screen that signs the message as written says how long the access lasts', () => {
  test('the line names the length up to the message\'s own Expiration Time', () => {
    const { target, cleanup } = signedAsWritten(modelOf(kvGet('notes/')));
    expect(staticLine(target)).toMatch(SEVEN_DAYS);
    expect(target.querySelector('.expiry')).toBeNull();
    cleanup();
  });

  test('a request issued earlier shows what is left, never less', () => {
    const now = Date.now();
    const { target, cleanup } = signedAsWritten(modelOf(kvGet('notes/'), 2 * H, now - 30 * M - 10 * S));
    expect(staticLine(target)).toBe("This app's access to your data lasts 90 minutes.");
    cleanup();
  });

  test('an expired message shows no length', () => {
    const { target, cleanup } = signedAsWritten(modelOf(kvGet('notes/'), H, Date.now() - 2 * H));
    expect(staticLine(target)).toBeNull();
    cleanup();
  });
});
