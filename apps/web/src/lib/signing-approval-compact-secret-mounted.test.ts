// Mounts the production approval view: the sensitive-secret block is one row, one caution line and an inline length toggle.
// The toggle drives the length the surface signs.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, setSystemTime, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { formatEndAt, formatLengthWithEnd } from './approval-expiry';
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
const TEST_HOME = mkdtempSync('/var/tmp/compact-secret.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'compact-secret.'));
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
const SECRETS_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:secrets`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const S = 1000;
const M = 60 * S;
const H = 60 * M;
const D = 24 * H;

type Attenuations = Record<string, Record<string, unknown[]>>;
const readSecret = (name: string): Attenuations => ({ [`${SECRETS_SPACE}/kv/vault/secrets/${name}`]: { 'tinycloud.kv/get': [{}] } });
const keyOf = (name: string, abilities: string[]): Attenuations => ({
  [urn(`/secrets/${name.toLowerCase()}`)]: Object.fromEntries(abilities.map((ability) => [`${E}${ability}`, [{}]])),
});
/** One named secret: its value and its key (decrypt, and creating the key). */
const ONE_SECRET: Attenuations = { ...readSecret('BOT_HISTORY'), ...keyOf('BOT_HISTORY', ['decrypt', 'key.create']) };
const TWO_SECRETS: Attenuations = {
  ...readSecret('BOT_HISTORY'), ...keyOf('BOT_HISTORY', ['decrypt']),
  ...readSecret('DEPLOY_KEY'), ...keyOf('DEPLOY_KEY', ['decrypt']),
};
/** Every secret: the whole vault and every secret's key. */
const ALL_SECRETS: Attenuations = { ...readSecret(''), [urn('/secrets/')]: { [`${E}decrypt`]: [{}] } };

/** A request issued at the time of the call that asks for `askMs`. */
function modelOf(att: Attenuations, askMs = 7 * D, now = Date.now(), renewalOnlyResources: string[] = []): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)], {
      issuedAt: new Date(now).toISOString(),
      expirationTime: new Date(now + askMs).toISOString(),
    }),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    renewalOnlyResources,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'tinycloud.one', verifiedOrigin: 'https://tinycloud.one', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}
const allIds = (m: CapabilityReviewModel) =>
  new Set(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));

/** A surface that writes the chosen length into what it signs: `signedMs` is the length it would sign. */
function mounted(m: CapabilityReviewModel, props: Record<string, unknown> = {}) {
  const state = new SvelteMap<string, unknown>();
  state.set('expiry', null);
  state.set('model', m);
  const calls: Array<number | null> = [];
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Approval, {
    target,
    props: {
      get model() { return state.get('model') as CapabilityReviewModel; },
      selection: allIds(m),
      get expiryMs() { return state.get('expiry') as number | null; },
      editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {},
      onExpiryChange: (ms: number | null) => { calls.push(ms); state.set('expiry', ms); },
      onceExpiryDefault: true,
      ...props,
    },
  });
  flushSync();
  const setModel = (next: CapabilityReviewModel) => { state.set('model', next); flushSync(); };
  return { target, calls, setModel, cleanup: () => { unmount(app); target.remove(); } };
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const rows = (t: HTMLElement) => [...t.querySelectorAll('.summary-statement')].map(text);
const cautionOf = (t: HTMLElement) => text(t.querySelector('[data-testid="approval-expiry-compact-caution"]'));
const toggleOf = (t: HTMLElement) => t.querySelector<HTMLElement>('[data-testid="approval-expiry-toggle"]');
const segments = (t: HTMLElement) => [...(toggleOf(t)?.querySelectorAll<HTMLInputElement>('input[type="radio"]') ?? [])];
const announcement = (t: HTMLElement) => text(t.querySelector('[data-testid="approval-expiry-announcement"]'));
const face = (t: HTMLElement) => text(t.querySelector('.summary'));
function pick(t: HTMLElement, index: number) {
  const radio = segments(t)[index]!;
  radio.checked = true;
  radio.dispatchEvent(new win.Event('change', { bubbles: true }) as unknown as Event);
  flushSync();
}
const END_DAY = '[A-Z][a-z]{2} \\d{1,2}(, \\d{4})?';

describe('one named secret is one row, one caution line and a length toggle', () => {
  test('the row names the secret with the Sensitive mark; the key creation and the lifetime sentence are not on the face', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET));
    expect(rows(target)).toEqual(['Read the secret BOT_HISTORY Sensitive']);
    expect(cautionOf(target)).toBe('Only BOT_HISTORY. No other secret.');
    expect(target.querySelector('.summary-sensitive-pill')?.textContent).toBe('Sensitive');
    expect(face(target)).not.toContain('Create a key');
    expect(face(target)).not.toContain("can't read any of your secrets");
    expect(face(target)).not.toContain("This app's access to your data");
    expect(target.querySelector('[data-testid="approval-expiry-length-line"]')).toBeNull();
    expect(face(target)).not.toContain('marked Sensitive');
    cleanup();
  });

  test('key creation stays listed under the exact grants', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET));
    expect(text(target.querySelector('.permissions'))).toContain('key.create');
    cleanup();
  });

  test('the toggle starts at the length the app asked for, tagged (asked), and the end sits beside it', () => {
    const { target, calls, cleanup } = mounted(modelOf(ONE_SECRET));
    expect(calls).toEqual([]);
    expect(text(toggleOf(target)?.querySelector('legend'))).toBe('How long access lasts');
    const options = segments(target);
    expect(options.map((option) => text(option.closest('label')))).toEqual(['1 hour', '7 days (asked)']);
    expect(options.map((option) => option.checked)).toEqual([false, true]);
    expect(options.map((option) => option.getAttribute('aria-label'))).toEqual(['1 hour', '7 days, as the app asked']);
    expect(options.map((option) => option.closest('label')!.getAttribute('title'))).toEqual(options.map((option) => option.getAttribute('aria-label')));
    expect(text(toggleOf(target)?.querySelector('[data-testid="approval-expiry-end"]'))).toMatch(new RegExp(`^until ${END_DAY}$`));
    expect(announcement(target)).toMatch(new RegExp(`^Access lasts 7 days, until ${END_DAY}\\.$`));
    cleanup();
  });

  test('choosing 1 hour changes the length that is signed, announces it, and choosing the ask returns to it', () => {
    const { target, calls, cleanup } = mounted(modelOf(ONE_SECRET));
    pick(target, 0);
    expect(calls).toEqual([H]);
    expect(segments(target).map((option) => option.checked)).toEqual([true, false]);
    expect(announcement(target)).toMatch(/^Access lasts 1 hour, until \d{1,2}:\d{2} [AP]M\.$/);
    pick(target, 1);
    expect(calls).toEqual([H, null]);
    expect(segments(target).map((option) => option.checked)).toEqual([false, true]);
    cleanup();
  });

  test('a request for an hour has no toggle, only the line', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET, H));
    expect(toggleOf(target)).toBeNull();
    expect(text(target.querySelector('[data-testid="approval-expiry-length-line"]'))).toBe('Access lasts 1 hour.');
    expect(cautionOf(target)).toBe('Only BOT_HISTORY. No other secret.');
    cleanup();
  });

  test('a request that asks for more than the secret cap offers the longest allowed, not the ask', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET, 30 * D));
    expect(segments(target).map((option) => text(option.closest('label')))).toEqual(['1 hour', '7 days (longest allowed)']);
    cleanup();
  });

  test('a read of one secret with no key request is the same compact row as with a key request', () => {
    const { target, cleanup } = mounted(modelOf(readSecret('BOT_HISTORY')));
    expect(rows(target)).toEqual(['Read the secret BOT_HISTORY Sensitive']);
    expect(cautionOf(target)).toBe('Only BOT_HISTORY. No other secret.');
    expect(segments(target).map((option) => text(option.closest('label')))).toEqual(['1 hour', '7 days (asked)']);
    expect(face(target)).not.toContain('marked Sensitive');
    expect(face(target)).not.toContain("This app's access to your data");
    cleanup();
  });

  test('the name is set on one line in the row and in the caution', () => {
    const { target, cleanup } = mounted(modelOf(keyOf('bot-history', ['decrypt'])));
    expect(text(target.querySelector('.statement-primary .secret-name'))).toBe('bot-history');
    expect(text(target.querySelector('[data-testid="approval-expiry-compact-caution"] .secret-name'))).toBe('bot-history.');
    cleanup();
  });

  test('the period after the name is inside the no-break run, so no line holds only ". No other secret."', () => {
    const name = 'BOT_HISTORY_PRODUCTION_DEPLOY_KEY_2026_X';
    const { target, cleanup } = mounted(modelOf(readSecret(name)));
    const caution = target.querySelector('[data-testid="approval-expiry-compact-caution"]')!;
    const run = caution.querySelector('.secret-name')!;
    expect(text(run)).toBe(`${name}.`);
    expect(run.previousSibling?.textContent).toBe('Only ');
    expect(run.nextSibling?.textContent).toBe(' No other secret.');
    expect(cautionOf(target)).toBe(`Only ${name}. No other secret.`);
    cleanup();
  });
});

describe('a read with no key request names only secrets that nothing else in the request opens', () => {
  test('a read of one secret with a decrypt on the whole vault prefix keeps its ordinary rows, never "Only NAME"', () => {
    const { target, cleanup } = mounted(modelOf({ ...readSecret('BOT_HISTORY'), [urn('/secrets/')]: { [`${E}decrypt`]: [{}] } }));
    expect(rows(target)).toEqual(['Decrypt data locked with your keys in secrets/ Sensitive', 'Read secret values Sensitive']);
    expect(face(target)).not.toContain('Only BOT_HISTORY');
    expect(face(target)).not.toContain('Read the secret BOT_HISTORY');
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });

  test('two reads with no key requests are one "Read secret values" row for 2 secrets', () => {
    const { target, cleanup } = mounted(modelOf({ ...readSecret('BOT_HISTORY'), ...readSecret('DEPLOY_KEY') }));
    expect(rows(target)).toEqual(['Read secret values Sensitive']);
    expect(cautionOf(target)).toBe('Only these 2 secrets. Names are in Advanced details.');
    cleanup();
  });

  test('Advanced details lists each secret read with no key request by name and its exact value path', () => {
    const { target, cleanup } = mounted(modelOf({ ...readSecret('BOT_HISTORY'), ...readSecret('DEPLOY_KEY') }));
    const entries = [...target.querySelectorAll('[data-testid="secrets-group"] li.grant')];
    expect(entries.map((entry) => text(entry.querySelector('.grant-title')))).toEqual(['Secret: BOT_HISTORY', 'Secret: DEPLOY_KEY']);
    expect(entries.map((entry) => text(entry.querySelector('.grant-path')))).toEqual(['vault/secrets/BOT_HISTORY', 'vault/secrets/DEPLOY_KEY']);
    cleanup();
  });
});

describe('several named secrets are one "Read secret values" row', () => {
  test('one row with the Sensitive mark, the count in the caution, and no header', () => {
    const { target, cleanup } = mounted(modelOf(TWO_SECRETS));
    expect(rows(target)).toEqual(['Read secret values Sensitive']);
    expect(cautionOf(target)).toBe('Only these 2 secrets. Names are in Advanced details.');
    expect(face(target)).not.toContain('marked Sensitive');
    expect(text(target.querySelector('.permissions'))).toContain('secrets/bot_history');
    expect(text(target.querySelector('.permissions'))).toContain('secrets/deploy_key');
    expect(segments(target).map((option) => text(option.closest('label')))).toEqual(['1 hour', '7 days (asked)']);
    cleanup();
  });
});

describe('the secrets the row covers are listed by name under Advanced details', () => {
  test('one group of "Secret: NAME" rows with each exact path, as many as the count in the caution', () => {
    const { target, cleanup } = mounted(modelOf(TWO_SECRETS));
    const group = target.querySelector('[data-testid="secrets-group"]')!;
    expect(text(group.querySelector('.bucket-heading'))).toBe('Secrets');
    const entries = [...group.querySelectorAll('li.grant')];
    expect(entries.map((entry) => text(entry.querySelector('.grant-title')))).toEqual(['Secret: BOT_HISTORY', 'Secret: DEPLOY_KEY']);
    expect(entries.map((entry) => text(entry.querySelector('.grant-path')))).toEqual(['secrets/bot_history', 'secrets/deploy_key']);
    expect(cautionOf(target)).toBe(`Only these ${entries.length} secrets. Names are in Advanced details.`);
    cleanup();
  });

  test('named secrets that are every secret today read as the named ones; only the vault prefix reads as all', () => {
    const { target, cleanup } = mounted(modelOf(TWO_SECRETS));
    expect(rows(target)).toEqual(['Read secret values Sensitive']);
    expect(cautionOf(target)).toBe('Only these 2 secrets. Names are in Advanced details.');
    expect(face(target)).not.toContain('every secret in your vault');
    cleanup();
    const whole = mounted(modelOf(ALL_SECRETS));
    expect(rows(whole.target)).toEqual(['Read all your secret values Sensitive']);
    expect(whole.target.querySelector('[data-testid="secrets-group"]')).toBeNull();
    whole.cleanup();
  });
});

const DECRYPT_PREFIX: Attenuations = { [urn('/secrets/')]: { [`${E}decrypt`]: [{}] } };
const kvAt = (path: string, abilities: string[], space = SECRETS_SPACE): Attenuations => ({
  [`${space}/kv/${path}`]: Object.fromEntries(abilities.map((ability) => [ability, [{}]])),
});
const GET = 'tinycloud.kv/get';

describe('only a read keeps the compact block: a request with any other action on the secrets keeps its own rows', () => {
  const OLD_FACE: Array<[string, Attenuations, string[]]> = [
    ['put and delete beside the read of the secrets directory', { ...kvAt('vault/secrets/', [GET, 'tinycloud.kv/put', 'tinycloud.kv/del']), ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Read, update and delete secret values Sensitive']],
    ['put alone on the secrets directory', { ...kvAt('vault/secrets/', ['tinycloud.kv/put']), ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Update secret values Sensitive']],
    ['the kv wildcard', { ...kvAt('vault/secrets/', ['tinycloud.kv/*']), ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Unknown action: tinycloud.kv/* Sensitive']],
    ['kv admin', { ...kvAt('vault/secrets/', ['tinycloud.kv/admin']), ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Unknown action: tinycloud.kv/admin Sensitive']],
    ['the secrets service writes', { [`${SECRETS_SPACE}/secrets/vault/secrets/`]: { 'tinycloud.secrets/put': [{}], 'tinycloud.secrets/delete': [{}] }, ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Unknown actions: tinycloud.secrets/delete, tinycloud.secrets/put Sensitive']],
  ];
  test.each(OLD_FACE)('%s', (_label, att, expected) => {
    const { target, cleanup } = mounted(modelOf(att));
    expect(rows(target)).toEqual(expected);
    expect(face(target)).not.toContain('Read all your secret values');
    expect(toggleOf(target)).toBeNull();
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });
});

describe('"Read all your secret values" is the secrets directory read, the decrypt on the secrets prefix, or both, and nothing else', () => {
  test('the secrets directory with no trailing slash reads as all as well', () => {
    const { target, cleanup } = mounted(modelOf({ ...kvAt('vault/secrets', [GET]), ...DECRYPT_PREFIX }));
    expect(rows(target)).toEqual(['Read all your secret values Sensitive']);
    cleanup();
  });

  test('the read alone and the decrypt alone each read as all', () => {
    for (const att of [kvAt('vault/secrets/', [GET]), DECRYPT_PREFIX]) {
      const { target, cleanup } = mounted(modelOf(att));
      expect(rows(target)).toEqual(['Read all your secret values Sensitive']);
      expect(cautionOf(target)).toBe('Covers every secret in your vault.');
      cleanup();
    }
  });

  const ELSE = FIXTURE_META.crossAppOwner;
  const elseDecrypt = { [`urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${ELSE}:default/secrets/`]: { [`${E}decrypt`]: [{}] } };
  const elseKv = kvAt('vault/secrets/', [GET], `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${ELSE}:secrets`);
  test.each([
    ["a decrypt on another account's default/secrets/", elseDecrypt, ["Decrypt another user's data Sensitive"]],
    ["a read of vault/secrets/ in another account's space", elseKv, ["Read another user's secret values Sensitive"]],
    ["the read of vault/secrets/ beside a decrypt on another account's default/secrets/", { ...kvAt('vault/secrets/', [GET]), ...elseDecrypt },
      ['Read secret values Sensitive', "Decrypt another user's data Sensitive"]],
    ["the decrypt on default/secrets/ beside a read of vault/secrets/ in another account's space", { ...DECRYPT_PREFIX, ...elseKv },
      ['Decrypt data locked with your keys in secrets/ Sensitive', "Read another user's secret values Sensitive"]],
    ['the decrypt on default/secrets/ of the own address on chain 137', { [`urn:tinycloud:encryption:did:pkh:eip155:137:${FIXTURE_META.address}:default/secrets/`]: { [`${E}decrypt`]: [{}] } } as Attenuations, ["Decrypt another user's data Sensitive"]],
    ['a read of vault/secrets/ in the secrets space of the own address on chain 137', kvAt('vault/secrets/', [GET], `tinycloud:pkh:eip155:137:${FIXTURE_META.address}:secrets`), ["Read another user's secret values Sensitive"]],
    ['a read of vault/secrets/ in the default space beside the decrypt on default/secrets/', { ...kvAt('vault/secrets/', [GET], FIXTURE_META.ownSpace), ...DECRYPT_PREFIX } as Attenuations, ['Decrypt data locked with your keys in secrets/ Sensitive', 'View secrets stored in your vault Sensitive']],
  ])('%s keeps its own rows and never reads as "your" secrets', (_name: string, att: Attenuations, expected: string[]) => {
    const { target, cleanup } = mounted(modelOf(att));
    expect(rows(target)).toEqual(expected);
    expect(face(target)).not.toContain('Covers every secret in your vault');
    expect(target.querySelector('[data-testid="approval-expiry-compact-caution"]')).toBeNull();
    cleanup();
  });

  const OTHER: Array<[string, Attenuations, string[]]> = [
    ['a decrypt on the scoped prefix alone', { [urn('/secrets/scoped/')]: { [`${E}decrypt`]: [{}] } }, ['Decrypt data locked with your keys in secrets/scoped/ Sensitive']],
    ['the secrets directory read with a decrypt on the scoped prefix', { ...readSecret(''), [urn('/secrets/scoped/')]: { [`${E}decrypt`]: [{}] } },
      ['Decrypt data locked with your keys in secrets/scoped/ Sensitive', 'Read secret values Sensitive']],
    ['a read of vault/ alone', kvAt('vault/', [GET]), ['Read secret values Sensitive']],
    ['a read of vault/ with a decrypt on the secrets prefix', { ...kvAt('vault/', [GET]), ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Read secret values Sensitive']],
    ['a read of vault with a decrypt on the secrets prefix', { ...kvAt('vault', [GET]), ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Read secret values Sensitive']],
    ['a read of secrets/ with a decrypt on the secrets prefix', { ...kvAt('secrets/', [GET]), ...DECRYPT_PREFIX },
      ['Decrypt data locked with your keys in secrets/ Sensitive', 'Read secret values Sensitive']],
  ];
  test.each(OTHER)('%s keeps its own rows', (_label, att, expected) => {
    const { target, cleanup } = mounted(modelOf(att));
    expect(rows(target)).toEqual(expected);
    expect(face(target)).not.toContain('Read all your secret values');
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });
});

describe('a secret is named only where the name is the whole story', () => {
  test('a scoped key is not shown as its bare name', () => {
    const { target, cleanup } = mounted(modelOf(keyOf('scoped/evil/bot_history', ['decrypt'])));
    expect(face(target)).not.toContain('Only bot_history');
    expect(cautionOf(target)).toBeNull();
    expect(toggleOf(target)).toBeNull();
    cleanup();
  });

  test('a scoped KV path keeps its own rows', () => {
    const { target, cleanup } = mounted(modelOf(readSecret('scoped/evil/BOT_HISTORY')));
    expect(cautionOf(target)).toBeNull();
    expect(toggleOf(target)).toBeNull();
    cleanup();
  });

  test('a scoped secret beside a named one keeps the rows of the whole request', () => {
    const { target, cleanup } = mounted(modelOf({ ...readSecret('BOT_HISTORY'), ...readSecret('scoped/evil/DEPLOY_KEY') }));
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });

  test('NAME-2 is not NAME: a read of a path that is not a secret name is not named by its prefix', () => {
    const { target, cleanup } = mounted(modelOf(readSecret('NAME-2')));
    expect(rows(target)).toEqual(['Read secret values Sensitive']);
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });

  test('NAME beside NAME-2 does not read as "Only NAME"', () => {
    const { target, cleanup } = mounted(modelOf({ ...readSecret('NAME'), ...readSecret('NAME-2') }));
    expect(face(target)).not.toContain('Only NAME');
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });

  test.each([
    ['a trailing slash', kvAt('vault/secrets/NAME/', [GET])],
    ['a get with a put', kvAt('vault/secrets/NAME', [GET, 'tinycloud.kv/put'])],
    ["another service's path", { [`${SECRETS_SPACE}/sql/vault/secrets/NAME`]: { 'tinycloud.sql/read': [{}] } } as Attenuations],
    ['the default space', kvAt('vault/secrets/NAME', [GET], SECRETS_SPACE.replace(':secrets', ':default'))],
  ] as Array<[string, Attenuations]>)('%s keeps its own rows', (_label, att) => {
    const { target, cleanup } = mounted(modelOf(att));
    expect(face(target)).not.toContain('Read the secret NAME');
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });

  test('exactly one get on the exact path is the one-secret row', () => {
    const { target, cleanup } = mounted(modelOf(kvAt('vault/secrets/NAME', [GET])));
    expect(rows(target)).toEqual(['Read the secret NAME Sensitive']);
    expect(cautionOf(target)).toBe('Only NAME. No other secret.');
    cleanup();
  });
});

describe('a length shown as a line names where it ends', () => {
  const start = Date.UTC(2026, 10, 29, 12, 6);
  test('a day or more ends on a day, a shorter length at a time of day', () => {
    setSystemTime(new Date(start));
    try {
      expect(formatLengthWithEnd(2 * D, start + 2 * D, 'UTC')).toBe('2 days, until Dec 1');
      expect(formatLengthWithEnd(H, start + H, 'UTC')).toBe('1 hour, until 1:06 PM');
      expect(formatLengthWithEnd(7 * D, start + 7 * D, 'UTC')).toBe('7 days, until Dec 6');
      expect(formatLengthWithEnd(30 * D, start + 30 * D, 'UTC')).toBe('30 days, until Dec 29');
      expect(formatLengthWithEnd(60 * D, start + 60 * D, 'UTC')).toBe('60 days, until Jan 28, 2027');
    } finally {
      setSystemTime();
    }
  });
});

describe('the end beside the toggle is the Expiration Time of the message that is signed', () => {
  const endOf = (t: HTMLElement) => text(t.querySelector('[data-testid="approval-expiry-end"]'));
  test('the asked length ends where the signed message ends', () => {
    const m = modelOf(ONE_SECRET);
    const { target, cleanup } = mounted(m);
    expect(endOf(target)).toBe(`until ${formatEndAt(Date.parse(m.expiry!), 7 * D)}`);
    cleanup();
  });

  test('the toggle is described by the caution and by the visible end, and the announcement holds the same end', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET));
    const ids = toggleOf(target)!.getAttribute('aria-describedby')!.split(' ');
    expect(ids.map((id) => text(target.ownerDocument.getElementById(id)))).toEqual([cautionOf(target), endOf(target)]);
    pick(target, 0);
    expect(announcement(target)).toBe(`Access lasts 1 hour, ${endOf(target)}.`);
    cleanup();
  });

  test('a pick made long after the screen opened is named by the new Expiration Time, not by the time the screen opened', () => {
    const opened = Date.now();
    const { target, setModel, cleanup } = mounted(modelOf(ONE_SECRET));
    // 40 minutes pass; the page then signs an hour from this moment and its review model carries that time.
    setSystemTime(new Date(opened + 40 * M));
    try {
      pick(target, 0);
      const signedEnd = opened + 40 * M + H;
      setModel({ ...modelOf(ONE_SECRET), expiry: new Date(signedEnd).toISOString() });
      const hour = formatEndAt(signedEnd, H);
      expect(endOf(target)).toBe(`until ${hour}`);
      expect(announcement(target)).toBe(`Access lasts 1 hour, until ${hour}.`);
      expect(hour).not.toBe(formatEndAt(opened + H, H));
    } finally {
      setSystemTime();
      cleanup();
    }
  });

  test('a length picked under Advanced is the visible line with the signed end', () => {
    const { target, setModel, cleanup } = mounted(modelOf(ONE_SECRET), { expiryMs: 2 * D });
    const signedEnd = Date.now() + 2 * D;
    setModel({ ...modelOf(ONE_SECRET), expiry: new Date(signedEnd).toISOString() });
    expect(toggleOf(target)).toBeNull();
    expect(text(target.querySelector('[data-testid="approval-expiry-length-line"]'))).toBe(`Access lasts 2 days, until ${formatEndAt(signedEnd, 2 * D)}.`);
    cleanup();
  });
});

describe('every secret is one "Read all your secret values" row', () => {
  test('one row, the caution for the whole vault, and the toggle at its one-hour start', () => {
    const { target, calls, cleanup } = mounted(modelOf(ALL_SECRETS));
    expect(calls).toEqual([H]);
    expect(rows(target)).toEqual(['Read all your secret values Sensitive']);
    expect(cautionOf(target)).toBe('Covers every secret in your vault.');
    expect(face(target)).not.toContain('marked Sensitive');
    expect(face(target)).not.toContain("This app's access to your data");
    expect(target.querySelector('[data-testid="approval-expiry-length-line"]')).toBeNull();
    expect(segments(target).map((option) => text(option.closest('label')))).toEqual(['1 hour', '7 days (asked)']);
    expect(segments(target).map((option) => option.checked)).toEqual([true, false]);
    pick(target, 1);
    expect(calls).toEqual([H, 7 * D]);
    cleanup();
  });
});

describe('a secret key named without its value is one row too', () => {
  test('decrypt and key creation on one key read as the one secret, with no key-creation line', () => {
    const { target, cleanup } = mounted(modelOf(keyOf('bot-history', ['decrypt', 'key.create'])));
    expect(rows(target)).toEqual(['Read the secret bot-history Sensitive']);
    expect(cautionOf(target)).toBe('Only bot-history. No other secret.');
    expect(face(target)).not.toContain('Create a key');
    expect(face(target)).not.toContain('marked Sensitive');
    cleanup();
  });

  test('creating a key alone keeps its own row and the sentence that it cannot read secrets', () => {
    const { target, cleanup } = mounted(modelOf(keyOf('bot-history', ['key.create'])));
    expect(rows(target)).toEqual(["Create a key for the new secret bot-history. It can't read any of your secrets."]);
    expect(toggleOf(target)).toBeNull();
    cleanup();
  });
});

describe('the compact block leaves other requests as they are', () => {
  test('a second Sensitive row keeps the header and the full access line', () => {
    const att: Attenuations = { ...ONE_SECRET, [urn('/apps/xyz.tinycloud.listen/')]: { [`${E}decrypt`]: [{}] } };
    const { target, cleanup } = mounted(modelOf(att));
    expect(toggleOf(target)).toBeNull();
    expect(cautionOf(target)).toBeNull();
    cleanup();
  });
});

describe('where the renewal offer is made, the toggle states the length and the box keeps its place below it', () => {
  const renewal = (leaseMs: number | null = null) => ({ leaseMs, maxLeaseMs: 365 * D, onChange() {} });

  test('the box offers renewal in its own words and the lifetime sentence is not on the face', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET), { renewal: renewal() });
    expect(segments(target).map((option) => option.checked)).toEqual([false, true]);
    expect(text(target.querySelector('.renewal-line'))).toBe('Renew automatically for up to 90 days');
    expect(face(target)).not.toContain("This app's access to your data");
    const order = target.querySelector('[data-testid="approval-expiry-toggle"]')!.compareDocumentPosition(target.querySelector('.renewal-box')!);
    expect(order & 4).toBe(4);
    cleanup();
  });

  test('ticked, the box says how long it renews and the toggle names the window', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET), { renewal: renewal(90 * D) });
    expect(text(target.querySelector('.renewal-line'))).toBe('This permission renews automatically for up to 90 days');
    expect(segments(target)).toHaveLength(2);
    cleanup();
  });

  test('while the renewal offer is pending the placeholder takes the box\'s place and there is no box', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET), { renewalPending: true });
    expect(text(target.querySelector('[data-testid="approval-expiry-line"]'))).toBe('Checking renewal…');
    expect(target.querySelector('.renewal-box')).toBeNull();
    expect(segments(target)).toHaveLength(2);
    expect(face(target)).not.toContain("This app's access to your data");
    cleanup();
  });

  test('turning renewal on for it asks first', () => {
    const leases: Array<number | null> = [];
    const { target, cleanup } = mounted(modelOf(ONE_SECRET), { renewal: { leaseMs: null, maxLeaseMs: 365 * D, onChange: (ms: number | null) => { leases.push(ms); } } });
    const box = target.querySelector<HTMLInputElement>('.renewal-box')!;
    box.checked = true;
    box.dispatchEvent(new win.Event('change', { bubbles: true }) as unknown as Event);
    flushSync();
    expect(leases).toEqual([]);
    expect(text(target.querySelector('.renewal-confirm-heading'))).toBe('Renew sensitive access?');
    cleanup();
  });

  test('an hour-long ask with the box offered shows the line "Access lasts 1 hour." above it', () => {
    const { target, cleanup } = mounted(modelOf(ONE_SECRET, H), { renewal: renewal() });
    expect(toggleOf(target)).toBeNull();
    expect(text(target.querySelector('[data-testid="approval-expiry-length-line"]'))).toBe('Access lasts 1 hour.');
    expect(target.querySelector('.renewal-box')).not.toBeNull();
    cleanup();
  });
});

describe('a decrypt that only renewal adds does not leave "Only NAME. No other secret." standing', () => {
  const renewal = (leaseMs: number | null) => ({ leaseMs, maxLeaseMs: 365 * D, onChange() {} });
  const withOther = () => modelOf({ ...ONE_SECRET, ...keyOf('DEPLOY_KEY', ['decrypt']) }, 7 * D, Date.now(), [urn('/secrets/deploy_key')]);
  test.each([null, 90 * D])('a key for another secret that only renewal adds ends the compact face (renewal lease %p)', (lease) => {
    const { target, cleanup } = mounted(withOther(), { renewal: renewal(lease) });
    expect(cautionOf(target)).toBeNull();
    expect(toggleOf(target)).toBeNull();
    expect(face(target)).not.toContain('No other secret');
    expect(rows(target)[1]).toContain('Read the secret deploy_key');
    cleanup();
  });

  test('a key for the same secret that only renewal adds keeps the compact face', () => {
    const m = modelOf(ONE_SECRET, 7 * D, Date.now(), [urn('/secrets/bot_history')]);
    const { target, cleanup } = mounted(m, { renewal: renewal(90 * D) });
    expect(cautionOf(target)).toBe('Only BOT_HISTORY. No other secret.');
    expect(toggleOf(target)).not.toBeNull();
    cleanup();
  });
});
