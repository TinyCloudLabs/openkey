// Mounts the production approval view: the sensitive-secret block is one row, one caution line and an inline length toggle.
// The toggle drives the length the surface signs.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { formatLengthWithEnd } from './approval-expiry';
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

  test('the toggle starts at the length the app asked for, tagged (asked), and names each end', () => {
    const { target, calls, cleanup } = mounted(modelOf(ONE_SECRET));
    expect(calls).toEqual([]);
    expect(text(toggleOf(target)?.querySelector('legend'))).toBe('How long access lasts');
    const options = segments(target);
    expect(options.map((option) => text(option.closest('label')))).toEqual(['1 hour', '7 days (asked)']);
    expect(options.map((option) => option.checked)).toEqual([false, true]);
    expect(options[0]!.getAttribute('aria-label')).toMatch(/^1 hour, until \d{1,2}:\d{2} [AP]M$/);
    expect(options[1]!.getAttribute('aria-label')).toMatch(new RegExp(`^7 days, until ${END_DAY}, as the app asked$`));
    expect(options.map((option) => option.closest('label')!.getAttribute('title'))).toEqual(options.map((option) => option.getAttribute('aria-label')));
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

  test('a read of a secret with no key request keeps the plain line, not the compact block', () => {
    const { target, cleanup } = mounted(modelOf(readSecret('BOT_HISTORY')));
    expect(toggleOf(target)).toBeNull();
    expect(cautionOf(target)).toBeNull();
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

describe('a length shown as a line names where it ends', () => {
  const start = Date.UTC(2025, 10, 29, 12, 6);
  test('a day or more ends on a day, a shorter length at a time of day', () => {
    expect(formatLengthWithEnd(2 * 24 * 3_600_000, start, 'UTC')).toBe('2 days, until Dec 1');
    expect(formatLengthWithEnd(3_600_000, start, 'UTC')).toBe('1 hour, until 1:06 PM');
    expect(formatLengthWithEnd(7 * 24 * 3_600_000, start, 'UTC')).toBe('7 days, until Dec 6');
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
