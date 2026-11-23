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
import {
  FIXTURE_META,
  REAL_RECAP_WITH_PATH,
  makeRecapResource,
  siweWithResources,
} from '../../../../packages/capability-review/test/fixtures/index';

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
const TEST_HOME = mkdtempSync('/var/tmp/tc2272.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc2272.'));
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

function model(): CapabilityReviewModel {
  const att = { [urn('/apps/xyz.tinycloud.listen/')]: { [`${E}key.create`]: [{}], [`${E}decrypt`]: [{}] } };
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)]),
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

function render(props: Record<string, unknown> = {}) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const m = model();
  const selection = new Set<string>(
    m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)),
  );
  const app = mount(Approval, {
    target,
    props: { model: m, selection, editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {}, ...props },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

// TC-2933: the line has no "(Change)" button; the window is picked under the closed "How long it lasts" fold.
const line = (t: HTMLElement) => t.querySelector('[data-testid="approval-expiry-line"]')?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const presets = (t: HTMLElement) => [...t.querySelectorAll<HTMLButtonElement>('.choice-preset')];
const preset = (t: HTMLElement, label: string) => presets(t).find((b) => b.textContent?.trim() === label)!;
const error = (t: HTMLElement) => t.querySelector('#approval-expiry-error')?.textContent ?? null;

function type(t: HTMLElement, value: string) {
  const input = t.querySelector<HTMLInputElement>('#approval-expiry-custom')!;
  input.value = value;
  input.dispatchEvent(new win.Event('input', { bubbles: true }) as unknown as Event);
  flushSync();
}
function submit(t: HTMLElement) {
  t.querySelector('.choice-custom')!.dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }) as unknown as Event);
  flushSync();
}
function open(t: HTMLElement) {
  t.querySelector<HTMLDetailsElement>('.expiry-fold')!.open = true;
  flushSync();
}

// The line's wording is Monica's; these check what it says about time (the duration), not the sentence.
describe('the expiry line', () => {
  test('shows what the app asked for', () => {
    const { target, cleanup } = render({ onExpiryChange() {} });
    expect(line(target)).toContain('7 days');
    cleanup();
  });

  test('is not shown on a surface that cannot write the choice into the signed message', () => {
    const { target, cleanup } = render();
    expect(target.querySelector('.expiry')).toBeNull();
    cleanup();
  });

  test('shows the chosen time instead of the requested one', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, expiryMs: 5600 * S });
    expect(line(target)).toContain('5600 seconds');
    expect(line(target)).not.toContain('7 days');
    cleanup();
  });

  test('a preset reports its time', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms) });
    open(target);
    expect(presets(target)).toHaveLength(4);
    preset(target, '30 days').click();
    flushSync();
    expect(chosen).toEqual([30 * D]);
    cleanup();
  });

  test('choosing what the app asked for reports no change', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms), expiryMs: H });
    open(target);
    preset(target, '7 days').click();
    expect(chosen).toEqual([null]);
    cleanup();
  });

  test('a typed time is reported once set, in any case', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms) });
    open(target);
    type(target, ' 40D ');
    submit(target);
    expect(chosen).toEqual([40 * D]);
    cleanup();
  });

  test.each(['', 'soon', '0d', '-5h', '1.5h'])('typed %p shows a plain error and reports nothing', (value: string) => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms) });
    open(target);
    type(target, value);
    submit(target);
    const alert = target.querySelector('#approval-expiry-error');
    expect(alert?.getAttribute('role')).toBe('alert');
    expect(alert?.textContent?.length).toBeGreaterThan(0);
    expect(chosen).toEqual([]);
    // Typing again clears the error.
    type(target, '1d');
    expect(error(target)).toBeNull();
    cleanup();
  });

  test('a time over a year shows the warning, a year or less does not', () => {
    const warning = (t: HTMLElement) => t.querySelector('.expiry-warning')?.textContent ?? null;
    const long = render({ onExpiryChange() {}, expiryMs: 366 * D });
    expect(warning(long.target)).toBe("That's a long time. OpenKey can't cancel it early once you approve.");
    long.cleanup();
    const edge = render({ onExpiryChange() {}, expiryMs: 365 * D });
    expect(warning(edge.target)).toBeNull();
    edge.cleanup();
  });

  test('is a labelled, keyboard-reachable form under a native fold: buttons, a labelled input, a submit button', () => {
    const { target, cleanup } = render({ onExpiryChange() {} });
    expect(target.querySelector('.expiry-fold > summary')).not.toBeNull();
    open(target);
    const input = target.querySelector<HTMLInputElement>('#approval-expiry-custom')!;
    expect(target.querySelector(`label[for="${input.id}"]`)?.textContent).toBe('Or type a time');
    expect(target.querySelector<HTMLButtonElement>('.choice-set')?.type).toBe('submit');
    for (const button of target.querySelectorAll('.expiry button')) expect((button as HTMLButtonElement).tabIndex).not.toBe(-1);
    cleanup();
  });

  test('the choices are disabled while approving', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, approving: true });
    open(target);
    expect(presets(target).every((b) => b.disabled)).toBe(true);
    expect(target.querySelector<HTMLInputElement>('#approval-expiry-custom')!.disabled).toBe(true);
    cleanup();
  });
});

// A refusal is an alert naming the longest time allowed; its sentence is not pinned here.
const refusal = (t: HTMLElement) => t.querySelector('[role="alert"]');

describe('where the requester signed the longest time it accepts', () => {

  test('the picker offers nothing longer than asked', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, expiryBounded: true });
    open(target);
    expect(presets(target).map((b) => b.textContent?.trim())).not.toContain('30 days');
    expect(presets(target)).toHaveLength(3);
    cleanup();
  });

  test('a typed time past the signed maximum is refused with an alert naming the maximum; the maximum itself is allowed', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms), expiryBounded: true });
    open(target);
    type(target, '8d');
    submit(target);
    expect(refusal(target)?.textContent).toContain('7 days');
    expect(chosen).toEqual([]);
    type(target, '7d');
    submit(target);
    expect(chosen).toEqual([null]);
    cleanup();
  });

  test('a shorter typed time is reported', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms), expiryBounded: true });
    open(target);
    type(target, '5600s');
    submit(target);
    expect(chosen).toEqual([5600 * S]);
    cleanup();
  });

  test('where the user may pick anything, 30 days is offered', () => {
    const { target, cleanup } = render({ onExpiryChange() {} });
    open(target);
    expect(presets(target)).toHaveLength(4);
    cleanup();
  });

  test('after a refused typed value there is one alert, and typing clears it', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, expiryBounded: true });
    open(target);
    type(target, '8d');
    submit(target);
    expect(target.querySelectorAll('[role="alert"]')).toHaveLength(1);
    type(target, '1d');
    expect(error(target)).toBeNull();
    cleanup();
  });
});

describe('where the requester signed a maximum above its suggested default (TC-2274)', () => {
  test('the default is the suggestion and the picker offers up to the signed maximum', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, expiryBounded: true, expiryMaxMs: 365 * D });
    expect(line(target)).toContain('7 days');
    open(target);
    expect(presets(target)).toHaveLength(4);
    cleanup();
  });

  test('a time up to the maximum is reported; one past it is refused', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms), expiryBounded: true, expiryMaxMs: 365 * D });
    open(target);
    type(target, '1y');
    submit(target);
    expect(chosen).toEqual([365 * D]);
    type(target, '366d');
    submit(target);
    expect(refusal(target)?.textContent).toContain('1 year');
    expect(chosen).toEqual([365 * D]);
    cleanup();
  });
});

describe('the link notice', () => {

  test('the link notice shows its own Expires row only where nothing else shows the expiry', async () => {
    const Notice = (await import(await compileSvelte('components/delegate/delegate-link-notice.svelte'))).default;
    const rows = (props: Record<string, unknown>) => {
      const host = document.createElement('div');
      document.body.appendChild(host);
      const app = mount(Notice, { target: host, props: { host: 'https://node.tinycloud.xyz', hostRecognized: true, callback: null, expiresAt: '2030-01-01T00:00:00.000Z', ...props } });
      flushSync();
      const labels = [...host.querySelectorAll('dt')].map((dt) => dt.textContent?.trim());
      unmount(app);
      host.remove();
      return labels;
    };
    expect(rows({})).toContain('Expires');
    expect(rows({ showExpires: true })).toContain('Expires');
    expect(rows({ showExpires: false })).not.toContain('Expires');
    expect(rows({ showExpires: false })).toContain('Node');
  });
});

// TC-3111: a one-time approval (secrets or decrypt) that asks for longer than an hour starts at one hour.
describe('one-time approvals start at one hour (TC-3111)', () => {
  const ASKED = '2026-08-07T00:00:00.000Z';
  const SOON = '2026-07-31T00:30:00.000Z';
  const kvGet = { [FIXTURE_META.ownSpace]: { 'tinycloud.kv/get': [{}] } };
  const decrypt = { [urn('')]: { [`${E}decrypt`]: [{}] } };
  const namedSecret = { [`${FIXTURE_META.ownSpace}/kv/vault/secrets/DEPLOY_KEY`]: { 'tinycloud.kv/get': [{}] } };
  const appKeys = { [urn('/apps/xyz.tinycloud.listen/')]: { [`${E}decrypt`]: [{}] } };

  function modelOf(resources: Array<Record<string, Record<string, unknown[]>>>, expirationTime = ASKED): CapabilityReviewModel {
    return parseCapabilityReview({
      message: siweWithResources(resources.map(makeRecapResource), { expirationTime }),
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

  // A parent that applies each choice at once, as the signing surfaces do.
  function mounted(m: CapabilityReviewModel, props: Record<string, unknown> = {}) {
    const state = new SvelteMap<string, unknown>();
    state.set('expiry', null);
    state.set('selection', allIds(m));
    const calls: Array<number | null> = [];
    const target = document.createElement('div');
    document.body.appendChild(target);
    const app = mount(Approval, {
      target,
      props: {
        model: m,
        get selection() { return state.get('selection') as Set<string>; },
        get expiryMs() { return state.get('expiry') as number | null; },
        editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {},
        get approving() { return state.get('approving') === true; },
        onExpiryChange: (ms: number | null) => { calls.push(ms); if (state.get('failToPrepare') !== true) state.set('expiry', ms); },
        onceExpiryDefault: true,
        ...props,
      },
    });
    flushSync();
    return { target, calls, state, cleanup: () => { unmount(app); target.remove(); } };
  }
  const choice = (t: HTMLElement) => t.querySelector('[data-testid="approval-expiry-once-choice"]');
  const caution = (t: HTMLElement) => t.querySelector('[data-testid="approval-expiry-once-caution"]');
  const radios = (t: HTMLElement) => [...t.querySelectorAll<HTMLInputElement>('[data-testid="approval-expiry-once-choice"] input[type="radio"]')];
  const radioLabels = (t: HTMLElement) => radios(t).map((radio) => radio.closest('label')?.textContent?.replace(/\s+/g, ' ').trim());
  const checkedLabel = (t: HTMLElement) => radioLabels(t)[radios(t).findIndex((radio) => radio.checked)];
  const cautionText = (t: HTMLElement) => caution(t)?.textContent?.replace(/\s+/g, ' ').trim() ?? null;

  test('a secret or decrypt request that asks for 7 days starts at one hour, and the line says so', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]));
    expect(calls).toEqual([H]);
    expect(line(target)).toContain('1 hour');
    expect(choice(target)).not.toBeNull();
    expect(checkedLabel(target)).toBe('1 hour');
    cleanup();
  });

  test('a named secret or one app\'s own keys keep what the app asked for, with no one-hour start', () => {
    for (const narrow of [namedSecret, appKeys]) {
      const { target, calls, cleanup } = mounted(modelOf([narrow]));
      expect(calls).toEqual([]);
      expect(line(target)).toContain('7 days');
      expect(choice(target)).toBeNull();
      expect(caution(target)).toBeNull();
      cleanup();
    }
  });

  test('a request that asks for an hour or less keeps what it asked for', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt], SOON));
    expect(calls).toEqual([]);
    expect(line(target)).toContain('30 minutes');
    expect(choice(target)).toBeNull();
    expect(cautionText(target)).toBe('This access can open all your encrypted data.');
    cleanup();
  });

  test('standing access (ordinary data) is unchanged', () => {
    const { target, calls, cleanup } = mounted(modelOf([kvGet]));
    expect(calls).toEqual([]);
    expect(line(target)).toContain('7 days');
    expect(choice(target)).toBeNull();
    expect(caution(target)).toBeNull();
    cleanup();
  });

  test('a surface that does not opt in is unchanged', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]), { onceExpiryDefault: false });
    expect(calls).toEqual([]);
    expect(line(target)).toContain('7 days');
    cleanup();
  });

  test('the owner can pick another time, and the default never replaces it', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]));
    open(target);
    preset(target, '24 hours').click();
    flushSync();
    expect(calls).toEqual([H, 24 * H]);
    expect(line(target)).toContain('1 day');
    expect(choice(target)).toBeNull();
    expect(cautionText(target)).toBe('This access can open all your encrypted data.');
    cleanup();
  });

  test('the owner can go back to what the app asked for, and the default does not return', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]));
    open(target);
    preset(target, '7 days').click();
    flushSync();
    expect(calls).toEqual([H, 7 * D]);
    expect(line(target)).toContain('7 days');
    expect(checkedLabel(target)).toBe('7 days (what the app asked)');
    cleanup();
  });

  test('narrowing away the secret or decrypt access returns to what the app asked for', () => {
    const m = modelOf([decrypt, kvGet]);
    const { target, calls, state, cleanup } = mounted(m);
    expect(calls).toEqual([H]);
    const kvIds = new Set(m.permissions.filter((grant) => grant.service === 'tinycloud.kv').flatMap((grant) => grant.actions.map((action) => action.id)));
    state.set('selection', kvIds);
    flushSync();
    expect(calls).toEqual([H, null]);
    expect(line(target)).toContain('7 days');
    cleanup();
  });

  test('nothing is sent while the approval is being signed or previewed', () => {
    const approving = mounted(modelOf([decrypt]), { approving: true });
    expect(approving.calls).toEqual([]);
    approving.cleanup();
    const previewing = mounted(modelOf([decrypt]), { previewPending: true });
    expect(previewing.calls).toEqual([]);
    previewing.cleanup();
  });

  const approveButton = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('button.approve');

  test('the choice reads How long, offers 1 hour and what the app asked for, and the caution describes it', () => {
    const { target, cleanup } = mounted(modelOf([decrypt]));
    const group = choice(target)!;
    expect(group.tagName).toBe('FIELDSET');
    expect(group.querySelector('legend')?.textContent).toBe('How long');
    expect(radioLabels(target)).toEqual(['1 hour', '7 days (what the app asked)']);
    expect(new Set(radios(target).map((radio) => radio.name)).size).toBe(1);
    expect(group.getAttribute('aria-describedby')).toBe(caution(target)!.id);
    expect(cautionText(target)).toBe('This access can open all your encrypted data.');
    cleanup();
  });

  test('until the hour is applied the line and its note are not shown and Approve waits', () => {
    const waiting = mounted(modelOf([decrypt]), { previewPending: true });
    expect(waiting.target.querySelector('.expiry')).toBeNull();
    expect(approveButton(waiting.target)?.disabled).toBe(true);
    waiting.cleanup();
    const applied = mounted(modelOf([decrypt]));
    expect(applied.target.querySelector('.expiry')).not.toBeNull();
    expect(approveButton(applied.target)?.disabled).toBe(false);
    applied.cleanup();
  });

  test('a request that is not one-time shows its line at once', () => {
    const { target, cleanup } = mounted(modelOf([kvGet]), { previewPending: true });
    expect(target.querySelector('.expiry')).not.toBeNull();
    cleanup();
  });

  // TC-4156: the choice sends an explicit length, never null (null on a popup or frame is "no pick", which the server
  // starts at one hour). Each click is what the page puts into the preview's expirationTime.
  const ASKED_30_DAYS = '2026-08-30T00:00:00.000Z';
  const ONE_HOUR = '2026-07-31T01:00:00.000Z';

  test('picking what the app asked for sends that length, and picking 1 hour again sends 1 hour, keeping the choice', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]));
    radios(target)[1]!.click();
    flushSync();
    expect(calls).toEqual([H, 7 * D]);
    expect(line(target)).toContain('7 days');
    expect(checkedLabel(target)).toBe('7 days (what the app asked)');
    radios(target)[0]!.click();
    flushSync();
    expect(calls).toEqual([H, 7 * D, H]);
    expect(checkedLabel(target)).toBe('1 hour');
    expect(cautionText(target)).toBe('This access can open all your encrypted data.');
    cleanup();
  });

  test('the longer length is not checked or sent until the owner picks it', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]));
    expect(radios(target).map((radio) => radio.checked)).toEqual([true, false]);
    expect(calls).toEqual([H]);
    cleanup();
  });

  test('on a popup or frame an ask over 7 days reads "7 days (the longest allowed)" and sends 7 days', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt], ASKED_30_DAYS), { oncePickCapped: true });
    expect(radioLabels(target)).toEqual(['1 hour', '7 days (the longest allowed)']);
    radios(target)[1]!.click();
    flushSync();
    expect(calls).toEqual([H, 7 * D]);
    cleanup();
  });

  test('an ask of exactly 7 days on a popup or frame reads as what the app asked', () => {
    const { target, cleanup } = mounted(modelOf([decrypt]), { oncePickCapped: true });
    expect(radioLabels(target)).toEqual(['1 hour', '7 days (what the app asked)']);
    cleanup();
  });

  test('where no cap applies an ask over 7 days is offered as asked, never as the longest allowed', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt], ASKED_30_DAYS));
    expect(radioLabels(target)).toEqual(['1 hour', '30 days (what the app asked)']);
    radios(target)[1]!.click();
    flushSync();
    expect(calls).toEqual([H, 30 * D]);
    cleanup();
  });

  test('an ask of exactly 1 hour shows the caution only and sends nothing', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt], ONE_HOUR));
    expect(choice(target)).toBeNull();
    expect(calls).toEqual([]);
    expect(cautionText(target)).toBe('This access can open all your encrypted data.');
    cleanup();
  });

  test('a fold pick that equals no option hides the choice and keeps the caution; one that equals an option checks it', () => {
    const { target, cleanup } = mounted(modelOf([decrypt]));
    open(target);
    preset(target, '24 hours').click();
    flushSync();
    expect(choice(target)).toBeNull();
    expect(cautionText(target)).toBe('This access can open all your encrypted data.');
    preset(target, '1 hour').click();
    flushSync();
    expect(checkedLabel(target)).toBe('1 hour');
    cleanup();
  });

  test('the radios are disabled while approving', () => {
    const { target, cleanup } = mounted(modelOf([decrypt]), { approving: true });
    expect(radios(target).every((radio) => radio.disabled)).toBe(true);
    cleanup();
  });

  test('ticking renewal hides the choice and keeps the caution', () => {
    const renewal = { leaseMs: 90 * D, maxLeaseMs: 365 * D, onChange() {} };
    const { target, cleanup } = mounted(modelOf([decrypt]), { renewal });
    expect(choice(target)).toBeNull();
    expect(cautionText(target)).toBe('This access can open all your encrypted data.');
    cleanup();
  });

  test('removing the broad access and adding it back starts at 1 hour again, and a pick made after that is kept', () => {
    const m = modelOf([decrypt, kvGet]);
    const { target, calls, state, cleanup } = mounted(m);
    radios(target)[1]!.click();
    flushSync();
    expect(calls).toEqual([H, 7 * D]);
    const kvIds = new Set(m.permissions.filter((grant) => grant.service === 'tinycloud.kv').flatMap((grant) => grant.actions.map((action) => action.id)));
    const everyId = state.get('selection') as Set<string>;
    state.set('selection', kvIds);
    flushSync();
    expect(calls).toEqual([H, 7 * D, null]);
    expect(choice(target)).toBeNull();
    state.set('selection', everyId);
    flushSync();
    expect(calls).toEqual([H, 7 * D, null, H]);
    expect(checkedLabel(target)).toBe('1 hour');
    radios(target)[1]!.click();
    flushSync();
    expect(calls).toEqual([H, 7 * D, null, H, 7 * D]);
    expect(checkedLabel(target)).toBe('7 days (what the app asked)');
    cleanup();
  });

  // A signed approval request (/a/<id>): the start is the ask cut to the 7-day limit, and the label says "the longest
  // allowed" only where the limit cut it.
  const signed = (startMs: number, askedMs: number) => ({
    shortenOnlyExpiry: {
      startMs,
      askedMs,
      limitNote: () => '',
      lengthNote: () => '',
    },
  });

  test('a signed request the limit cut to 7 days reads "7 days (the longest allowed)" and sends 7 days', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]), signed(7 * D, 30 * D));
    expect(radioLabels(target)).toEqual(['1 hour', '7 days (the longest allowed)']);
    radios(target)[1]!.click();
    flushSync();
    expect(calls).toEqual([H, 7 * D]);
    cleanup();
  });

  test('a signed request the limit did not cut reads what the app asked', () => {
    const { target, calls, cleanup } = mounted(modelOf([decrypt]), signed(3 * D, 3 * D));
    expect(radioLabels(target)).toEqual(['1 hour', '3 days (what the app asked)']);
    expect(calls).toEqual([H]);
    cleanup();
  });

  // The signed /a/<id> page disables the choice while it prepares the new length, and on a failed prepare keeps the
  // old length as the one that will be signed.
  test('a pick that could not be prepared leaves the radios on the length that will be signed', () => {
    const { target, calls, state, cleanup } = mounted(modelOf([decrypt]), signed(7 * D, 30 * D));
    state.set('failToPrepare', true);
    radios(target)[1]!.click();
    state.set('approving', true);
    flushSync();
    state.set('approving', false);
    flushSync();
    expect(calls).toEqual([H, 7 * D]);
    expect(line(target)).toContain('1 hour');
    expect(checkedLabel(target)).toBe('1 hour');
    expect(radios(target).map((radio) => radio.checked)).toEqual([true, false]);
    cleanup();
  });
});
