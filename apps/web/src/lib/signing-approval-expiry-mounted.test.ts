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

const line = (t: HTMLElement) => t.querySelector('.expiry-line')?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const changeButton = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('.expiry-change')!;
const preset = (t: HTMLElement, label: string) =>
  [...t.querySelectorAll<HTMLButtonElement>('.expiry-preset')].find((b) => b.textContent?.trim() === label)!;

function type(t: HTMLElement, value: string) {
  const input = t.querySelector<HTMLInputElement>('.expiry-input')!;
  input.value = value;
  input.dispatchEvent(new win.Event('input', { bubbles: true }) as unknown as Event);
  flushSync();
}
function submit(t: HTMLElement) {
  t.querySelector('.expiry-custom')!.dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }) as unknown as Event);
  flushSync();
}
function open(t: HTMLElement) {
  changeButton(t).click();
  flushSync();
}

describe('the "Approval expires" line', () => {
  test('shows what the app asked for, in the short form', () => {
    const { target, cleanup } = render({ onExpiryChange() {} });
    expect(line(target)).toBe('Approval expires: 7d (Change)');
    cleanup();
  });

  test('is not shown on a surface that cannot write the choice into the signed message', () => {
    const { target, cleanup } = render();
    expect(target.querySelector('.expiry')).toBeNull();
    cleanup();
  });

  test('shows the chosen time instead of the requested one', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, expiryMs: 5600 * S });
    expect(line(target)).toBe('Approval expires: 5600s (Change)');
    cleanup();
  });

  test('the presets are 1 hr, 24 hr, 7d and 30d, and a preset reports its time', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms) });
    open(target);
    expect([...target.querySelectorAll('.expiry-preset')].map((b) => b.textContent?.trim())).toEqual(['1 hr', '24 hr', '7d', '30d']);
    preset(target, '30d').click();
    flushSync();
    expect(chosen).toEqual([30 * D]);
    expect(target.querySelector('#approval-expiry-panel')).toBeNull();
    cleanup();
  });

  test('choosing what the app asked for reports no change', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms), expiryMs: H });
    open(target);
    preset(target, '7d').click();
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
    const alert = target.querySelector('.expiry-error');
    expect(alert?.getAttribute('role')).toBe('alert');
    expect(alert?.textContent?.length).toBeGreaterThan(0);
    expect(chosen).toEqual([]);
    expect(target.querySelector('#approval-expiry-panel')).not.toBeNull();
    // Typing again clears the error.
    type(target, '1d');
    expect(target.querySelector('.expiry-error')).toBeNull();
    cleanup();
  });

  test('a long time shows the warning, a year or less does not', () => {
    const warning = (t: HTMLElement) => t.querySelector('.expiry-warning')?.textContent ?? null;
    const long = render({ onExpiryChange() {}, expiryMs: 366 * D });
    expect(warning(long.target)).toBe("That's a long time. OpenKey can't cancel it early once you approve.");
    long.cleanup();
    const edge = render({ onExpiryChange() {}, expiryMs: 365 * D });
    expect(warning(edge.target)).toBeNull();
    edge.cleanup();
    const typed = render({ onExpiryChange() {} });
    open(typed.target);
    type(typed.target, '2y');
    expect(warning(typed.target)).not.toBeNull();
    type(typed.target, '30d');
    expect(warning(typed.target)).toBeNull();
    typed.cleanup();
  });

  test('Escape closes the picker and returns focus to Change', () => {
    const { target, cleanup } = render({ onExpiryChange() {} });
    open(target);
    expect(changeButton(target).getAttribute('aria-expanded')).toBe('true');
    target.querySelector('.expiry-input')!.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }) as unknown as Event);
    flushSync();
    expect(target.querySelector('#approval-expiry-panel')).toBeNull();
    expect(changeButton(target).getAttribute('aria-expanded')).toBe('false');
    expect(document.activeElement).toBe(changeButton(target));
    cleanup();
  });

  test('is a labelled, keyboard-reachable form: native buttons, a labelled input, a submit button', () => {
    const { target, cleanup } = render({ onExpiryChange() {} });
    open(target);
    const input = target.querySelector<HTMLInputElement>('.expiry-input')!;
    expect(target.querySelector(`label[for="${input.id}"]`)?.textContent).toBe('Or type a time');
    expect(target.querySelector<HTMLButtonElement>('.expiry-set')?.type).toBe('submit');
    for (const button of target.querySelectorAll('.expiry button')) expect((button as HTMLButtonElement).tabIndex).not.toBe(-1);
    cleanup();
  });

  test('Change is disabled while approving', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, approving: true });
    expect(changeButton(target).disabled).toBe(true);
    cleanup();
  });
});

describe('where the requester signed the longest time it accepts', () => {
  const NOTE = 'This app asked for up to 7d. To allow longer, start the request again with a longer expiry.';

  test('the picker offers nothing longer than asked, with the plain note', () => {
    const { target, cleanup } = render({ onExpiryChange() {}, expiryBounded: true });
    open(target);
    expect([...target.querySelectorAll('.expiry-preset')].map((b) => b.textContent?.trim())).toEqual(['1 hr', '24 hr', '7d']);
    expect(target.querySelector('.expiry-note')?.textContent).toBe(NOTE);
    cleanup();
  });

  test('a typed time past the signed maximum is refused with that note; the maximum itself is allowed', () => {
    const chosen: Array<number | null> = [];
    const { target, cleanup } = render({ onExpiryChange: (ms: number | null) => chosen.push(ms), expiryBounded: true });
    open(target);
    type(target, '8d');
    submit(target);
    expect(target.querySelector('.expiry-error')?.textContent).toBe(NOTE);
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

  test('where the user may pick anything there is no note and 30d is offered', () => {
    const { target, cleanup } = render({ onExpiryChange() {} });
    open(target);
    expect(target.querySelector('.expiry-note')).toBeNull();
    expect(target.querySelectorAll('.expiry-preset').length).toBe(4);
    cleanup();
  });
});
