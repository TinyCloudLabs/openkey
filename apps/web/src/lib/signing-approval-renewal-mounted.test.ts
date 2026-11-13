// Mounts the production approval view and drives the renewal checkbox (TC-2933): the plain line where
// renewal is not offered, the box and its two labels, the lease under the fold, and the extra step
// before renewing secrets or decrypt (spec D7).
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
});

// HOME and the tool homes point at a temp dir for this file.
const TEST_HOME = mkdtempSync('/var/tmp/tc2933.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME', 'TC_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc2933.'));
afterAll(() => {
  rmSync(OUT_DIR, { recursive: true, force: true });
  rmSync(TEST_HOME, { recursive: true, force: true });
  for (const [name, value] of savedHomes) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

const require = createRequire(import.meta.url);
const { mount, unmount, flushSync } = (await import(
  pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href
)) as {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
};

const compiled = new Map<string, string>();
async function compileSvelte(libRel: string): Promise<string> {
  const cached = compiled.get(libRel);
  if (cached) return cached;
  const result = compile(readFileSync(join(WEB_ROOT, 'src/lib', libRel), 'utf8'), {
    generate: 'client', dev: false, name: 'Subject', filename: `src/lib/${libRel}`,
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
      target = rel.endsWith('.svelte') ? await compileSvelte(rel) : pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
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

const S = 1000;
const D = 24 * 60 * 60 * S;
const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const SPACE = `${FIXTURE_META.ownSpace}`;

// A 30-day request (the Courier window). `sensitive` adds decrypt, which spec D7 treats like a secret.
function model(sensitive: boolean): CapabilityReviewModel {
  const att: Record<string, Record<string, unknown[]>> = {
    [`${SPACE}/kv/courier/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] },
  };
  if (sensitive) att[`urn:tinycloud:encryption:${OWNER}:default/apps/xyz.tinycloud.listen/`] = { 'tinycloud.encryption/decrypt': [{}] };
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)], { expirationTime: '2026-08-30T00:00:00.000Z' }),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'courier.tinycloud.xyz', verifiedOrigin: 'https://courier.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

interface Calls { lease: Array<number | null>; expiry: Array<number | null>; windowWithLease: Array<number | null | undefined> }

function render(options: { sensitive?: boolean; leaseMs?: number | null; maxLeaseMs?: number; renewal?: boolean; approving?: boolean; expiryMs?: number | null } = {}) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const m = model(options.sensitive ?? false);
  const selection = new Set<string>(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));
  const calls: Calls = { lease: [], expiry: [], windowWithLease: [] };
  const renewal = options.renewal === false ? null : {
    leaseMs: options.leaseMs === undefined ? 90 * D : options.leaseMs,
    maxLeaseMs: options.maxLeaseMs ?? 365 * D,
    onChange: (ms: number | null, windowMs?: number | null) => { calls.lease.push(ms); calls.windowWithLease.push(windowMs); },
  };
  const app = mount(Approval, {
    target,
    props: {
      model: m, selection, editing: false, approving: options.approving ?? false,
      onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {},
      expiryMs: options.expiryMs ?? null,
      onExpiryChange: (ms: number | null) => { calls.expiry.push(ms); },
      expiryBounded: true,
      renewal,
    },
  });
  flushSync();
  return { target, calls, cleanup: () => { unmount(app); target.remove(); } };
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const line = (t: HTMLElement) => text(t.querySelector('[data-testid="approval-expiry-line"]'));
const box = (t: HTMLElement) => t.querySelector<HTMLInputElement>('.renewal-box');
const buttonNamed = (t: HTMLElement, name: string) =>
  [...t.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name);
function click(el: HTMLElement | undefined | null) {
  el!.click();
  flushSync();
}
function toggle(t: HTMLElement) {
  const input = box(t)!;
  input.checked = !input.checked;
  input.dispatchEvent(new win.Event('change', { bubbles: true }) as unknown as Event);
  flushSync();
}
function openFold(t: HTMLElement) {
  t.querySelector<HTMLDetailsElement>('.expiry-fold')!.open = true;
  flushSync();
}
function typeLease(t: HTMLElement, value: string) {
  const input = t.querySelector<HTMLInputElement>('#approval-lease-custom')!;
  input.value = value;
  input.dispatchEvent(new win.Event('input', { bubbles: true }) as unknown as Event);
  input.form!.dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }) as unknown as Event);
  flushSync();
}

describe('where the requester cannot use renewal', () => {
  test('there is no box, only how long it lasts', () => {
    const { target, cleanup } = render({ renewal: false });
    expect(box(target)).toBeNull();
    expect(line(target)).toBe('This permission expires in 30 days');
    expect(text(target.querySelector('.expiry-fold > summary'))).toBe('How long it lasts');
    expect(target.querySelector('#approval-lease-custom')).toBeNull();
    cleanup();
  });
});

describe('the renewal box', () => {
  test('ticked, it says how long renewal can go on', () => {
    const { target, cleanup } = render();
    expect(box(target)!.checked).toBe(true);
    expect(line(target)).toBe('This permission renews automatically for up to 90 days');
    cleanup();
  });

  test('unticked, it says when the permission expires', () => {
    const { target, cleanup } = render({ leaseMs: null });
    expect(box(target)!.checked).toBe(false);
    expect(line(target)).toBe('This permission expires in 30 days');
    cleanup();
  });

  test('unticking reports no lease; ticking reports the 90-day default, or less when the requester asked for less', () => {
    const ticked = render();
    toggle(ticked.target);
    expect(ticked.calls.lease).toEqual([null]);
    ticked.cleanup();

    const unticked = render({ leaseMs: null });
    toggle(unticked.target);
    expect(unticked.calls.lease).toEqual([90 * D]);
    unticked.cleanup();

    const short = render({ leaseMs: null, maxLeaseMs: 60 * D });
    toggle(short.target);
    expect(short.calls.lease).toEqual([60 * D]);
    short.cleanup();
  });

  test('a lease no longer than the window never renews, so the line says it expires (spec D6 rule 4)', () => {
    const { target, cleanup } = render({ leaseMs: 30 * D });
    expect(line(target)).toBe('This permission expires in 30 days');
    cleanup();
  });

  test('the lease is picked under the fold and cannot pass what the requester signed', () => {
    const { target, calls, cleanup } = render({ maxLeaseMs: 182 * D });
    openFold(target);
    const presets = [...target.querySelectorAll('fieldset')].at(-1)!.querySelectorAll('.choice-preset');
    expect([...presets].map(text)).toEqual(['90 days', '6 months']);
    click(buttonNamed(target, '6 months'));
    expect(calls.lease).toEqual([182 * D]);
    typeLease(target, '1y');
    expect(text(target.querySelector('#approval-lease-error'))).toBe('Renewal can last up to 6 months. Choose that or less.');
    expect(calls.lease).toEqual([182 * D]);
    typeLease(target, '120d');
    expect(calls.lease).toEqual([182 * D, 120 * D]);
    cleanup();
  });

  test('the box is locked while approving', () => {
    const { target, cleanup } = render({ approving: true });
    expect(box(target)!.disabled).toBe(true);
    cleanup();
  });
});

describe('renewing secrets or decrypt asks first (spec D7)', () => {
  test('ticking shows the warning and leaves the box unticked', () => {
    const { target, calls, cleanup } = render({ sensitive: true, leaseMs: null });
    toggle(target);
    expect(calls.lease).toEqual([]);
    expect(text(target.querySelector('.renewal-confirm-heading'))).toBe('Renew sensitive access?');
    expect(text(target.querySelector('#renewal-confirm-body'))).toBe(
      'This lets courier.tinycloud.xyz keep the Sensitive access listed here for up to 90 days, without asking you again.',
    );
    expect(box(target)).toBeNull();
    cleanup();
  });

  test("Don't renew goes back to the unticked box and reports nothing", () => {
    const { target, calls, cleanup } = render({ sensitive: true, leaseMs: null });
    toggle(target);
    click(buttonNamed(target, "Don't renew"));
    expect(box(target)!.checked).toBe(false);
    expect(calls).toEqual({ lease: [], expiry: [], windowWithLease: [] });
    cleanup();
  });

  test('Turn on renewal reports the lease and the 7-day window (spec D6 rule 3)', () => {
    const { target, calls, cleanup } = render({ sensitive: true, leaseMs: null });
    toggle(target);
    click(buttonNamed(target, 'Turn on renewal'));
    // One change carries both, so the preview is prepared once with the lease and the 7-day window.
    expect(calls).toEqual({ lease: [90 * D], expiry: [], windowWithLease: [7 * D] });
    cleanup();
  });

  test('ordinary data turns renewal on without the warning', () => {
    const { target, calls, cleanup } = render({ leaseMs: null });
    toggle(target);
    expect(target.querySelector('.renewal-confirm')).toBeNull();
    expect(calls.lease).toEqual([90 * D]);
    cleanup();
  });
});
