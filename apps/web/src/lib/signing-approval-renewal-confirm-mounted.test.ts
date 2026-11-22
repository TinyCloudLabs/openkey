// TC-3821: the "Renew sensitive access?" confirm travels with the renewal choice, so the server can tell an owner who
// confirmed from a bare leased choice: only Turn on renewal reports `sensitiveConfirmed`. And a confirmed window is
// counted from the message's own start, which is where the node renews each window from.
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
import { RENEWAL_SENSITIVE_CASES, renewalSensitiveReviewMessage } from '../../../../packages/capability-review/test/fixtures/renewal-sensitive-grants';
import { renewalWindowExpiryAt } from './approval-expiry';
import { renewalStartsTicked } from './renewal-default';

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
const TEST_HOME = mkdtempSync('/var/tmp/tc3821.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME', 'TC_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc3821.'));
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

const D = 24 * 60 * 60 * 1000;
const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;

// A 30-day request; `sensitive` adds decrypt on a secret's key.
function requestMessage(sensitive: boolean): string {
  const att: Record<string, Record<string, unknown[]>> = {
    [`${FIXTURE_META.ownSpace}/kv/courier/`]: { 'tinycloud.kv/get': [{}] },
  };
  if (sensitive) att[`urn:tinycloud:encryption:${OWNER}:default/secrets/openai_api_key`] = { 'tinycloud.encryption/decrypt': [{}] };
  return siweWithResources([makeRecapResource(att)], { expirationTime: '2026-08-30T00:00:00.000Z' });
}

function model(message: string): CapabilityReviewModel {
  return parseCapabilityReview({
    message,
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

function render(message: string | boolean, leaseMs: number | null) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const m = model(typeof message === 'string' ? message : requestMessage(message));
  const selection = new Set<string>(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));
  const confirms: Array<true | undefined> = [];
  const app = mount(Approval, {
    target,
    props: {
      model: m, selection, editing: false, approving: false,
      onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {},
      expiryMs: null, onExpiryChange() {}, expiryBounded: true,
      renewal: { leaseMs, maxLeaseMs: 365 * D, onChange: (_ms: number | null, _windowMs?: number | null, confirmed?: true) => { confirms.push(confirmed); } },
    },
  });
  flushSync();
  return { target, confirms, cleanup: () => { unmount(app); target.remove(); } };
}

const box = (t: HTMLElement) => t.querySelector<HTMLInputElement>('.renewal-box')!;
function toggle(t: HTMLElement) {
  const input = box(t);
  input.checked = !input.checked;
  input.dispatchEvent(new win.Event('change', { bubbles: true }) as unknown as Event);
  flushSync();
}
function clickButton(t: HTMLElement, name: string) {
  [...t.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim() === name)!.click();
  flushSync();
}

describe('the sensitive-access confirm in the renewal choice', () => {
  test('Turn on renewal reports the confirm', () => {
    const { target, confirms, cleanup } = render(true, null);
    toggle(target);
    clickButton(target, 'Turn on renewal');
    expect(confirms).toEqual([true]);
    cleanup();
  });

  test("ordinary data ticks without it, and unticking never carries it", () => {
    const ordinary = render(false, null);
    toggle(ordinary.target);
    expect(ordinary.confirms).toEqual([undefined]);
    ordinary.cleanup();
    const ticked = render(true, 90 * D);
    toggle(ticked.target);
    expect(ticked.confirms).toEqual([undefined]);
    ticked.cleanup();
  });
});

describe('a confirmed window counts from the message start', () => {
  const message = (lines: string) => `openkey.so wants you to sign in with your Ethereum account:\n${FIXTURE_META.address}\n\nURI: did:key:z\nVersion: 1\nChain ID: 1\nNonce: n\n${lines}`;
  test('from Issued At, or Not Before when present, never later than now', () => {
    const now = Date.parse('2026-11-22T12:00:30.000Z');
    expect(renewalWindowExpiryAt(7 * D, message('Issued At: 2026-11-22T12:00:00.000Z'), now)).toBe('2026-11-29T12:00:00.000Z');
    expect(renewalWindowExpiryAt(7 * D, message('Issued At: 2026-11-22T11:00:00.000Z\nNot Before: 2026-11-22T12:00:10.000Z'), now)).toBe('2026-11-29T12:00:10.000Z');
    expect(renewalWindowExpiryAt(7 * D, message('Issued At: 2026-11-22T12:05:00.000Z'), now)).toBe('2026-11-29T12:00:30.000Z');
    expect(renewalWindowExpiryAt(7 * D, 'not a SIWE', now)).toBe('2026-11-29T12:00:30.000Z');
  });
});

// Rows of the shared TC-3821 list the page used to tick through without a confirm, though the API refuses the lease
// without one: each now asks first, and the box starts unticked even on a standing request.
describe('grants the API leases only with the confirm, which the page used to miss', () => {
  const missed = RENEWAL_SENSITIVE_CASES.filter((row) => row.formerDeadEnd);
  test('the shared list names the three', () => {
    expect(missed.map((row) => row.name)).toEqual(['key.create on the secrets/ prefix', 'key.describe on one secret', 'every ability on the whole network']);
  });
  for (const row of missed) {
    test(`${row.name}: ticking asks "Renew sensitive access?", and the box starts unticked`, () => {
      const message = renewalSensitiveReviewMessage(row);
      expect(renewalStartsTicked('standing', model(message).permissions)).toBe(false);
      const { target, confirms, cleanup } = render(message, null);
      expect(box(target).checked).toBe(false);
      toggle(target);
      expect(target.querySelector('#renewal-confirm-heading')?.textContent).toBe('Renew sensitive access?');
      expect(confirms).toEqual([]);
      clickButton(target, 'Turn on renewal');
      expect(confirms).toEqual([true]);
      cleanup();
    });
  }
});
