// The warning screen for extra permissions (TC-2927), mounted on the production approval component in happy-dom with
// the shared review model. It checks the state machine an owner goes through, not the sentences (Monica's wording is
// pinned in capability-review): the screen opens on Approve only when the selection carries decrypt or key creation on
// the encryption network or outside the app's own keys, neither choice is made for the owner, rejecting narrows the
// request and still approves the rest, allowing sends the decision, and a request that cannot be split is all or nothing.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { tick } from 'svelte';
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

function modelOf(
  resources: Array<Record<string, Record<string, unknown[]>>>,
  verifiedOrigin: string | null = 'https://gk.gbafa.com',
): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources(resources.map(makeRecapResource), { domain: 'gk.gbafa.com', uri: 'https://gk.gbafa.com' }),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'gk.gbafa.com', verifiedOrigin, appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}
const kvGet = { [FIXTURE_META.ownSpace]: { 'tinycloud.kv/get': [{}] } };
const network = { [urn('')]: { [`${E}decrypt`]: [{}], [`${E}network.create`]: [{}] } };
const sharePrefix = { [urn('/share/')]: { [`${E}decrypt`]: [{}] } };
const ownKeys = { [urn('/apps/xyz.tinycloud.listen/')]: { [`${E}decrypt`]: [{}], [`${E}key.create`]: [{}] } };

const allIds = (m: CapabilityReviewModel) =>
  new Set(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));
const isElevatedId = (id: string) => /encryption\/(decrypt|key\.create)$/.test(id) && !id.includes('/apps/');

function mounted(m: CapabilityReviewModel, options: { splittable?: boolean; withTransport?: boolean; previewPending?: boolean } = {}) {
  const state = new SvelteMap<string, unknown>();
  state.set('selection', allIds(m));
  state.set('previewPending', options.previewPending ?? false);
  const events = { approved: 0, cancelled: 0, decided: [] as string[][], selections: [] as string[][] };
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Approval, {
    target,
    props: {
      model: m,
      get selection() { return state.get('selection') as Set<string>; },
      get previewPending() { return state.get('previewPending') as boolean; },
      editing: false,
      onApprove() { events.approved += 1; },
      onCancel() { events.cancelled += 1; },
      onSelectionChange(next: Set<string>) { events.selections.push([...next]); state.set('selection', next); },
      onEditingChange() {},
      elevated: options.withTransport === false ? null : {
        splittable: options.splittable ?? true,
        onDecide(allowed: string[]) { events.decided.push([...allowed]); },
      },
    },
  });
  flushSync();
  return { target, events, state, cleanup: () => { unmount(app); target.remove(); } };
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const screen = (t: HTMLElement) => t.querySelector('.elevated');
const cards = (t: HTMLElement) => [...t.querySelectorAll<HTMLElement>('.elevated .card')];
const cardButton = (card: HTMLElement, name: string) => [...card.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name)!;
const approve = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('button.approve')!;
const continueButton = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('.elevated button.continue')!;
async function click(el: HTMLElement) {
  el.click();
  flushSync();
  await tick();
  flushSync();
}

describe('Approve with an extra permission in the request', () => {
  test('opens the warning screen first and does not approve', async () => {
    const { target, events, cleanup } = mounted(modelOf([network]));
    await click(approve(target));
    expect(screen(target)).not.toBeNull();
    expect(events.approved).toBe(0);
    expect(text(target.querySelector('.elevated h1'))).toBe('gk.gbafa.com is asking for more access');
    cleanup();
  });

  test('one card per permission, marked Sensitive, with Reject first and neither chosen', async () => {
    const { target, cleanup } = mounted(modelOf([network, sharePrefix]));
    await click(approve(target));
    const found = cards(target);
    expect(found).toHaveLength(2);
    expect(text(found[0]!.querySelector('h2'))).toContain('Use your master key to decrypt?');
    expect(text(found[0])).toContain("gk.gbafa.com is asking to use your master key, which opens all your encrypted data. Allow this only for an app you trust.");
    expect(text(found[0]!.querySelector('h2'))).toContain('Sensitive');
    expect(text(found[1]!.querySelector('h2'))).toContain('Unlock encrypted items in a folder named share');
    for (const card of found) {
      const labels = [...card.querySelectorAll('button')].map((b) => text(b));
      expect(labels).toEqual(['Reject this permission', 'Allow this permission']);
    }
    expect(target.querySelectorAll('.elevated .status')).toHaveLength(0);
    cleanup();
  });

  test('the whole-network card is a master-key question, with the site in the body or the cue when no site is verified', async () => {
    const asked = "is asking to use your master key, which opens all your encrypted data. Allow this only for an app you trust.";
    const verified = mounted(modelOf([network]));
    await click(approve(verified.target));
    expect(text(cards(verified.target)[0])).toContain(`gk.gbafa.com ${asked}`);
    expect(text(cards(verified.target)[0])).not.toContain("OpenKey can't confirm");
    verified.cleanup();
    const unverified = mounted(modelOf([network], null));
    await click(approve(unverified.target));
    expect(text(cards(unverified.target)[0]!.querySelector('h2'))).toContain('Use your master key to decrypt?');
    expect(text(cards(unverified.target)[0])).toContain(`This app ${asked} OpenKey can't confirm the site.`);
    unverified.cleanup();
  });

  test('Continue stays disabled until every card has a choice, and a hint says why', async () => {
    const { target, cleanup } = mounted(modelOf([network, sharePrefix]));
    await click(approve(target));
    expect(continueButton(target).disabled).toBe(true);
    expect(continueButton(target).getAttribute('aria-describedby')).toBe('elevated-continue-hint');
    expect(text(target.querySelector('#elevated-continue-hint'))).toBe('Decide on each permission to continue.');
    await click(cardButton(cards(target)[0]!, 'Allow this permission'));
    expect(continueButton(target).disabled).toBe(true);
    await click(cardButton(cards(target)[1]!, 'Reject this permission'));
    expect(continueButton(target).disabled).toBe(false);
    expect(target.querySelector('#elevated-continue-hint')).toBeNull();
    cleanup();
  });

  test('a decided card shows a status line and Change brings the pair back', async () => {
    const { target, cleanup } = mounted(modelOf([network]));
    await click(approve(target));
    await click(cardButton(cards(target)[0]!, 'Reject this permission'));
    expect(text(cards(target)[0]!.querySelector('.status'))).toContain('You rejected this permission.');
    await click(cardButton(cards(target)[0]!, 'Change'));
    expect(cards(target)[0]!.querySelector('.reject')).not.toBeNull();
    expect(cards(target)[0]!.querySelector('.status')).toBeNull();
    cleanup();
  });

  test('allowing everything sends the decision with every extra action id and keeps the whole selection', async () => {
    const m = modelOf([network, sharePrefix, kvGet]);
    const { target, events, cleanup } = mounted(m);
    await click(approve(target));
    for (const card of cards(target)) await click(cardButton(card, 'Allow this permission'));
    await click(continueButton(target));
    expect(events.selections).toEqual([]);
    expect(events.decided).toHaveLength(1);
    expect(events.decided[0]!.length).toBeGreaterThan(0);
    expect(events.decided[0]!.every(isElevatedId)).toBe(true);
    expect(events.decided[0]!.filter((id) => id.includes('/share/'))).toHaveLength(1);
    expect(screen(target)).toBeNull();
    cleanup();
  });

  test('rejecting removes only those actions, tells the server nothing was allowed for them, and the rest is approved', async () => {
    const m = modelOf([network, sharePrefix, kvGet]);
    const { target, events, cleanup } = mounted(m);
    await click(approve(target));
    const [first, second] = cards(target);
    await click(cardButton(first!, 'Reject this permission'));
    await click(cardButton(second!, 'Allow this permission'));
    await click(continueButton(target));
    expect(events.selections).toHaveLength(1);
    const kept = events.selections[0]!;
    expect(kept.some((id) => id.includes('network.create'))).toBe(true);
    expect(kept.some((id) => id.includes('tinycloud.kv'))).toBe(true);
    expect(kept.filter(isElevatedId).every((id) => id.includes('/share/'))).toBe(true);
    expect(events.decided[0]!.every((id) => id.includes('/share/'))).toBe(true);
    // The tap on Approve continues on its own once the next preview is ready: here nothing is pending.
    await tick();
    expect(events.approved).toBe(1);
    cleanup();
  });

  test('after a rejection the review says which permission was not approved', async () => {
    const { target, cleanup } = mounted(modelOf([network, kvGet]));
    await click(approve(target));
    await click(cardButton(cards(target)[0]!, 'Reject this permission'));
    await click(continueButton(target));
    const rows = [...target.querySelectorAll('[data-testid="elevated-not-approved"] li')].map((li) => text(li));
    expect(rows).toEqual(['Not approved: Use your master key to decrypt']);
    expect(text(target.querySelector('.not-approved + [role="status"]'))).toBe('1 permission not approved.');
    cleanup();
  });

  test('waits for the next preview before approving, and does not approve while it is pending', async () => {
    const { target, events, state, cleanup } = mounted(modelOf([network]));
    await click(approve(target));
    await click(cardButton(cards(target)[0]!, 'Allow this permission'));
    state.set('previewPending', true);
    await click(continueButton(target));
    expect(events.approved).toBe(0);
    state.set('previewPending', false);
    flushSync();
    await tick();
    flushSync();
    expect(events.approved).toBe(1);
    cleanup();
  });

  test('is asked again when a rejected permission is added back, and not again for one already allowed', async () => {
    const m = modelOf([network, sharePrefix]);
    const { target, events, state, cleanup } = mounted(m);
    await click(approve(target));
    await click(cardButton(cards(target)[0]!, 'Reject this permission'));
    await click(cardButton(cards(target)[1]!, 'Allow this permission'));
    await click(continueButton(target));
    expect(events.approved).toBe(1);
    // Approve again with the same selection: everything left was already allowed, so no screen.
    await click(approve(target));
    expect(screen(target)).toBeNull();
    expect(events.approved).toBe(2);
    // The owner adds the rejected permission back in Advanced details: it needs its own decision.
    state.set('selection', allIds(m));
    flushSync();
    await click(approve(target));
    expect(cards(target)).toHaveLength(1);
    expect(text(cards(target)[0]!.querySelector('h2'))).toContain('Use your master key to decrypt?');
    expect(events.approved).toBe(2);
    cleanup();
  });
});

describe('no screen where none applies', () => {
  const NO_SCREEN: Array<[string, Array<Record<string, Record<string, unknown[]>>>]> = [
    ['ordinary data', [kvGet]],
    ['the app\'s own keys', [ownKeys]],
    ['network.create alone', [{ [urn('')]: { [`${E}network.create`]: [{}] } }]],
  ];
  test.each(NO_SCREEN)('%s approves at once', async (_name: string, resources: Array<Record<string, Record<string, unknown[]>>>) => {
    const { target, events, cleanup } = mounted(modelOf(resources));
    await click(approve(target));
    expect(screen(target)).toBeNull();
    expect(events.approved).toBe(1);
    expect(events.decided).toEqual([]);
    cleanup();
  });

  test('a surface that does not carry the decision (the command-line page) approves at once', async () => {
    const { target, events, cleanup } = mounted(modelOf([network]), { withTransport: false });
    await click(approve(target));
    expect(screen(target)).toBeNull();
    expect(events.approved).toBe(1);
    cleanup();
  });

  test('a permission the owner unticked in Advanced details is not asked about', async () => {
    const m = modelOf([network, sharePrefix, kvGet]);
    const { target, state, cleanup } = mounted(m);
    const withoutShare = new Set([...allIds(m)].filter((id) => !id.includes('/share/')));
    state.set('selection', withoutShare);
    flushSync();
    await click(approve(target));
    expect(cards(target)).toHaveLength(1);
    cleanup();
  });
});

describe('a request that cannot be split (exact bytes)', () => {
  test('offers only the whole request, in Monica\'s words, and cancel does not approve', async () => {
    const { target, events, cleanup } = mounted(modelOf([network]), { splittable: false });
    await click(approve(target));
    expect(text(target.querySelector('.elevated .sub'))).toBe('gk.gbafa.com sent this as one request, so you can approve all of it or none of it.');
    const labels = [...target.querySelectorAll('.elevated .finish button')].map((b) => text(b));
    expect(labels).toEqual(['Cancel the whole request', 'Allow and approve']);
    expect(target.querySelector('.elevated .pair')).toBeNull();
    await click(cardlessButton(target, 'Cancel the whole request'));
    expect(events.cancelled).toBe(1);
    expect(events.approved).toBe(0);
    cleanup();
  });

  test('Allow and approve sends the decision and approves the whole request', async () => {
    const { target, events, cleanup } = mounted(modelOf([network]), { splittable: false });
    await click(approve(target));
    await click(cardlessButton(target, 'Allow and approve'));
    expect(events.decided).toHaveLength(1);
    expect(events.selections).toEqual([]);
    await tick();
    expect(events.approved).toBe(1);
    cleanup();
  });
});

function cardlessButton(t: HTMLElement, name: string): HTMLElement {
  return [...t.querySelectorAll<HTMLButtonElement>('.elevated button')].find((b) => text(b) === name)!;
}

describe('accessibility', () => {
  test('the screen is a labelled dialog whose title takes focus, and no alert is used', async () => {
    const { target, cleanup } = mounted(modelOf([network]));
    await click(approve(target));
    const dialog = target.querySelector('.elevated')!;
    expect(dialog.getAttribute('role')).toBe('dialog');
    expect(dialog.getAttribute('aria-labelledby')).toBe('elevated-title');
    expect(target.querySelector('.elevated [role="alert"]')).toBeNull();
    expect(target.querySelector('#elevated-title')?.getAttribute('tabindex')).toBe('-1');
    cleanup();
  });

  test('each card is a group named by its heading, and a polite region announces each decision', async () => {
    const { target, cleanup } = mounted(modelOf([network, sharePrefix]));
    await click(approve(target));
    for (const card of cards(target)) {
      expect(card.getAttribute('role')).toBe('group');
      const id = card.getAttribute('aria-labelledby')!;
      expect(card.querySelector(`#${id}`)).not.toBeNull();
    }
    await click(cardButton(cards(target)[0]!, 'Reject this permission'));
    const region = target.querySelector('.elevated [role="status"]')!;
    expect(region.getAttribute('aria-live')).toBe('polite');
    expect(text(region)).toBe('Rejected: Use your master key to decrypt. 1 left to decide.');
    cleanup();
  });
});
