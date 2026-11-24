// The hint on the master-key card of the per-permission face, mounted on the production approval
// component in happy-dom. A request that can open all encrypted data is held to one hour; rejecting the master-key
// card leaves the length the app asked for. The card says so when the app asked for longer than an hour and the
// request outside that card is not held to the hour. The end day comes from the same clock as the access line.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, beforeAll, describe, expect, setSystemTime, test } from 'bun:test';
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
const TEST_HOME = mkdtempSync('/var/tmp/durline.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'durline.'));
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

const NOW = '2026-11-24T12:00:00.000Z';
const HOUR = 60 * 60 * 1000;
const iso = (offsetMs: number) => new Date(Date.parse(NOW) + offsetMs).toISOString();
const HINT_7_DAYS = 'If you reject it, the rest of the request is approved for 7 days, until Dec 1. gk.gbafa.com may not work fully.';
const HINT_SHARED = 'If you reject it, the rest of the request is still approved. gk.gbafa.com may not work fully.';

beforeAll(() => setSystemTime(new Date(NOW)));
afterAll(() => setSystemTime());

function modelOf(resources: Array<Record<string, Record<string, unknown[]>>>, askedMs: number): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources(resources.map(makeRecapResource), {
      domain: 'gk.gbafa.com',
      uri: 'https://gk.gbafa.com',
      issuedAt: NOW,
      expirationTime: iso(askedMs),
    }),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'gk.gbafa.com', verifiedOrigin: 'https://gk.gbafa.com', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}
const network = { [urn('')]: { [`${E}decrypt`]: [{}] } };
const sharePrefix = { [urn('/share/')]: { [`${E}decrypt`]: [{}] } };
const secretKeys = ['fireflies_api_key', 'granola_api_key'].map((name) => ({ [urn(`/secrets/${name}`)]: { [`${E}decrypt`]: [{}], [`${E}key.create`]: [{}] } }));
const allSecrets = { [urn('/secrets/')]: { [`${E}decrypt`]: [{}] } };

const allIds = (m: CapabilityReviewModel) =>
  new Set(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));

function mounted(m: CapabilityReviewModel) {
  const state = new SvelteMap<string, unknown>();
  state.set('selection', allIds(m));
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Approval, {
    target,
    props: {
      model: m,
      get selection() { return state.get('selection') as Set<string>; },
      previewPending: false,
      editing: false,
      onApprove() {},
      onCancel() {},
      onSelectionChange(next: Set<string>) { state.set('selection', next); },
      onEditingChange() {},
      elevated: { splittable: true, onDecide() {} },
    },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const cards = (t: HTMLElement) => [...t.querySelectorAll<HTMLElement>('.elevated .card')];
const cardButton = (card: HTMLElement, name: string) => [...card.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name)!;
const approve = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('button.approve')!;
async function click(el: HTMLElement) {
  el.click();
  flushSync();
  await tick();
  flushSync();
}
async function openFace(m: CapabilityReviewModel) {
  const view = mounted(m);
  await click(approve(view.target));
  return view;
}

const note = (card: HTMLElement) => text(card.querySelector('.note'));

describe('The master-key card says how long a rejection leaves the approval', () => {
  test('a 7-day request names 7 days and the computed end day in the master-key hint', async () => {
    const { target, cleanup } = await openFace(modelOf([network, sharePrefix], 7 * 24 * HOUR));
    const [master] = cards(target);
    expect(text(master!.querySelector('h2'))).toContain('Use your master key to decrypt?');
    expect(note(master!)).toBe(HINT_7_DAYS);
    cleanup();
  });

  test('the length and the end day follow what the app asked', async () => {
    const { target, cleanup } = await openFace(modelOf([network, sharePrefix], 30 * 24 * HOUR));
    expect(note(cards(target)[0]!)).toBe(
      'If you reject it, the rest of the request is approved for 30 days, until Dec 24. gk.gbafa.com may not work fully.',
    );
    cleanup();
  });

  test('a request of 1 hour or shorter keeps the shared hint', async () => {
    for (const asked of [HOUR, 30 * 60 * 1000]) {
      const { target, cleanup } = await openFace(modelOf([network, sharePrefix], asked));
      expect(note(cards(target)[0]!)).toBe(HINT_SHARED);
      cleanup();
    }
  });

  test('a request that also unlocks named secret keys names the length for the master-key card only', async () => {
    const { target, cleanup } = await openFace(modelOf([network, ...secretKeys], 7 * 24 * HOUR));
    const found = cards(target);
    expect(found).toHaveLength(3);
    expect(note(found[0]!)).toBe(HINT_7_DAYS);
    expect(text(found[1]!.querySelector('h2'))).toContain('fireflies_api_key');
    expect(note(found[1]!)).toBe(HINT_SHARED);
    expect(note(found[2]!)).toBe(HINT_SHARED);
    cleanup();
  });

  test('a folder card keeps the shared hint', async () => {
    const { target, cleanup } = await openFace(modelOf([network, sharePrefix], 7 * 24 * HOUR));
    const [, folder] = cards(target);
    expect(text(folder!.querySelector('h2'))).toContain('Unlock encrypted items in a folder named share');
    expect(note(folder!)).toBe(HINT_SHARED);
    cleanup();
  });

  test('a request with a folder card and no master-key card keeps the shared hint', async () => {
    const { target, cleanup } = await openFace(modelOf([sharePrefix], 7 * 24 * HOUR));
    expect(note(cards(target)[0]!)).toBe(HINT_SHARED);
    cleanup();
  });

  test('a request that stays at 1 hour without the master-key card keeps the shared hint', async () => {
    const { target, cleanup } = await openFace(modelOf([network, allSecrets], 7 * 24 * HOUR));
    for (const card of cards(target)) expect(note(card)).toBe(HINT_SHARED);
    cleanup();
  });

  test('Reject replaces the hint with the status and Change shows the master-key hint', async () => {
    const { target, cleanup } = await openFace(modelOf([network, sharePrefix], 7 * 24 * HOUR));
    await click(cardButton(cards(target)[0]!, 'Reject this permission'));
    expect(text(cards(target)[0]!.querySelector('.status'))).toContain('You rejected this permission.');
    expect(note(cards(target)[0]!)).toBeNull();
    expect(note(cards(target)[1]!)).toBe(HINT_SHARED);
    await click(cardButton(cards(target)[0]!, 'Change'));
    expect(note(cards(target)[0]!)).toBe(HINT_7_DAYS);
    cleanup();
  });
});
