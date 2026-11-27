// The warning screen's card for one exact encryption key (TC-4073), mounted on the production approval component in
// happy-dom: a grant of decrypt and key creation on `share/<id>` reads as one key and says it can't use any other, and
// the same grant on the folder `share/` keeps the folder wording.
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

function modelOf(resources: Array<Record<string, Record<string, unknown[]>>>): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources(resources.map(makeRecapResource), { domain: 'gk.gbafa.com', uri: 'https://gk.gbafa.com' }),
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
const kvGet = { [FIXTURE_META.ownSpace]: { 'tinycloud.kv/get': [{}] } };

const allIds = (m: CapabilityReviewModel) =>
  new Set(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));

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

const both = (resource: string) => ({ [urn(resource)]: { [`${E}decrypt`]: [{}], [`${E}key.create`]: [{}] } });

describe('The warning screen for an exact encryption key', () => {
  test('decrypt and key creation on one key read as one key, and say no other key can be used', async () => {
    const { target, cleanup } = mounted(modelOf([both('/share/abc')]));
    await click(approve(target));
    const found = cards(target);
    expect(found).toHaveLength(1);
    expect(text(found[0]!.querySelector('h2'))).toContain('Create and use one encryption key: abc');
    expect(text(found[0]!)).toContain(
      'gk.gbafa.com could create the encryption key named abc and unlock the items encrypted with it, for as long as this approval lasts. This permission covers only that key.',
    );
    expect(text(found[0]!)).not.toContain('folder');
    cleanup();
  });

  test('the same grant on the folder keeps the folder wording and does not claim one key', async () => {
    const { target, cleanup } = mounted(modelOf([both('/share/')]));
    await click(approve(target));
    const found = cards(target);
    expect(found).toHaveLength(1);
    expect(text(found[0]!.querySelector('h2'))).toContain('Unlock and create encrypted items in a folder named share');
    expect(text(found[0]!)).not.toContain('covers only that key');
    cleanup();
  });

  test('a rejected one-key card is listed on the review under its heading', async () => {
    const { target, cleanup } = mounted(modelOf([both('/share/abc'), kvGet]));
    await click(approve(target));
    await click(cardButton(cards(target)[0]!, 'Reject this permission'));
    await click(continueButton(target));
    expect(text(target)).toContain('Not approved: Create and use one encryption key: abc');
    cleanup();
  });
});
