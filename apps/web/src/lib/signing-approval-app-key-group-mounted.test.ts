// Mounted check of the approval view's selection controls when a request
// carries app keys: the app-key rows are approved together with the rest of
// the request or removed as a unit, and no control reaches a selection that
// keeps an app-key action while dropping another action. Compiles and mounts
// the real signing-approval.svelte in happy-dom.

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
const TEST_HOME = mkdtempSync('/var/tmp/tc1777.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc1777.'));
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
const PREFIX = `urn:tinycloud:encryption:${OWNER}:default/apps/xyz.tinycloud.listen/`;
const E = 'tinycloud.encryption/';

function reviewOf(message: string): CapabilityReviewModel {
  return parseCapabilityReview({
    message,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'listen.tinycloud.xyz',
      verifiedOrigin: 'https://listen.tinycloud.xyz',
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function requestModel(extra: Record<string, string[]> = {}): CapabilityReviewModel {
  const att: Record<string, Record<string, unknown[]>> = {
    [`${FIXTURE_META.ownSpace}/kv/data`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] },
    [PREFIX]: { [`${E}key.create`]: [{}], [`${E}decrypt`]: [{}] },
  };
  for (const [resource, abilities] of Object.entries(extra)) {
    att[resource] = Object.fromEntries(abilities.map((ability) => [ability, [{}]]));
  }
  return reviewOf(siweWithResources([makeRecapResource(att)]));
}

const allActions = (model: CapabilityReviewModel) => model.permissions.flatMap((grant) => grant.actions);

/** Mount in editing mode with this selection and return the selection the next click would send. */
function mountEditing(model: CapabilityReviewModel, selection: Set<string>) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const sent: Set<string>[] = [];
  const app = mount(Approval, {
    target,
    props: {
      model,
      selection,
      editing: true,
      onApprove() {},
      onCancel() {},
      onSelectionChange(next: Set<string>) { sent.push(next); },
      onEditingChange() {},
    },
  });
  flushSync();
  const boxes = [...target.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')];
  return { target, boxes, sent, cleanup: () => { unmount(app); target.remove(); } };
}

describe('selection controls for a request with app keys', () => {
  const model = requestModel();
  const actions = allActions(model);
  const appKeyIds = new Set(actions.filter((action) => action.ability.includes('key.create') || action.ability.endsWith('/decrypt')).map((action) => action.id));
  const everyId = new Set(actions.filter((action) => action.editable).map((action) => action.id));

  test('the fixture has two kv actions and two app-key actions, all editable', () => {
    expect(actions).toHaveLength(4);
    expect(appKeyIds.size).toBe(2);
    expect(everyId.size).toBe(4);
  });

  test('shows one checkbox for the app keys and one for each kv action; no checkbox per app-key ability', () => {
    const { target, boxes, cleanup } = mountEditing(model, new Set(everyId));
    expect(boxes).toHaveLength(3);
    const appKeyGrant = [...target.querySelectorAll('.grant')].find((grant) => grant.textContent?.includes('App keys'))!;
    expect(appKeyGrant.querySelectorAll('input[type="checkbox"]')).toHaveLength(1);
    expect(appKeyGrant.textContent).toContain('key.create');
    expect(appKeyGrant.textContent).toContain('decrypt');
    cleanup();
  });

  test('while the app keys are selected the kv checkboxes are disabled and do nothing', () => {
    const { target, boxes, sent, cleanup } = mountEditing(model, new Set(everyId));
    const kvBoxes = boxes.filter((box) => !(box.closest('.grant')?.textContent?.includes('App keys') ?? false));
    expect(kvBoxes).toHaveLength(2);
    for (const box of kvBoxes) {
      expect(box.disabled).toBe(true);
      box.click();
    }
    expect(sent).toEqual([]);
    expect(target.querySelectorAll('input[type="checkbox"]:not([disabled])')).toHaveLength(1);
    cleanup();
  });

  test('unticking the app keys removes both of their actions and nothing else', () => {
    const { boxes, sent, cleanup } = mountEditing(model, new Set(everyId));
    boxes.find((box) => !box.disabled)!.click();
    expect(sent).toHaveLength(1);
    const kvIds = [...everyId].filter((id) => !appKeyIds.has(id));
    expect([...sent[0]!].sort()).toEqual(kvIds.sort());
    cleanup();
  });

  test('with the app keys removed the kv checkboxes work, and ticking the app keys again selects the whole request', () => {
    const kvIds = [...everyId].filter((id) => !appKeyIds.has(id));
    const removed = mountEditing(model, new Set(kvIds));
    expect(removed.boxes.every((box) => !box.disabled)).toBe(true);
    const kvBox = removed.boxes.find((box) => !(box.closest('.grant')?.textContent?.includes('App keys') ?? false))!;
    kvBox.click();
    expect(removed.sent).toHaveLength(1);
    expect(removed.sent[0]!.size).toBe(kvIds.length - 1);
    removed.cleanup();

    const dropped = mountEditing(model, new Set([kvIds[0]!]));
    const groupBox = dropped.boxes.find((box) => box.closest('.grant')?.textContent?.includes('App keys'))!;
    groupBox.click();
    expect([...dropped.sent[0]!].sort()).toEqual([...everyId].sort());
    dropped.cleanup();
  });

  test('no sequence of clicks reaches a selection that keeps an app-key action and drops another action', () => {
    const key = (selection: Set<string>) => [...selection].sort().join('|');
    const seen = new Map<string, Set<string>>();
    const queue: Set<string>[] = [new Set(everyId)];
    while (queue.length > 0) {
      const selection = queue.shift()!;
      if (seen.has(key(selection))) continue;
      seen.set(key(selection), selection);
      // One fresh mount per control, each starting from `selection`.
      const boxCount = mountEditing(model, selection);
      const total = boxCount.boxes.length;
      boxCount.cleanup();
      for (let index = 0; index < total; index++) {
        const single = mountEditing(model, selection);
        const box = single.boxes[index]!;
        if (!box.disabled) box.click();
        for (const next of single.sent) queue.push(next);
        single.cleanup();
      }
    }
    expect(seen.size).toBeGreaterThanOrEqual(5);
    for (const selection of seen.values()) {
      const keepsAppKey = [...appKeyIds].some((id) => selection.has(id));
      if (keepsAppKey) expect([...everyId].every((id) => selection.has(id))).toBe(true);
    }
  });

  test('the keyboard reaches the same rules: Space on the app-key box toggles the unit, on a locked kv box does nothing', () => {
    const { boxes, sent, cleanup } = mountEditing(model, new Set(everyId));
    const kvBox = boxes.find((box) => !(box.closest('.grant')?.textContent?.includes('App keys') ?? false))!;
    kvBox.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true }));
    expect(sent).toEqual([]);
    const groupBox = boxes.find((box) => !box.disabled)!;
    groupBox.dispatchEvent(new KeyboardEvent('keydown', { key: ' ', bubbles: true }));
    expect(sent).toHaveLength(1);
    expect(sent[0]!.size).toBe(2);
    cleanup();
  });

  test('the edit view says the app keys are one unit, and labels their checkbox "App keys"', () => {
    const { target, boxes, cleanup } = mountEditing(model, new Set(everyId));
    expect(target.querySelector('.app-key-note')?.textContent).toBe(
      'App keys can only be approved together. Untick all of them, or keep them all.',
    );
    const groupBox = boxes.find((box) => !box.disabled)!;
    expect(groupBox.closest('label')?.textContent?.trim()).toBe('App keys');
    cleanup();
  });

  test('the note is not shown outside the edit view', () => {
    const target = document.createElement('div');
    document.body.appendChild(target);
    const app = mount(Approval, {
      target,
      props: { model, selection: new Set(everyId), editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {} },
    });
    flushSync();
    expect(target.querySelector('.app-key-note')).toBeNull();
    unmount(app);
    target.remove();
  });

  test('a request with no app keys keeps one checkbox per action', () => {
    const plain = reviewOf(siweWithResources([makeRecapResource({ [`${FIXTURE_META.ownSpace}/kv/data`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] } })]));
    const { target, boxes, cleanup } = mountEditing(plain, new Set(allActions(plain).map((action) => action.id)));
    expect(target.querySelector('.app-key-note')).toBeNull();
    expect(boxes).toHaveLength(2);
    expect(boxes.every((box) => !box.disabled)).toBe(true);
    expect(plain.permissions.some((grant) => grant.family === 'app-keys')).toBe(false);
    cleanup();
  });

  test('key.delete beside the app keys has no checkbox and is not part of the unit', () => {
    const withDelete = requestModel({ [`urn:tinycloud:encryption:${OWNER}:default/secrets/x`]: [`${E}key.delete`] });
    const ids = allActions(withDelete).filter((action) => action.editable).map((action) => action.id);
    const { boxes, cleanup } = mountEditing(withDelete, new Set(ids));
    expect(boxes).toHaveLength(3);
    cleanup();
  });
});
