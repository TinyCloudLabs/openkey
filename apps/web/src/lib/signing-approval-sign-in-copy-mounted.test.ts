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
import { FIXTURE_META, REAL_RECAP_WITH_PATH, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';

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
const TEST_HOME = mkdtempSync('/var/tmp/tc3921.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc3921.'));
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

type Trust = 'unsigned' | 'origin-bound' | 'verified';
type Requester = {
  displayName?: string;
  verifiedOrigin?: string | null;
  manifestId?: string | null;
  manifestIdProvenance?: 'verified' | 'origin-bound' | 'caller' | 'none';
  trust?: Trust;
  message?: string;
};

function reviewOf(who: Requester = {}): CapabilityReviewModel {
  const trust = who.trust ?? 'origin-bound';
  return parseCapabilityReview({
    message: who.message ?? REAL_RECAP_WITH_PATH,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: trust === 'unsigned' ? { status: 'unsigned', reason: 'no manifest' } : { status: trust, reason: 'matched manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: who.displayName ?? 'Food Tracker',
      verifiedOrigin: who.verifiedOrigin === undefined ? 'https://food.example' : who.verifiedOrigin,
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: who.manifestId ?? null,
      manifestIdProvenance: who.manifestIdProvenance ?? 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function render(model: CapabilityReviewModel, extra: Record<string, unknown> = {}) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const selection = new Set<string>(
    model.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)),
  );
  const app = mount(Approval, {
    target,
    props: { model, selection, editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {}, ...extra },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

const headlineOf = (who: Requester) => {
  const { target, cleanup } = render(reviewOf(who));
  const result = target.querySelector('#signing-approval-headline')?.textContent?.trim() ?? null;
  cleanup();
  return result;
};

/** The tag beside the Manifest ID row, or null when the view has no such row. */
const manifestIdTag = (who: Requester) => {
  const { target, cleanup } = render(reviewOf(who));
  const row = [...target.querySelectorAll('.row')].find((node) => node.querySelector('.label')?.textContent?.trim() === 'Manifest ID');
  const result = row ? { id: row.querySelector('.value')?.textContent?.trim(), tag: row.querySelector('.provenance-tag')?.textContent?.replace(/\s+/g, ' ').trim() } : null;
  cleanup();
  return result;
};

describe('the heading of a sign-in review', () => {
  test('names the app that is shown after "Requested by"', () => {
    const { target, cleanup } = render(reviewOf());
    expect(target.querySelector('#signing-approval-headline')?.textContent?.trim()).toBe('Sign in to Food Tracker');
    expect(target.querySelector('.requester-line')?.textContent?.trim()).toBe('Requested by Food Tracker');
    cleanup();
  });

  test('names the browser authority where the app has no name of its own', () => {
    expect(headlineOf({ displayName: '', verifiedOrigin: 'https://food.example' })).toBe('Sign in to food.example');
  });

  test('keeps the protocol heading where nothing names the requester', () => {
    expect(headlineOf({ displayName: '', verifiedOrigin: null })).toBe('Authorize capabilities');
  });

  test('keeps the protocol heading for a recap that hosts a new space on a node', () => {
    const space = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;
    const hostRecap = makeRecapResource({ [`${space}/space`]: { 'tinycloud.space/host': [{}] } });
    expect(headlineOf({ message: siweWithResources([hostRecap]) })).toBe('Authorize capabilities');
    expect(headlineOf({ message: REAL_RECAP_WITH_PATH })).toBe('Sign in to Food Tracker');
  });

  test('keeps the protocol heading for a requester OpenKey cannot name', () => {
    const { target, cleanup } = render(reviewOf({ displayName: '', verifiedOrigin: null }), {
      unverifiedRequester: { name: 'Not verified', line: 'OpenKey can’t confirm who made this link.' },
    });
    expect(target.querySelector('.requester-line')?.textContent?.trim()).toBe('Requested by Not verified');
    expect(target.querySelector('#signing-approval-headline')?.textContent?.trim()).toBe('Authorize capabilities');
    cleanup();
  });

  test('shows a name with markup as text', () => {
    const { target, cleanup } = render(reviewOf({ displayName: '<img src=x onerror=alert(1)>' }));
    expect(target.querySelector('#signing-approval-headline img')).toBeNull();
    cleanup();
  });
});

describe('the tag on the Manifest ID row', () => {
  const ID = 'xyz.tinycloud.tinyapps.food';

  test('says the id came from the app where the matched manifest names none', () => {
    for (const trust of ['origin-bound', 'verified'] as const) {
      expect(manifestIdTag({ trust, manifestId: ID, manifestIdProvenance: 'caller' })).toEqual({
        id: ID,
        tag: "from the app's request; the manifest doesn't name one",
      });
    }
  });

  test('says caller-supplied, unverified where no manifest matched', () => {
    expect(manifestIdTag({ trust: 'unsigned', manifestId: ID, manifestIdProvenance: 'caller' })).toEqual({
      id: ID,
      tag: 'caller-supplied, unverified',
    });
  });

  test('keeps the tags for an id the manifest names', () => {
    expect(manifestIdTag({ trust: 'verified', manifestId: ID, manifestIdProvenance: 'verified' })?.tag).toBe('signed manifest');
    expect(manifestIdTag({ trust: 'origin-bound', manifestId: ID, manifestIdProvenance: 'origin-bound' })?.tag).toBe('from origin-bound manifest');
  });
});
