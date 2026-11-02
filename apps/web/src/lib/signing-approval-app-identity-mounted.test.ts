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
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

type Requester = {
  name?: string | null;
  provenance?: 'verified' | 'origin-bound' | 'caller' | 'none';
  appId?: string | null;
  verifiedOrigin?: string | null;
  displayName?: string;
};

function reviewOf(message: string, who: Requester = {}): CapabilityReviewModel {
  return parseCapabilityReview({
    message,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: who.displayName ?? 'listen.tinycloud.xyz',
      verifiedOrigin: who.verifiedOrigin === undefined ? 'https://listen.tinycloud.xyz' : who.verifiedOrigin,
      appId: who.appId ?? null,
      manifestName: who.name ?? null,
      manifestNameProvenance: who.provenance ?? 'none',
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

function render(model: CapabilityReviewModel, editing = false) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const selection = new Set<string>(
    model.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)),
  );
  const app = mount(Approval, {
    target,
    props: { model, selection, editing, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {} },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

function appKeyModel(abilities: Record<string, string[]>, who: Requester = {}) {
  const att = Object.fromEntries(
    Object.entries(abilities).map(([resource, list]) => [resource, Object.fromEntries(list.map((ability) => [ability, [{}]]))]),
  );
  return reviewOf(siweWithResources([makeRecapResource(att)]), who);
}

const E = 'tinycloud.encryption/';
const statementTexts = (target: HTMLElement) =>
  [...target.querySelectorAll('.summary-statement .statement-primary')].map((node) => node.textContent?.trim());

const APP = 'xyz.tinycloud.listen';
const PREFIX_REQUEST = { [urn(`/apps/${APP}/`)]: [`${E}key.create`, `${E}decrypt`] };
const text = (target: HTMLElement, selector: string) => target.querySelector(selector)?.textContent?.trim() ?? null;

function top(who: Requester, abilities: Record<string, string[]> = PREFIX_REQUEST) {
  const { target, cleanup } = render(appKeyModel(abilities, who));
  const result = {
    headline: text(target, '#signing-approval-headline'),
    headlineMono: target.querySelector('#signing-approval-headline')?.classList.contains('mono') ?? false,
    id: text(target, '.app-id:not(h2)'),
    requestedBy: text(target, '.requester-line'),
    lead: text(target, '.summary-lead'),
  };
  cleanup();
  return result;
}

describe('the top of an approval view for app keys', () => {
  test('a verified name, then the app id in monospace, then the origin, then the line above the rows', () => {
    const result = top({ name: 'Listen', provenance: 'origin-bound', appId: APP });
    expect(result).toEqual({
      headline: 'Listen',
      headlineMono: false,
      id: APP,
      requestedBy: 'Requested by listen.tinycloud.xyz',
      lead: 'Listen is requesting:',
    });
  });

  test('the id is in monospace under the name', () => {
    const { target, cleanup } = render(appKeyModel(PREFIX_REQUEST, { name: 'Listen', provenance: 'verified', appId: APP }));
    expect(target.querySelector('p.app-id')?.classList.contains('mono')).toBe(true);
    cleanup();
  });

  test('no name: the id alone on top and "This app is requesting:"', () => {
    const result = top({ provenance: 'none', appId: APP });
    expect(result).toEqual({
      headline: APP,
      headlineMono: true,
      id: null,
      requestedBy: 'Requested by listen.tinycloud.xyz',
      lead: 'This app is requesting:',
    });
  });

  test('a name the caller supplied is never shown: the id alone', () => {
    const result = top({ name: 'Listen', provenance: 'caller', appId: null });
    expect(result.headline).toBe(APP);
    expect(result.lead).toBe('This app is requesting:');
  });

  test('before the manifest is verified the id comes from the key resources', () => {
    const result = top({ provenance: 'none', appId: null });
    expect(result.headline).toBe(APP);
    expect(result.id).toBeNull();
  });

  const hostileNames: Array<[string, string]> = [
    ['a right-to-left override', 'Listen\u202Egnp.exe'],
    ['a control character', 'Lis\u001Bten'],
    ['a zero-width character', 'Lis\u200Bten'],
    ['Latin mixed with Cyrillic', 'Lіsten'],
  ];
  for (const [label, hostile] of hostileNames) {
    test(`a name with ${label} is left out: the id alone`, () => {
      const result = top({ name: hostile, provenance: 'origin-bound', appId: APP });
      expect(result.headline).toBe(APP);
      expect(result.id).toBeNull();
      expect(result.lead).toBe('This app is requesting:');
    });
  }

  test('a name that is left out is not on the page at all, Advanced details included', () => {
    for (const [, hostile] of hostileNames) {
      const { target, cleanup } = render(appKeyModel(PREFIX_REQUEST, { name: hostile, displayName: hostile, provenance: 'origin-bound', appId: APP }));
      const page = target.textContent ?? '';
      expect(page).not.toContain('Listen');
      for (const character of ['\u202E', '\u001B', '\u200B', 'і']) expect(page).not.toContain(character);
      expect(page).toContain(APP);
      cleanup();
    }
  });

  test('a name that is shown appears in Advanced details as the same text, a long one cut', () => {
    const { target, cleanup } = render(appKeyModel(PREFIX_REQUEST, { name: 'B'.repeat(80), displayName: 'B'.repeat(80), provenance: 'origin-bound', appId: APP }));
    const values = [...target.querySelectorAll('.value')].map((node) => node.textContent?.trim());
    expect(values).toContain(`${'B'.repeat(47)}…`);
    expect(target.textContent).not.toContain('B'.repeat(48));
    cleanup();
  });

  test('a request without app keys also shows a hostile name as the origin instead', () => {
    const hostile = 'Listen\u202Egnp.exe';
    const { target, cleanup } = render(reviewOf(REAL_RECAP_WITH_PATH, { name: hostile, displayName: hostile, provenance: 'origin-bound', appId: APP }));
    expect(target.textContent).not.toContain('\u202E');
    expect(text(target, '.requester-line')).toBe('Requested by listen.tinycloud.xyz');
    cleanup();
  });

  test('a long name is cut to 48 characters with an ellipsis, and the id stays beneath it', () => {
    const result = top({ name: 'A'.repeat(80), provenance: 'origin-bound', appId: APP });
    expect(result.headline).toBe(`${'A'.repeat(47)}…`);
    expect(result.id).toBe(APP);
  });

  test('the name is rendered as text, never as markup', () => {
    const { target, cleanup } = render(appKeyModel(PREFIX_REQUEST, { name: '<img src=x onerror=alert(1)>', provenance: 'origin-bound', appId: APP }));
    expect(target.querySelector('#signing-approval-headline')?.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(target.querySelector('#signing-approval-headline img')).toBeNull();
    cleanup();
  });

  test('a request without app keys keeps its headline and "Requested by"', () => {
    const { target, cleanup } = render(reviewOf(REAL_RECAP_WITH_PATH, { name: 'Listen', provenance: 'origin-bound', appId: APP }));
    expect(target.querySelector('.app-id')).toBeNull();
    expect(target.querySelector('.summary-lead')).toBeNull();
    expect(text(target, '.requester-line')).toBe('Requested by listen.tinycloud.xyz');
    cleanup();
  });
});
