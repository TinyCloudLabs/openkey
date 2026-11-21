// Mounted check of the approval view for a request that only reads the account's app list and space list: the main
// row, the Advanced details line, and the "Manage your TinyCloud account" row for anything that can change
// the account. Mounts the real signing-approval.svelte in happy-dom, as signing-approval-app-keys-mounted does.

// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { ACCOUNT_LISTS_READ_ONLY_DETAILS, parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import type { CapabilityReviewModel } from '../../../../packages/capability-review/src/index';
import {
  FIXTURE_META,
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
const TEST_HOME = mkdtempSync('/var/tmp/tc3711.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc3711.'));
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

const ACCOUNT_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:account`;
const APPS = `${ACCOUNT_SPACE}/kv/applications/`;
const SPACES = `${ACCOUNT_SPACE}/kv/spaces/`;

function reviewOf(message: string): CapabilityReviewModel {
  return parseCapabilityReview({
    message,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'example.com',
      verifiedOrigin: 'https://example.com',
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

function render(abilities: Record<string, string[]>) {
  const att = Object.fromEntries(
    Object.entries(abilities).map(([resource, list]) => [resource, Object.fromEntries(list.map((ability) => [ability, [{}]]))]),
  );
  const model = reviewOf(siweWithResources([makeRecapResource(att)]));
  const target = document.createElement('div');
  document.body.appendChild(target);
  const selection = new Set<string>(
    model.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)),
  );
  const app = mount(Approval, {
    target,
    props: { model, selection, editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {} },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

const statementTexts = (target: HTMLElement) =>
  [...target.querySelectorAll('.summary-statement .statement-primary')].map((node) => node.textContent?.trim());
const note = (target: HTMLElement) => target.querySelector('details.advanced-details [data-testid="account-lists-read-only-note"]');

describe('approval view for read-only account lists', () => {
  test('reading both lists shows the main row and the Advanced details line', () => {
    const { target, cleanup } = render({
      [APPS]: ['tinycloud.kv/get', 'tinycloud.kv/list'],
      [SPACES]: ['tinycloud.kv/get', 'tinycloud.kv/list'],
    });
    try {
      expect(statementTexts(target)).toEqual(['See your apps and spaces']);
      expect(note(target)?.textContent?.trim()).toBe(
        "Read-only account lists: Reads the list of apps you've installed and the list of your spaces. Nothing can be changed.",
      );
      expect(note(target)?.textContent?.trim()).toBe(ACCOUNT_LISTS_READ_ONLY_DETAILS);
    } finally {
      cleanup();
    }
  });

  test('a write verb on the lists keeps the manage row and shows no line', () => {
    const { target, cleanup } = render({ [APPS]: ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/put'] });
    try {
      expect(statementTexts(target)).toEqual(['Manage your TinyCloud account']);
      expect(note(target)).toBeNull();
    } finally {
      cleanup();
    }
  });

  test('read-only lists beside account SQL keep the manage row and show no line', () => {
    const { target, cleanup } = render({
      [APPS]: ['tinycloud.kv/get', 'tinycloud.kv/list'],
      [`${ACCOUNT_SPACE}/sql/account`]: ['tinycloud.sql/read'],
    });
    try {
      expect(statementTexts(target)).toEqual(['Manage your TinyCloud account']);
      expect(note(target)).toBeNull();
    } finally {
      cleanup();
    }
  });
});
