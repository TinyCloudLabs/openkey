// Mounted check of the approval view for app keys: the summary rows, the key
// path in monospace, the standing-access line, `key.delete` listed without a
// checkbox, and an ordinary request unchanged. Compiles and mounts the real
// signing-approval.svelte in happy-dom, the way signing-approval-parity-mounted
// does for the adapters.

// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { formatAccessEnd } from './access-end';
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

function appKeyModel(abilities: Record<string, string[]>) {
  const att = Object.fromEntries(
    Object.entries(abilities).map(([resource, list]) => [resource, Object.fromEntries(list.map((ability) => [ability, [{}]]))]),
  );
  return reviewOf(siweWithResources([makeRecapResource(att)]));
}

const E = 'tinycloud.encryption/';
const statementTexts = (target: HTMLElement) =>
  [...target.querySelectorAll('.summary-statement .statement-primary')].map((node) => node.textContent?.trim());

describe('approval view for app keys', () => {
  test('lists one row per ability in words tied to the app, with no path', () => {
    const model = appKeyModel({ [urn('/apps/xyz.tinycloud.listen/')]: [`${E}key.create`, `${E}decrypt`] });
    const { target, cleanup } = render(model);
    expect(statementTexts(target)).toEqual([
      'Create new encryption keys tied to this app',
      "Decrypt data locked with this app's keys",
    ]);
    expect(target.querySelectorAll('.summary-statement code.mono')).toHaveLength(0);
    expect(target.querySelector('.summary')!.textContent).not.toContain('apps/xyz.tinycloud.listen');
    cleanup();
  });

  test('names an exact key by its last segment in monospace', () => {
    const model = appKeyModel({ [urn('/apps/xyz.tinycloud.listen/api-token')]: [`${E}key.create`, `${E}decrypt`] });
    const { target, cleanup } = render(model);
    expect(statementTexts(target)).toEqual([
      'Create the encryption key api-token for this app',
      "Decrypt data locked with this app's key api-token",
    ]);
    const code = [...target.querySelectorAll('.summary-statement code.mono')].map((node) => node.textContent);
    expect(code).toEqual(['api-token', 'api-token']);
    cleanup();
  });

  test.each([
    ['a prefix', `/apps/xyz.tinycloud.listen/`, 'apps/xyz.tinycloud.listen/'],
    ['an exact key', `/apps/xyz.tinycloud.listen/api-token`, 'apps/xyz.tinycloud.listen/api-token'],
  ])('keeps the raw path of %s in Advanced details, expanded, though the rows no longer show it', (_name: string, rest: string, path: string) => {
    const model = appKeyModel({ [urn(rest)]: [`${E}key.create`, `${E}decrypt`] });
    const { target, cleanup } = render(model);
    expect(target.querySelector('.summary')!.textContent).not.toContain(path);
    const advanced = target.querySelector('details.advanced-details') as HTMLDetailsElement;
    advanced.open = true;
    flushSync();
    expect(advanced.open).toBe(true);
    const targets = [...advanced.querySelectorAll('.grant-target')];
    expect(targets.map((node) => node.textContent?.trim())).toContain(`default/${path}`);
    expect(targets.map((node) => node.getAttribute('title'))).toContain(urn(`/${path}`));
    cleanup();
  });

  test('states the signed expiry beneath decrypt rows only', () => {
    const decrypt = render(appKeyModel({ [urn('/apps/x/k')]: [`${E}decrypt`] }));
    expect(decrypt.target.querySelector('.summary-note')?.textContent).toBe(
      `This access lasts until ${formatAccessEnd(FIXTURE_META.expirationTime)}.`,
    );
    decrypt.cleanup();
    const createOnly = render(appKeyModel({ [urn('/apps/x/k')]: [`${E}key.create`] }));
    expect(createOnly.target.querySelector('.summary-note')).toBeNull();
    createOnly.cleanup();
  });

  test('lists key.delete as a row that cannot be granted, with no checkbox', () => {
    const model = appKeyModel({ [urn('/apps/x/k')]: [`${E}key.create`, `${E}key.delete`] });
    const { target, cleanup } = render(model, true);
    expect(statementTexts(target)).toEqual([
      'Create the encryption key k for this app',
      "Delete this app's key k. Apps can't be given this permission.",
    ]);
    const boxes = [...target.querySelectorAll('input[type="checkbox"]')];
    expect(boxes).toHaveLength(1);
    const labels = [...target.querySelectorAll('.action .verb')].map((node) => node.textContent);
    expect(labels).toContain('key.create');
    expect(labels).toContain('key.delete');
    const deleteRow = [...target.querySelectorAll('.action')].find((node) => node.textContent?.includes('key.delete'))!;
    expect(deleteRow.querySelector('input')).toBeNull();
    cleanup();
  });

  test('shows the App keys heading and the Sensitive pill for decrypt', () => {
    const { target, cleanup } = render(appKeyModel({ [urn('/apps/x/k')]: [`${E}decrypt`] }));
    expect(target.querySelector('.grant-title')?.textContent).toBe('App keys');
    expect(target.querySelector('.summary-sensitive-pill')?.textContent).toBe('Sensitive');
    cleanup();
  });

  test('an ordinary request has no access line, no code spans and no not-granted rows', () => {
    const { target, cleanup } = render(reviewOf(REAL_RECAP_WITH_PATH));
    expect(target.querySelector('.summary-note')).toBeNull();
    expect(target.querySelector('.summary-not-granted')).toBeNull();
    expect(target.querySelectorAll('.summary-statement code').length).toBe(0);
    cleanup();
  });
});
