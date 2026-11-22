// A decrypt or key creation on `default/secrets` itself, a prefix under `secrets/`, or a path that only reads as
// one of them once lower-cased and percent-decoded (`Secrets/`, `secrets%2F`), shows the all-secrets card and never the
// one-secret card, on a screen with the warning (a sign-in popup or frame) and on one without (a link, the command
// line). One secret's own key still shows the one-secret card. Mounts the production approval view in happy-dom.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tick } from 'svelte';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import type { CapabilityReviewModel } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { ONE_SECRET } from '../../../../packages/sdk/src/approval-copy/strings';

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
const TEST_HOME = mkdtempSync('/var/tmp/all-secrets-prefix.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'all-secrets-prefix.'));
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
const SECRETS_SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:secrets`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const CREATE = 'tinycloud.encryption/key.create';
const H = 60 * 60 * 1000;
const D = 24 * H;
const SITE = 'listen.tinycloud.xyz';

type Attenuations = Record<string, Record<string, unknown[]>>;
/** The secret's value in the vault, plus the encryption grant under test: what a one-secret request carries. */
const request = (rest: string, abilities: string[] = [DECRYPT]): Attenuations => ({
  [`${SECRETS_SPACE}/kv/vault/secrets/OPENAI_API_KEY`]: { 'tinycloud.kv/get': [{}] },
  [urn(rest)]: Object.fromEntries(abilities.map((ability) => [ability, [{}]])),
});

function modelOf(att: Attenuations, now = Date.now()): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)], {
      issuedAt: new Date(now).toISOString(),
      expirationTime: new Date(now + 7 * D).toISOString(),
    }),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: SITE, verifiedOrigin: `https://${SITE}`, appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}
const allIds = (m: CapabilityReviewModel) =>
  new Set(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));

/** The one-secret words the signed approval request page (`/a/`) passes. */
const ONE_SECRET_WORDS = { headline: `${SITE} wants to use one secret`, hint: ONE_SECRET.hint, decryptNote: ONE_SECRET.decryptNote };

/** A screen without the warning (a link, the command line); `warning` adds the popup or frame warning screen. */
function mounted(m: CapabilityReviewModel, options: { warning?: boolean } = {}) {
  const state = new SvelteMap<string, unknown>();
  state.set('expiry', null);
  const calls: Array<number | null> = [];
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Approval, {
    target,
    props: {
      model: m,
      selection: allIds(m),
      get expiryMs() { return state.get('expiry') as number | null; },
      editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {},
      onExpiryChange: (ms: number | null) => { calls.push(ms); state.set('expiry', ms); },
      onceExpiryDefault: true,
      oneSecret: ONE_SECRET_WORDS,
      elevated: options.warning === true ? { splittable: true, onDecide() {} } : null,
    },
  });
  flushSync();
  return { target, calls, cleanup: () => { unmount(app); target.remove(); } };
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const summaryCard = (t: HTMLElement) => t.querySelector('[data-testid="all-secrets-card"]');
const headline = (t: HTMLElement) => text(t.querySelector('#signing-approval-headline'));
const rows = (t: HTMLElement) => [...t.querySelectorAll('.summary-statement .statement-primary')].map(text);
const warningHeadings = (t: HTMLElement) => [...t.querySelectorAll('.elevated .card h2')].map(text);
async function openWarning(t: HTMLElement) {
  t.querySelector<HTMLButtonElement>('button.approve')!.click();
  flushSync();
  await tick();
  flushSync();
}

/** Every grant OpenKey shows as all secrets: `secrets` itself, a prefix under it, or an unreadable path naming them. */
const ALL_SECRETS_SHAPES: Array<[string, string]> = [
  ['the secrets/ prefix', '/secrets/'],
  ['the secrets key, no trailing slash', '/secrets'],
  ['a scope prefix (secrets/scoped/work/)', '/secrets/scoped/work/'],
  ['every scope (secrets/scoped/)', '/secrets/scoped/'],
  ['Secrets/', '/Secrets/'],
  ['SECRETS/', '/SECRETS/'],
  ['SECRETS/x', '/SECRETS/x'],
  ['Secrets/<name>', '/Secrets/openai_api_key'],
  ['secrets%2F', '/secrets%2F'],
  ['secrets%2f', '/secrets%2f'],
  ['secrets%2F<name>', '/secrets%2Fopenai_api_key'],
  ['secrets%2fx', '/secrets%2fx'],
];

describe('a grant on every secret shows the all-secrets card, never the one-secret card', () => {
  test.each(ALL_SECRETS_SHAPES)('%s, on a screen without the warning', (_name: string, rest: string) => {
    const { target, calls, cleanup } = mounted(modelOf(request(rest)));
    expect(text(summaryCard(target)?.querySelector('h3'))).toBe(`Let ${SITE} read all your secrets?`);
    expect(headline(target)).not.toBe(ONE_SECRET_WORDS.headline);
    expect(rows(target)).not.toContain('Read the secret OPENAI_API_KEY');
    expect(text(target)).not.toContain(ONE_SECRET.decryptNote);
    expect(calls).toEqual([H]);
    cleanup();
  });

  test.each(ALL_SECRETS_SHAPES)('%s, on the warning screen', async (_name: string, rest: string) => {
    const { target, cleanup } = mounted(modelOf(request(rest)), { warning: true });
    expect(summaryCard(target)).toBeNull();
    expect(headline(target)).not.toBe(ONE_SECRET_WORDS.headline);
    await openWarning(target);
    expect(warningHeadings(target)[0]).toContain(`Let ${SITE} read all your secrets?`);
    cleanup();
  });

  test.each(ALL_SECRETS_SHAPES)('%s with key creation reads and adds all secrets', (_name: string, rest: string) => {
    const { target, cleanup } = mounted(modelOf(request(rest, [DECRYPT, CREATE])));
    expect(text(summaryCard(target)?.querySelector('h3'))).toBe(`Let ${SITE} read and add all your secrets?`);
    expect(headline(target)).not.toBe(ONE_SECRET_WORDS.headline);
    cleanup();
  });
});

describe('one secret\'s own key still shows the one-secret card', () => {
  test('on a screen without the warning', () => {
    const { target, calls, cleanup } = mounted(modelOf(request('/secrets/openai_api_key')));
    expect(summaryCard(target)).toBeNull();
    expect(headline(target)).toBe(ONE_SECRET_WORDS.headline);
    expect(rows(target)).toEqual(['Read the secret OPENAI_API_KEY']);
    expect(text(target)).toContain(ONE_SECRET.decryptNote);
    expect(calls).toEqual([]);
    cleanup();
  });

  test('on the warning screen, no card offers all secrets', async () => {
    const { target, cleanup } = mounted(modelOf(request('/secrets/openai_api_key')), { warning: true });
    expect(headline(target)).toBe(ONE_SECRET_WORDS.headline);
    await openWarning(target);
    expect(warningHeadings(target).length).toBeGreaterThan(0);
    for (const heading of warningHeadings(target)) expect(heading).not.toContain('all your secrets');
    cleanup();
  });
});
