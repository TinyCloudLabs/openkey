// TC-3826: a sign-in message with no `Expiration Time` says so in the Expires
// row instead of showing no row; one with an expiry still shows it; a plain
// message has no Expires row.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, describe, expect, test } from 'bun:test';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { FIXTURE_META, makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

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
const TEST_HOME = mkdtempSync('/var/tmp/tc3826.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc3826.'));
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

const NO_EXPIRY = "Doesn't expire. It doesn't end by itself.";
const EXPIRY = '2036-11-22T00:00:00Z';
const RECAP = makeRecapResource({ [`tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default/kv/data`]: { 'tinycloud.kv/get': [{}] } });

function siwe({ expiry, recap }: { expiry?: string; recap: boolean }): string {
  return [
    'app.example wants you to sign in with your Ethereum account:',
    FIXTURE_META.address,
    '',
    'Sign in to app.example.',
    '',
    'URI: https://app.example',
    'Version: 1',
    `Chain ID: ${FIXTURE_META.chainId}`,
    'Nonce: abcdefgh12345678',
    'Issued At: 2026-11-22T00:00:00Z',
    ...(expiry ? [`Expiration Time: ${expiry}`] : []),
    ...(recap ? ['Resources:', `- ${RECAP}`] : []),
  ].join('\n');
}

function render(text: string) {
  const model = parseCapabilityReview({
    message: text,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'app.example', verifiedOrigin: 'https://app.example', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
  const selection = new Set<string>(model.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));
  const target = document.createElement('div');
  document.body.appendChild(target);
  const app = mount(Approval, {
    target,
    props: { model, selection, editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {} },
  });
  flushSync();
  const expiresRows = [...target.querySelectorAll('section.signer .row')]
    .filter((row) => row.querySelector('.label')?.textContent?.trim() === 'Expires')
    .map((row) => row.querySelector('.value')?.textContent?.trim());
  return { model, expiresRows, cleanup: () => { unmount(app); target.remove(); } };
}

describe('SigningApproval Expires row', () => {
  test.each([['plain', false], ['ReCap', true]] as const)('a %s SIWE with no Expiration Time says it does not expire', (_name: string, recap: boolean) => {
    const view = render(siwe({ recap }));
    try {
      expect(view.model.expiry).toBeNull();
      expect(view.expiresRows).toEqual([NO_EXPIRY]);
    } finally {
      view.cleanup();
    }
  });

  test.each([['plain', false], ['ReCap', true]] as const)('a %s SIWE with an Expiration Time still shows it', (_name: string, recap: boolean) => {
    const view = render(siwe({ expiry: EXPIRY, recap }));
    try {
      expect(view.expiresRows).toEqual([EXPIRY]);
    } finally {
      view.cleanup();
    }
  });

  test('a message that is not a sign-in has no Expires row', () => {
    const view = render('Please sign this receipt: order #4472');
    try {
      expect(view.model.protocol).toBe('legacy-message');
      expect(view.expiresRows).toEqual([]);
    } finally {
      view.cleanup();
    }
  });
});
