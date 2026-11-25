// Mounts the production approval view: a request that reads the same secret name in two scopes shows one row per
// scope, and the secret count in the grouped row and the Sensitive banner equal the number of secret keys.
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
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';

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
const TEST_HOME = mkdtempSync('/var/tmp/scoped-secrets.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'scoped-secrets.'));
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
const DECRYPT = 'tinycloud.encryption/decrypt';

type Attenuations = Record<string, Record<string, unknown[]>>;
const decrypts = (keys: string[]): Attenuations => Object.fromEntries(keys.map((key) => [urn(key), { [DECRYPT]: [{}] }]));
const scoped = (scope: string, name: string) => `/secrets/scoped/${scope}/${name}`;

function modelOf(att: Attenuations): CapabilityReviewModel {
  const now = Date.now();
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)], {
      issuedAt: new Date(now).toISOString(),
      expirationTime: new Date(now + 3600_000).toISOString(),
    }),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    renewalOnlyResources: [],
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'tinycloud.one', verifiedOrigin: 'https://tinycloud.one', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function mounted(m: CapabilityReviewModel) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const selection = new Set(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));
  const app = mount(Approval, {
    target,
    props: { model: m, selection, editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {} },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const rows = (t: HTMLElement) => [...t.querySelectorAll('.summary-statement')].map(text);

describe('the same secret name in two scopes', () => {
  test('is two rows, each saying its scope, with the name and the scope set as the name is', () => {
    const { target, cleanup } = mounted(modelOf(decrypts([scoped('alpha', 'api_key'), scoped('beta', 'api_key')])));
    expect(rows(target)).toEqual([
      'Read the secret api_key from alpha Sensitive',
      'Read the secret api_key from beta Sensitive',
    ]);
    expect([...target.querySelectorAll('.statement-primary')].map((row) => [...row.querySelectorAll('.secret-name')].map(text))).toEqual([
      ['api_key', 'alpha'],
      ['api_key', 'beta'],
    ]);
    cleanup();
  });

  test('a global secret keeps its row without a scope beside the scoped rows of the same name', () => {
    const { target, cleanup } = mounted(modelOf(decrypts(['/secrets/api_key', scoped('alpha', 'api_key')])));
    expect(rows(target)).toEqual([
      'Read the secret api_key Sensitive',
      'Read the secret api_key from alpha Sensitive',
    ]);
    cleanup();
  });

  test('four or more secrets are one "Read N secrets" row that counts every key and lists SCOPE/NAME or NAME', () => {
    const { target, cleanup } = mounted(modelOf(decrypts([
      '/secrets/solo', scoped('alpha', 'api_key'), scoped('beta', 'api_key'), scoped('alpha', 'token'), scoped('beta', 'token'),
    ])));
    expect(rows(target)).toHaveLength(1);
    expect(text(target.querySelector('.secret-summary .statement-primary'))).toBe('Read 5 secrets');
    expect([...target.querySelectorAll('.secret-statements li')].map(text).sort()).toEqual([
      'alpha/api_key', 'alpha/token', 'beta/api_key', 'beta/token', 'solo',
    ]);
    cleanup();
  });
});

describe('scope in approval copy', () => {
  test('a single scoped secret displays only its name', () => {
    const { target, cleanup } = mounted(modelOf(decrypts([scoped('alpha', 'bot-history')])));
    try {
      expect(rows(target)).toEqual(['Read the secret bot-history Sensitive']);
      expect([...target.querySelectorAll('.statement-primary .secret-name')].map(text)).toEqual(['bot-history']);
    } finally {
      cleanup();
    }
  });

  test('same-name scoped rows display their scopes', () => {
    const { target, cleanup } = mounted(modelOf(decrypts([scoped('alpha', 'bot-history'), scoped('beta', 'bot-history')])));
    try {
      expect(rows(target)).toEqual([
        'Read the secret bot-history from alpha Sensitive',
        'Read the secret bot-history from beta Sensitive',
      ]);
    } finally {
      cleanup();
    }
  });

  test('a 140-secret request displays the count and scoped list labels', () => {
    const keys = Array.from({ length: 139 }, (_, i) => scoped('alpha', `secret_${i}`));
    const { target, cleanup } = mounted(modelOf(decrypts([...keys, scoped('beta', 'secret_0')])));
    try {
      expect(text(target.querySelector('.secret-summary .statement-primary'))).toBe('Read 140 secrets');
      expect([...target.querySelectorAll('.secret-statements li')].map(text).sort()).toEqual([
        ...keys.map((key) => key.slice('/secrets/scoped/'.length)),
        'beta/secret_0',
      ].sort());
    } finally {
      cleanup();
    }
  });
});
