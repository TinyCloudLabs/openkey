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
import { FIXTURE_META, REAL_RECAP_WITH_PATH } from '../../../../packages/capability-review/test/fixtures/index';

import { UNVERIFIED_REQUESTER } from '@openkey/sdk/approval-copy';
import type { VerifiedRequesterEntry } from './delegate-link-policy';
import { requesterRefusalLine } from './requester-refusal-line';
import type { RequesterScopePolicy, RequesterScopeRequest } from './requester-scope-policy';

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
const TEST_HOME = mkdtempSync('/var/tmp/refusal.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'refusal.'));
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


function reviewOf(): CapabilityReviewModel {
  return parseCapabilityReview({
    message: REAL_RECAP_WITH_PATH,
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: '', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none', manifestId: null,
      manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function render(extra: Record<string, unknown>) {
  const model = reviewOf();
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

const text = (node: Element | null | undefined) => node?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const headerLines = (target: HTMLElement) => [...target.querySelectorAll('.header .requester-line')].map((node) => text(node));

// A test table: the real tables are empty. The signer reads single secrets for an hour.
const SIGNER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const policy: RequesterScopePolicy = {
  maxLifetimeSeconds: 3600,
  rules: [
    { kind: 'path', service: 'tinycloud.kv', spaces: ['secrets'], actions: ['tinycloud.kv/get'], pathPrefixes: ['vault/secrets/'], segmentPatterns: ['^[A-Z][A-Z0-9_]*$'] },
  ],
};
const entry: VerifiedRequesterEntry = { did: SIGNER, displayName: 'Example Gateway', returnTo: 'Example Gateway', policy };
const read = { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/OPENAI_API_KEY', actions: ['tinycloud.kv/get'] };
const inside: RequesterScopeRequest = { permissions: [read], grantLifetimeSeconds: 3600 };
const refusedLine = (request: RequesterScopeRequest) => requesterRefusalLine(SIGNER, [], [entry], request, inside);

const REQUESTS: [string, RequesterScopeRequest, string][] = [
  ['lifetime', { ...inside, grantLifetimeSeconds: 3601 }, 'This link asks for longer access than Example Gateway is allowed to ask for.'],
  ['service', { permissions: [{ ...read, service: 'tinycloud.sql', path: 'tables' }], grantLifetimeSeconds: 3600 }, 'This link asks for a service Example Gateway is not allowed to use.'],
  ['action', { permissions: [{ ...read, actions: ['tinycloud.kv/put'] }], grantLifetimeSeconds: 3600 }, 'This link asks to do something Example Gateway is not allowed to do.'],
  ['path', { permissions: [{ ...read, path: 'vault/secrets/lower' }], grantLifetimeSeconds: 3600 }, 'This link asks for data outside what Example Gateway is allowed to reach.'],
  ['space', { permissions: [{ ...read, space: 'default' }], grantLifetimeSeconds: 3600 }, 'This link asks for a space Example Gateway is not allowed to ask for.'],
  ['renewal', { ...inside, renewal: { leaseLifetimeSeconds: 600 } }, 'This link asks to renew access, which Example Gateway is not allowed to ask for.'],
  ['context', { ...inside, context: { note: 'x' } }, 'Example Gateway doesn’t send this kind of request.'],
  ['malformed', { permissions: 'all', grantLifetimeSeconds: 3600 }, 'OpenKey couldn’t read this link’s request.'],
  ['no-permissions', { permissions: [], grantLifetimeSeconds: 3600 }, 'OpenKey couldn’t read this link’s request.'],
];

describe('the approval screen of a listed requester whose request is outside its policy', () => {
  test('shows one line under the unverified line for each reason, and the requester stays Not verified', () => {
    for (const [reason, request, wanted] of REQUESTS) {
      const reasonLine = refusedLine(request);
      expect(reasonLine, reason).toBe(wanted);
      const { target, cleanup } = render({ unverifiedRequester: { name: UNVERIFIED_REQUESTER.name, line: UNVERIFIED_REQUESTER.line, reason: reasonLine } });
      expect(headerLines(target), reason).toEqual(['Requested by Not verified', 'OpenKey can’t confirm who made this link.', wanted]);
      expect(text(target.querySelector('.requester-name')), reason).toBe('Not verified');
      expect(target.querySelectorAll('[data-testid="requester-refusal"]').length, reason).toBe(1);
      expect(target.querySelector('#signing-approval-headline')?.textContent?.trim(), reason).toBe('Authorize capabilities');
      cleanup();
    }
  });

  test('shows no third line for an unverified link with no reason', () => {
    for (const unverifiedRequester of [
      { name: UNVERIFIED_REQUESTER.name, line: UNVERIFIED_REQUESTER.line },
      { name: UNVERIFIED_REQUESTER.name, line: UNVERIFIED_REQUESTER.line, reason: null },
    ]) {
      const { target, cleanup } = render({ unverifiedRequester });
      expect(headerLines(target)).toEqual(['Requested by Not verified', 'OpenKey can’t confirm who made this link.']);
      expect(target.querySelector('[data-testid="requester-refusal"]')).toBeNull();
      cleanup();
    }
  });

  test('shows no reason line when a requester is named', () => {
    const { target, cleanup } = render({ signInApp: 'Example Gateway', unverifiedRequester: null });
    expect(target.querySelector('[data-testid="requester-refusal"]')).toBeNull();
    cleanup();
  });
});

describe('the "Access goes to" line', () => {
  const KEY = 'did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU';

  test('shows the label and the short key under the requester lines, with the whole key inside', () => {
    const { target, cleanup } = render({ recipientKey: KEY, unverifiedRequester: { name: UNVERIFIED_REQUESTER.name, line: UNVERIFIED_REQUESTER.line } });
    const details = target.querySelector('.header details.recipient-key') as HTMLDetailsElement | null;
    expect(details).not.toBeNull();
    expect(text(details!.querySelector('summary'))).toBe('Access goes to m7pWmP…5YbU');
    expect(text(details!.querySelector('[data-testid="recipient-key-full"]'))).toBe(KEY);
    expect(details!.open).toBe(false);
    // After the requester lines and before the hint.
    const order = [...target.querySelectorAll('.header > *')].map((node) => ['recipient-key', 'requester-line', 'hint'].find((name) => node.classList.contains(name)) ?? node.tagName.toLowerCase());
    expect(order.indexOf('recipient-key')).toBeGreaterThan(order.lastIndexOf('requester-line'));
    expect(order.indexOf('recipient-key')).toBeLessThan(order.indexOf('hint'));
    cleanup();
  });

  test('is left out when the request has no recipient key', () => {
    for (const recipientKey of [null, undefined, '']) {
      const { target, cleanup } = render({ recipientKey });
      expect(target.querySelector('.recipient-key')).toBeNull();
      expect(target.textContent).not.toContain('Access goes to');
      cleanup();
    }
  });
});
