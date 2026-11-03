// TC-2459: the review card can offer Decline (approval-request review only). The dismiss control is found by its
// stable test id, never by its text, and is a text link above the Decline/Approve pair when Decline is offered.
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
const TEST_HOME = mkdtempSync('/var/tmp/tc2459.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc2459.'));
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
const E = 'tinycloud.encryption/';
const S = 1000;
const M = 60 * S;
const H = 60 * M;
const D = 24 * H;

function model(): CapabilityReviewModel {
  const att = { [urn('/apps/xyz.tinycloud.listen/')]: { [`${E}key.create`]: [{}], [`${E}decrypt`]: [{}] } };
  return parseCapabilityReview({
    message: siweWithResources([makeRecapResource(att)]),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'listen.tinycloud.xyz', verifiedOrigin: 'https://listen.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function render(props: Record<string, unknown> = {}) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const m = model();
  const selection = new Set<string>(
    m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)),
  );
  const app = mount(Approval, {
    target,
    props: { model: m, selection, editing: false, onApprove() {}, onCancel() {}, onSelectionChange() {}, onEditingChange() {}, ...props },
  });
  flushSync();
  return { target, cleanup: () => { unmount(app); target.remove(); } };
}

const dismiss = (t: HTMLElement) => t.querySelector<HTMLElement>('[data-testid="signing-dismiss"]');
const decline = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('[data-testid="signing-decline"]');
const row = (t: HTMLElement) => t.querySelector<HTMLElement>('footer.actions')!;
const approveButton = (t: HTMLElement) => row(t).querySelector<HTMLButtonElement>('button.approve')!;

describe('the dismiss control, found by its test id', () => {
  test('is present on every surface, calls the cancel wiring once, and never reports a decline', () => {
    const calls: string[] = [];
    const { target, cleanup } = render({ onCancel: () => calls.push('cancel'), onDecline: undefined });
    expect(dismiss(target)).not.toBeNull();
    dismiss(target)!.click();
    flushSync();
    expect(calls).toEqual(['cancel']);
    cleanup();
  });

  test('without a decline handler there is no Decline, and the dismiss button stays in the action row', () => {
    const { target, cleanup } = render();
    expect(decline(target)).toBeNull();
    expect(row(target).contains(dismiss(target))).toBe(true);
    expect(dismiss(target)!.tagName).toBe('BUTTON');
    cleanup();
  });
});

describe('Decline on the review card', () => {
  test('Decline sits left of Approve in the action row, and the dismiss control is a text link above the pair', () => {
    const { target, cleanup } = render({ onDecline() {} });
    const buttons = [...row(target).querySelectorAll('button')];
    expect(buttons).toHaveLength(2);
    expect(buttons[0]).toBe(decline(target));
    expect(buttons[1]).toBe(approveButton(target));
    expect(row(target).contains(dismiss(target))).toBe(false);
    expect(dismiss(target)!.tagName).toBe('BUTTON');
    expect(dismiss(target)!.classList.contains('dismiss-link')).toBe(true);
    // Above the pair: it comes before the action row in the document.
    expect(dismiss(target)!.compareDocumentPosition(row(target)) & 4 /* FOLLOWING */).toBeTruthy();
    cleanup();
  });

  test('pressing Decline reports one decline and nothing else', () => {
    const calls: string[] = [];
    const { target, cleanup } = render({ onDecline: () => calls.push('decline'), onCancel: () => calls.push('cancel'), onApprove: () => calls.push('approve') });
    decline(target)!.click();
    flushSync();
    expect(calls).toEqual(['decline']);
    cleanup();
  });

  test('pressing the dismiss link goes back and is not a decline', () => {
    const calls: string[] = [];
    const { target, cleanup } = render({ onDecline: () => calls.push('decline'), onCancel: () => calls.push('cancel') });
    dismiss(target)!.click();
    flushSync();
    expect(calls).toEqual(['cancel']);
    cleanup();
  });

  test('while a decline is being sent, Decline, Approve and the dismiss link are all off, so it cannot go twice', () => {
    const calls: string[] = [];
    const { target, cleanup } = render({ onDecline: () => calls.push('decline'), declining: true });
    expect(decline(target)!.disabled).toBe(true);
    expect(approveButton(target).disabled).toBe(true);
    expect((dismiss(target) as HTMLButtonElement).disabled).toBe(true);
    decline(target)!.click();
    flushSync();
    expect(calls).toEqual([]);
    cleanup();
  });

  test('Decline stays available when Approve is blocked, so an owner can still refuse what they cannot approve', () => {
    const { target, cleanup } = render({ onDecline() {}, approveBlockedReason: 'Wallet mismatch' });
    expect(approveButton(target).disabled).toBe(true);
    expect(decline(target)!.disabled).toBe(false);
    cleanup();
  });
});
