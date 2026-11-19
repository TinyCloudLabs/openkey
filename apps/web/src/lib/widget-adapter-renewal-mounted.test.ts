// Mounts the production popup and iframe signing adapters with a spy transport (TC-2933): the renewal box shows
// only when the page hands the adapter `transport.renewal`, and toggling it reaches `transport.renewal.onChange`,
// which is what makes the page re-preview with the owner's choice.
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
import type { RenewalChoice, WidgetSigningTransport } from './components/signing/signing-adapter-types';

const win = new Window({ url: 'http://openkey.test/' });
Object.assign(globalThis, {
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
});

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'widget-renewal.'));
afterAll(() => rmSync(OUT_DIR, { recursive: true, force: true }));

const require = createRequire(import.meta.url);
const { mount, unmount, flushSync } = (await import(
  pathToFileURL(join(dirname(require.resolve('svelte/package.json')), 'src/index-client.js')).href
)) as {
  mount: (component: unknown, options: { target: HTMLElement; props: Record<string, unknown> }) => unknown;
  unmount: (app: unknown) => void;
  flushSync: () => void;
};

const compiled = new Map<string, string>();
async function compileSvelte(libRel: string): Promise<string> {
  const cached = compiled.get(libRel);
  if (cached) return cached;
  const result = compile(readFileSync(join(WEB_ROOT, 'src/lib', libRel), 'utf8'), {
    generate: 'client', dev: false, name: 'Subject', filename: `src/lib/${libRel}`,
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
      target = rel.endsWith('.svelte') ? await compileSvelte(rel) : pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
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

const ADAPTERS = [
  ['popup', 'components/signing/popup-signing-adapter.svelte'],
  ['iframe', 'components/signing/iframe-signing-adapter.svelte'],
] as const;
const Adapters: Record<string, unknown> = {};
for (const [name, file] of ADAPTERS) Adapters[name] = (await import(await compileSvelte(file))).default;

const D = 24 * 60 * 60 * 1000;
const SPACE = `${FIXTURE_META.ownSpace}`;

// A 30-day sign-in for ordinary app data.
function model(): CapabilityReviewModel {
  return parseCapabilityReview({
    message: siweWithResources(
      [makeRecapResource({ [`${SPACE}/kv/courier/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] } })],
      { expirationTime: '2026-08-30T00:00:00.000Z' },
    ),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: 'courier.tinycloud.xyz', verifiedOrigin: 'https://courier.tinycloud.xyz', appId: null,
      manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none',
      manifestDigest: null, domainWarning: false, originWarning: false,
    },
    requesterAddress: null,
    requesterVerified: false,
  });
}

function render(adapter: string, renewal: Omit<RenewalChoice, 'onChange'> | null) {
  const target = document.createElement('div');
  document.body.appendChild(target);
  const m = model();
  const selection = new Set<string>(m.permissions.flatMap((grant) => grant.actions.filter((action) => action.selected).map((action) => action.id)));
  const leases: Array<number | null> = [];
  const transport: WidgetSigningTransport = {
    canUseAuthorizeSign: true,
    previewReady: true,
    approveAndSign() {},
    cancel() {},
    onSelectionEdited() {},
    invalidatePreview() {},
    approving: false,
    error: null,
    expiry: { chosenMs: null, onChange() {} },
    ...(renewal ? { renewal: { ...renewal, onChange: (ms: number | null) => { leases.push(ms); } } } : {}),
  };
  const app = mount(Adapters[adapter], { target, props: { model: m, initialSelection: selection, transport } });
  flushSync();
  return { target, leases, cleanup: () => { unmount(app); target.remove(); } };
}

const box = (t: HTMLElement) => t.querySelector<HTMLInputElement>('.renewal-box');
function toggle(t: HTMLElement) {
  const input = box(t)!;
  input.checked = !input.checked;
  input.dispatchEvent(new win.Event('change', { bubbles: true }) as unknown as Event);
  flushSync();
}

for (const [name] of ADAPTERS) {
  describe(`the ${name} adapter`, () => {
    test('shows no renewal box when the page offers none', () => {
      const { target, cleanup } = render(name, null);
      expect(target.querySelector('[data-testid="approval-expiry-line"]')).not.toBeNull();
      expect(box(target)).toBeNull();
      cleanup();
    });

    test('shows the box with the page’s choice when the page offers it', () => {
      const ticked = render(name, { leaseMs: 90 * D, maxLeaseMs: 365 * D });
      expect(box(ticked.target)!.checked).toBe(true);
      ticked.cleanup();
      const unticked = render(name, { leaseMs: null, maxLeaseMs: 365 * D });
      expect(box(unticked.target)!.checked).toBe(false);
      unticked.cleanup();
    });

    test('toggling the box reports the lease to the page', () => {
      const ticked = render(name, { leaseMs: 90 * D, maxLeaseMs: 365 * D });
      toggle(ticked.target);
      expect(ticked.leases).toEqual([null]);
      ticked.cleanup();
      const unticked = render(name, { leaseMs: null, maxLeaseMs: 60 * D });
      toggle(unticked.target);
      expect(unticked.leases).toEqual([60 * D]);
      unticked.cleanup();
    });
  });
}
