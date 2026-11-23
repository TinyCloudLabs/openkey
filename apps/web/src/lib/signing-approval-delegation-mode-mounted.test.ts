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
import { FIXTURE_META, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';

const win = new Window({ url: 'http://openkey.test/' });
Object.assign(globalThis, {
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
});

const TEST_HOME = mkdtempSync('/var/tmp/tc3810-consent.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'tc3810-consent.'));
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

const SPACE = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;
const ATT = { [`${SPACE}/kv/notes/`]: { 'tinycloud.kv/get': [{}] } };

function messageWithMode(mode?: 'terminal' | 'attenuable'): string {
  const payload: Record<string, unknown> = { att: ATT, prf: [] };
  if (mode !== undefined) payload['xyz.tinycloud.policy/delegationMode'] = mode;
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return siweWithResources([`urn:recap:${b64}`]);
}

function modelFor(
  mode: 'terminal' | 'attenuable' | undefined,
  opts: { origin?: string | null; displayName?: string } = {},
): CapabilityReviewModel {
  const verifiedOrigin = opts.origin === undefined ? 'https://outside.example.com' : opts.origin;
  const displayName = opts.displayName ?? (verifiedOrigin ? new URL(verifiedOrigin).host : '');
  return parseCapabilityReview({
    message: messageWithMode(mode),
    signer: { label: 'Key', address: FIXTURE_META.address, chainId: FIXTURE_META.chainId, provenance: 'managed' },
    editable: true,
    metadataTrust: { status: 'unsigned', reason: 'no manifest' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName,
      verifiedOrigin,
      appId: null,
      manifestName: null,
      manifestNameProvenance: 'none',
      manifestId: null,
      manifestIdProvenance: 'none',
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
}

function render(model: CapabilityReviewModel) {
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

describe('SigningApproval attenuable delegation consent line (TC-3810)', () => {
  test('shows the verbatim consent line before Advanced details and Approve when an outside app declares attenuable', () => {
    const { target, cleanup } = render(modelFor('attenuable', { origin: 'https://outside.example.com' }));
    try {
      const note = target.querySelector('[data-testid="attenuable-delegation-note"]');
      expect(note?.textContent?.trim()).toBe(
        'outside.example.com can share this access with other apps or agents it works with.',
      );
      // Shown in top-level summary, NOT hidden inside Advanced details.
      expect(note?.closest('details')).toBeNull();
    } finally {
      cleanup();
    }
  });

  test('has no origin exemption: first-party TinyCloud origins also show the line when declared attenuable', () => {
    for (const origin of ['https://tinychat.xyz', 'https://one.tinycloud.xyz', 'https://secrets.tinycloud.xyz']) {
      const { target, cleanup } = render(modelFor('attenuable', { origin }));
      try {
        const host = new URL(origin).host;
        const note = target.querySelector('[data-testid="attenuable-delegation-note"]');
        expect(note?.textContent?.trim()).toBe(
          `${host} can share this access with other apps or agents it works with.`,
        );
      } finally {
        cleanup();
      }
    }
  });

  test('falls back to "This app" when no origin or display name is present', () => {
    const { target, cleanup } = render(modelFor('attenuable', { origin: null, displayName: '' }));
    try {
      const note = target.querySelector('[data-testid="attenuable-delegation-note"]');
      expect(note?.textContent?.trim()).toBe(
        'This app can share this access with other apps or agents it works with.',
      );
    } finally {
      cleanup();
    }
  });

  test('does NOT show the line for terminal or undeclared requests', () => {
    for (const mode of ['terminal', undefined] as const) {
      const { target, cleanup } = render(modelFor(mode, { origin: 'https://outside.example.com' }));
      try {
        expect(target.querySelector('[data-testid="attenuable-delegation-note"]')).toBeNull();
      } finally {
        cleanup();
      }
    }
  });
});
