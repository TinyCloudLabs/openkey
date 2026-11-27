// The hint on the master-key card of the per-permission face, mounted on the production approval component in
// happy-dom. The hint names the length the approval is signed for after the owner rejects the card, or it does not show.
// Every case that shows it drives Reject and Continue to the Approve the screen sends itself and compares the hint with
// the expiry that Approve signs, worked out the way the server does: the page's pick or the message's Expiration Time,
// held to the cap the server reads from the original request (`secretCapExpirationTime`).
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterAll, beforeAll, describe, expect, setSystemTime, test } from 'bun:test';
import { tick } from 'svelte';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Window } from 'happy-dom';
import { compile } from 'svelte/compiler';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import type { CapabilityReviewModel } from '../../../../packages/capability-review/src/index';
import { formatDurationWithEnd, formatEndDay } from './approval-expiry';
import { masterKeyRejectNote } from '../../../../packages/capability-review/src/index';
import { siweBroadOnceTier } from '../../../api/src/services/approval-expiry';
import { secretCapExpirationTime } from '../../../api/src/services/secret-lifetime';
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
const TEST_HOME = mkdtempSync('/var/tmp/durline.');
const savedHomes = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'TINYCLOUD_HOME']
  .map((name) => [name, process.env[name]] as const);
for (const [name] of savedHomes) process.env[name] = TEST_HOME;
if (process.env.HOME !== TEST_HOME) throw new Error('HOME is not the test home');

const here = dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = join(here, '..', '..');
// Compiled components go under .svelte-kit so their `svelte` imports resolve.
mkdirSync(join(WEB_ROOT, '.svelte-kit'), { recursive: true });
const OUT_DIR = mkdtempSync(join(WEB_ROOT, '.svelte-kit', 'durline.'));
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
// `networkCap` points the page's network-decrypt-cap import at a module with the flag on.
function flagOnModule(): string {
  const out = join(OUT_DIR, 'network_decrypt_cap_on.mjs');
  writeFileSync(out, 'export const NETWORK_DECRYPT_CAP = true;\n');
  return pathToFileURL(out).href;
}
async function compileSvelte(libRel: string, networkCap = false): Promise<string> {
  const cacheKey = `${libRel}|${networkCap}`;
  const cached = compiled.get(cacheKey);
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
        ? await compileSvelte(rel, networkCap)
        : networkCap && rel === 'network-decrypt-cap'
          ? flagOnModule()
          : pathToFileURL(join(WEB_ROOT, 'src/lib', rel)).href;
    } else if (spec.startsWith('.')) {
      target = pathToFileURL(join(dirname(join(WEB_ROOT, 'src/lib', libRel)), spec)).href;
    }
    code += `from '${target}'`;
    cursor = match.index + match[0].length;
  }
  code += result.js.code.slice(cursor);
  const out = join(OUT_DIR, `${libRel.replace(/[^A-Za-z0-9]/g, '_')}${networkCap ? '_cap' : ''}.mjs`);
  writeFileSync(out, code);
  const url = pathToFileURL(out).href;
  compiled.set(cacheKey, url);
  return url;
}

const Approval = (await import(await compileSvelte('components/signing/signing-approval.svelte'))).default;
const ApprovalNetworkCap = (await import(await compileSvelte('components/signing/signing-approval.svelte', true))).default;

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const SITE = 'gk.gbafa.com';

const NOW = Date.parse('2026-11-24T12:00:00.000Z');
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const iso = (at: number) => new Date(at).toISOString();

beforeAll(() => setSystemTime(new Date(NOW)));
afterAll(() => setSystemTime());

const network = { [urn('')]: { [`${E}decrypt`]: [{}] } };
const sharePrefix = { [urn('/share/')]: { [`${E}decrypt`]: [{}] } };
const allSecrets = { [urn('/secrets/')]: { [`${E}decrypt`]: [{}] } };
// An ordinary read the card does not touch: a KV path outside the secrets vault.
const kvGet = { [`${FIXTURE_META.ownSpace}/kv/notes/`]: { 'tinycloud.kv/get': [{}] } };
const kvSecretsVault = { [`${FIXTURE_META.ownSpace.replace(/:default$/, ':secrets')}/kv`]: { 'tinycloud.kv/get': [{}] } };
const secretKey = (name: string) => ({ [urn(`/secrets/${name}`)]: { [`${E}decrypt`]: [{}], [`${E}key.create`]: [{}] } });
const secretKeys = [secretKey('fireflies_api_key'), secretKey('granola_api_key')];

interface Ask {
  askedMs: number;
  /** Issued At as an offset from the frozen clock; the app signs it at its own time. */
  issuedOffsetMs?: number;
}

function request(resources: Array<Record<string, Record<string, unknown[]>>>, ask: Ask) {
  const issuedAt = NOW + (ask.issuedOffsetMs ?? 0);
  const message = siweWithResources(resources.map(makeRecapResource), {
    domain: SITE,
    uri: `https://${SITE}`,
    issuedAt: iso(issuedAt),
    expirationTime: iso(issuedAt + ask.askedMs),
  });
  const model = parseCapabilityReview({
    message,
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
  return { message, model };
}
type Request = ReturnType<typeof request>;


interface Options {
  networkCap?: boolean;
  renewal?: boolean;
  /** Secret-key grants that start unticked: still in the original request the server reads. */
  untickSecrets?: boolean;
}

// The page around the component, as the signing route runs it: the owner's pick lives with the page, a change to the
// selection or the pick makes the preview pending until it is prepared again, and Approve signs the pick or the
// message's own Expiration Time, which the server holds to the cap it reads from the original request.
function mounted({ message, model }: Request, options: Options = {}) {
  const state = new SvelteMap<string, unknown>();
  const selected = new Set(
    model.permissions.flatMap((grant) =>
      grant.actions.filter((action) => action.selected && !(options.untickSecrets && action.id.includes('/secrets/'))).map((action) => action.id)),
  );
  state.set('selection', selected);
  state.set('previewPending', false);
  state.set('expiryMs', null);
  const events = { approved: 0, signedAt: [] as number[] };
  const target = document.createElement('div');
  document.body.appendChild(target);
  function signedExpiry(): number {
    const picked = state.get('expiryMs') as number | null;
    const requested = picked !== null ? NOW + picked : Date.parse(siweExpiration(message));
    const cap = secretCapExpirationTime(message, NOW, siweBroadOnceTier(message, FIXTURE_META.address) && picked !== null);
    return cap !== null && !(requested <= Date.parse(cap)) ? Date.parse(cap) : requested;
  }
  const Component = options.networkCap ? ApprovalNetworkCap : Approval;
  const app = mount(Component, {
    target,
    props: {
      model,
      get selection() { return state.get('selection') as Set<string>; },
      get previewPending() { return state.get('previewPending') as boolean; },
      get expiryMs() { return state.get('expiryMs') as number | null; },
      onExpiryChange(ms: number | null) { state.set('expiryMs', ms); state.set('previewPending', true); },
      onceExpiryDefault: true,
      renewal: options.renewal ? { leaseMs: 90 * DAY, maxLeaseMs: 365 * DAY, onChange() {} } : null,
      editing: false,
      onApprove() { events.approved += 1; events.signedAt.push(signedExpiry()); },
      onCancel() {},
      onSelectionChange(next: Set<string>) { state.set('selection', next); state.set('previewPending', true); },
      onEditingChange() {},
      elevated: { splittable: true, onDecide() { state.set('previewPending', true); } },
    },
  });
  flushSync();
  return { target, events, state, cleanup: () => { unmount(app); target.remove(); } };
}
function siweExpiration(message: string): string {
  return /^Expiration Time: (.+)$/m.exec(message)![1]!;
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim() ?? null;
const cards = (t: HTMLElement) => [...t.querySelectorAll<HTMLElement>('.elevated .card')];
const note = (card: HTMLElement) => text(card.querySelector('.note'));
const cardButton = (card: HTMLElement, name: string) => [...card.querySelectorAll<HTMLButtonElement>('button')].find((b) => text(b) === name)!;
const approve = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('button.approve')!;
const continueButton = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('.elevated button.continue')!;
async function click(el: HTMLElement) {
  el.click();
  await settle();
}
async function settle() {
  for (let i = 0; i < 4; i += 1) {
    flushSync();
    await tick();
  }
}
// The route prepares the preview again after every change; here it is ready once the screen has settled.
async function prepared(view: ReturnType<typeof mounted>) {
  for (let i = 0; i < 6; i += 1) {
    await settle();
    if (view.state.get('previewPending') === true) view.state.set('previewPending', false);
  }
  await settle();
}
async function openFace(request: Request, options: Options = {}) {
  const view = mounted(request, options);
  await prepared(view);
  await click(approve(view.target));
  return view;
}

const HINT_SHARED = `If you reject it, the rest of the request is still approved. ${SITE} may not work fully.`;
const hintFor = (ms: number) => masterKeyRejectNote(SITE, formatDurationWithEnd(ms, NOW));

// Rejects the master-key card, decides every other card as `others`, continues, and returns the expiry Approve signed.
async function signAfterRejecting(view: ReturnType<typeof mounted>, others: 'allow' | 'reject' = 'allow') {
  const [master, ...rest] = cards(view.target);
  await click(cardButton(master!, 'Reject this permission'));
  for (const card of rest) await click(cardButton(cards(view.target).find((c) => c.querySelector('h2')?.textContent === card.querySelector('h2')?.textContent)!, others === 'allow' ? 'Allow this permission' : 'Reject this permission'));
  await click(continueButton(view.target));
  await prepared(view);
  expect(view.events.approved).toBe(1);
  return view.events.signedAt[0]!;
}

describe('The master-key hint matches the length the approval signs', () => {
  test('a 7-day ask with secret keys in the request: the hint is the day Approve signs', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet, ...secretKeys], { askedMs: 7 * DAY }));
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + 7 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    expect(hint).toContain(`7 days, until ${formatEndDay(7 * DAY, NOW)}`);
    view.cleanup();
  });

  test('a 30-day ask held to the 7-day cap by secret keys names 7 days', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet, ...secretKeys], { askedMs: 30 * DAY }));
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + 7 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    expect(hint).toContain('approved for 7 days');
    view.cleanup();
  });

  test('a 30-day ask with no cap names 30 days and the end day', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 30 * DAY }));
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + 30 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    expect(hint).toContain(`30 days, until ${formatEndDay(30 * DAY, NOW)}`);
    view.cleanup();
  });

  test('a 30-day ask with the network cap on names 7 days', async () => {
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    try {
      const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 30 * DAY }), { networkCap: true });
      const hint = note(cards(view.target)[0]!);
      const signed = await signAfterRejecting(view);
      expect(signed).toBe(NOW + 7 * DAY);
      expect(hint).toBe(hintFor(signed - NOW));
      view.cleanup();
    } finally {
      delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
    }
  });

  test('an unticked secrets grant in the original request still holds the ask to 7 days', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet, ...secretKeys], { askedMs: 30 * DAY }), { untickSecrets: true });
    expect(cards(view.target)).toHaveLength(2);
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + 7 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    view.cleanup();
  });

  test('an Issued At in the future counts the ask from now to its Expiration Time', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 30 * DAY, issuedOffsetMs: 365 * DAY }));
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + 395 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    expect(hint).toContain(`395 days, until ${formatEndDay(395 * DAY, NOW)}`);
    view.cleanup();
  });

  test('an Issued At in the past under the cap: the hint is the expiry the screen sends, not the ask minus Issued At', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet, ...secretKeys], { askedMs: 9 * DAY, issuedOffsetMs: -4 * DAY }));
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + 7 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    expect(hint).toContain(`7 days, until ${formatEndDay(7 * DAY, NOW)}`);
    view.cleanup();
  });

  test('an Issued At in the past with no cap: the hint is the time left to the Expiration Time', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 9 * DAY, issuedOffsetMs: -4 * DAY }));
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + 5 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    view.cleanup();
  });

  test('another card rejected as well: the hint still equals the signed expiry', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 7 * DAY }));
    const hint = note(cards(view.target)[0]!);
    const signed = await signAfterRejecting(view, 'reject');
    expect(signed).toBe(NOW + 7 * DAY);
    expect(hint).toBe(hintFor(signed - NOW));
    view.cleanup();
  });

  test('the owner picked a length: the shared hint shows', async () => {
    const view = mounted(request([network, sharePrefix, kvGet], { askedMs: 7 * DAY }));
    await prepared(view);
    const radios = [...view.target.querySelectorAll<HTMLInputElement>('[data-testid="approval-expiry-once-choice"] input[type="radio"]')];
    expect(radios).toHaveLength(2);
    radios[1]!.click();
    await prepared(view);
    expect(view.state.get('expiryMs')).toBe(7 * DAY);
    await click(approve(view.target));
    expect(note(cards(view.target)[0]!)).toBe(HINT_SHARED);
    view.cleanup();
  });

  test('the owner picked 1 hour after another length: the shared hint shows and Approve signs 1 hour', async () => {
    const view = mounted(request([network, sharePrefix, kvGet], { askedMs: 7 * DAY }));
    await prepared(view);
    const radios = () => [...view.target.querySelectorAll<HTMLInputElement>('[data-testid="approval-expiry-once-choice"] input[type="radio"]')];
    radios()[1]!.click();
    await prepared(view);
    radios()[0]!.click();
    await prepared(view);
    expect(view.state.get('expiryMs')).toBe(HOUR);
    await click(approve(view.target));
    expect(note(cards(view.target)[0]!)).toBe(HINT_SHARED);
    expect(await signAfterRejecting(view)).toBe(NOW + HOUR);
    view.cleanup();
  });

  test('renewal ticked: the shared hint shows', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 7 * DAY }), { renewal: true });
    expect(note(cards(view.target)[0]!)).toBe(HINT_SHARED);
    view.cleanup();
  });

  test('only the master key requested: the shared hint shows', async () => {
    const view = await openFace(request([network], { askedMs: 7 * DAY }));
    expect(cards(view.target)).toHaveLength(1);
    expect(note(cards(view.target)[0]!)).toBe(HINT_SHARED);
    view.cleanup();
  });

  test('a request that stays in the one-hour tier without the card shows the shared hint, and signs one hour', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet, kvSecretsVault], { askedMs: 7 * DAY }));
    expect(text(cards(view.target)[0]!.querySelector('h2'))).toContain('Use your master key to decrypt?');
    expect(note(cards(view.target)[0]!)).toBe(HINT_SHARED);
    const signed = await signAfterRejecting(view);
    expect(signed).toBe(NOW + HOUR);
    view.cleanup();
  });

  test('the combined all-secrets card keeps the shared hint', async () => {
    const view = await openFace(request([network, allSecrets, kvGet], { askedMs: 7 * DAY }));
    for (const card of cards(view.target)) expect(note(card)).toBe(HINT_SHARED);
    view.cleanup();
  });

  test('an ask of 1 hour or shorter keeps the shared hint', async () => {
    for (const asked of [HOUR, 30 * 60 * 1000]) {
      const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: asked }));
      expect(note(cards(view.target)[0]!)).toBe(HINT_SHARED);
      view.cleanup();
    }
  });

  test('a folder card keeps the shared hint', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 7 * DAY }));
    const [, folder] = cards(view.target);
    expect(text(folder!.querySelector('h2'))).toContain('Unlock encrypted items in a folder named share');
    expect(note(folder!)).toBe(HINT_SHARED);
    view.cleanup();
  });

  test('Reject replaces the hint with the status and Change shows the master-key hint', async () => {
    const view = await openFace(request([network, sharePrefix, kvGet], { askedMs: 7 * DAY }));
    const before = note(cards(view.target)[0]!);
    await click(cardButton(cards(view.target)[0]!, 'Reject this permission'));
    expect(text(cards(view.target)[0]!.querySelector('.status'))).toContain('You rejected this permission.');
    expect(note(cards(view.target)[0]!)).toBeNull();
    await click(cardButton(cards(view.target)[0]!, 'Change'));
    expect(note(cards(view.target)[0]!)).toBe(before);
    view.cleanup();
  });
});
