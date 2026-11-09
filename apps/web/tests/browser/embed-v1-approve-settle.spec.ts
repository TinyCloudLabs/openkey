// TC-2320: a v1 embed (protocolVersion 1) has no layout-ready message, so the SDK modal animates the frame's
// height (packages/sdk/src/index.ts: 400px frame, `transition:height 200ms`, flex-centred card) while the review is
// already on screen. Approve must not be enabled while the frame is still moving, and once enabled it must not move.
// The harness parent reproduces that modal around the REAL /widget/embed/sign page. A page-level slide that moves
// the frame without resizing it is not detectable from inside the frame (see the PR).
import { test, expect, type Page } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';
import { HOST } from './e2e-port';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);

type Parent = 'sdk-modal' | 'never-resizes' | 'resizes-forever';

async function openEmbed(page: Page, parent: Parent, version: 1 | 2 = 1, keyDelayMs = 0) {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', async (route) => {
    if (keyDelayMs > 0) await new Promise((resolve) => setTimeout(resolve, keyDelayMs));
    await route.fulfill({ json: { key: { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' } } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({ json: {
    authorizationContextToken: 'context-token', expiresAt: new Date(Date.now() + 300_000).toISOString(),
  } }));
  await page.route('**/api/delegate/authorize-sign-preview', (route) => {
    const ids = route.request().postDataJSON().selectedActionIds as string[];
    return route.fulfill({ json: {
      authorizationContextToken: 'context-token', previewApprovalToken: 'preview-token',
      previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(), signedMessage: siwe,
      selectedActionKeys: ids, permissions: ids.map(id => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      }),
    } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(([mode, protocol, message]) => {
    const w = window as unknown as Window & { frameLog: Array<{ t: number; top: number; enabled: boolean | null }>; resizeCount: number; sampleTimer: number };
    w.frameLog = [];
    w.resizeCount = 0;
    // The SDK modal: a flex-centred card around a 400px frame with a 200ms height transition (index.ts:587).
    const wrap = document.createElement('div');
    wrap.style.cssText = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center';
    const card = document.createElement('div');
    card.style.cssText = 'width:400px';
    const frame = document.createElement('iframe');
    frame.id = 'sign';
    frame.style.cssText = 'border:none;width:100%;height:400px;display:block;transition:height 200ms ease';
    const phase = protocol === 2 ? '&requestId=phase-1&keyId=selected-key' : '&requestId=v1-1&keyId=selected-key';
    frame.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}${phase}&protocolVersion=${protocol}`;
    card.append(frame); wrap.append(card); document.body.append(wrap);
    const t0 = performance.now();
    window.addEventListener('message', (event) => {
      if (event.source !== frame.contentWindow) return;
      // Like the SDK, post the sign request whenever the frame reports ready (a cold dev server can reload it once).
      if (event.data?.type === 'openkey:ready') {
        setTimeout(() => frame.contentWindow!.postMessage(
          { type: 'openkey:sign:request', requestId: protocol === 2 ? 'phase-1' : 'v1-1', protocolVersion: protocol, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message },
          location.origin), 300);
        return;
      }
      if (event.data?.type !== 'openkey:resize') return;
      w.resizeCount += 1;
      if (mode === 'never-resizes') return;
      if (mode === 'resizes-forever') return; // the forever-resizing parent is driven by the interval below
      frame.style.height = `${Math.min(event.data.height, Math.floor(innerHeight * 0.85))}px`;
    });
    if (mode === 'resizes-forever') {
      let flip = false;
      setInterval(() => { flip = !flip; frame.style.transition = 'none'; frame.style.height = flip ? '380px' : '420px'; }, 40);
    }
    // Sample the Approve button's page position and enabled state every animation frame.
    const sample = () => {
      const button = frame.contentDocument?.querySelector('button.approve') as HTMLButtonElement | null;
      const box = frame.getBoundingClientRect();
      const top = button ? Math.round((box.top + button.getBoundingClientRect().top) * 10) / 10 : NaN;
      w.frameLog.push({ t: Math.round(performance.now() - t0), top, enabled: button ? !button.disabled : null });
      w.sampleTimer = requestAnimationFrame(sample);
    };
    sample();
  }, [parent, version, siwe] as const);
}

const samples = (page: Page) => page.evaluate(() => (window as unknown as Window & { frameLog: Array<{ t: number; top: number; enabled: boolean | null }> }).frameLog);

// The first load of the embed route can take a while on a cold dev server, so tests wait for the review (a button
// exists) with the long default and then judge timings from the sampled clock, not from wall-clock timeouts.
async function reviewShown(page: Page) {
  await expect.poll(async () => (await samples(page)).some((s) => s.enabled !== null), { timeout: 45_000 }).toBe(true);
}
function appearedAt(log: Awaited<ReturnType<typeof samples>>) { return log.find((s) => s.enabled !== null)!.t; }
function enabledAt(log: Awaited<ReturnType<typeof samples>>) { return log.find((s) => s.enabled === true)?.t; }

test('a v1 review behind an animating frame: Approve is enabled only once the frame has stopped, and then it does not move', async ({ page }) => {
  await openEmbed(page, 'sdk-modal');
  await reviewShown(page);
  await expect.poll(async () => enabledAt(await samples(page)), { timeout: 10_000 }).toBeDefined();
  await page.waitForTimeout(500);
  const log = await samples(page);
  const firstEnabled = log.findIndex((s) => s.enabled === true);
  expect(firstEnabled).toBeGreaterThan(0);
  const tops = log.slice(firstEnabled).filter((s) => !Number.isNaN(s.top)).map((s) => s.top);
  // From the first moment Approve is enabled, its page position never changes (no 92px jump under the click).
  expect(Math.max(...tops) - Math.min(...tops)).toBeLessThanOrEqual(0.5);
  // While it was moving it was not enabled: every enabled sample is at the final position.
  const finalTop = tops.at(-1)!;
  expect(log.filter((s) => s.enabled === true && Math.abs(s.top - finalTop) > 0.5)).toEqual([]);
});

test('a v1 review that renders later than the ceiling (slow key read) still waits for the frame, and then does not move', async ({ page }) => {
  await openEmbed(page, 'sdk-modal', 1, 2200);
  await reviewShown(page);
  await expect.poll(async () => enabledAt(await samples(page)), { timeout: 10_000 }).toBeDefined();
  await page.waitForTimeout(500);
  const log = await samples(page);
  const firstEnabled = log.findIndex((s) => s.enabled === true);
  const tops = log.slice(firstEnabled).filter((s) => !Number.isNaN(s.top)).map((s) => s.top);
  expect(Math.max(...tops) - Math.min(...tops)).toBeLessThanOrEqual(0.5);
  // The clock started when the review rendered, not when the page loaded: it was not enabled at first display.
  expect(log.find((s) => s.enabled !== null)!.enabled).toBe(false);
});

test('a v1 parent that never resizes the frame: Approve is enabled within the ceiling', async ({ page }) => {
  await openEmbed(page, 'never-resizes');
  await reviewShown(page);
  await expect.poll(async () => enabledAt(await samples(page)), { timeout: 5000 }).toBeDefined();
  const log = await samples(page);
  expect(enabledAt(log)! - appearedAt(log)).toBeLessThanOrEqual(1500 + 250);
});

test('a v1 parent that keeps resizing forever: Approve is still enabled by the ceiling', async ({ page }) => {
  await openEmbed(page, 'resizes-forever');
  await reviewShown(page);
  await expect.poll(async () => enabledAt(await samples(page)), { timeout: 6000 }).toBeDefined();
  const log = await samples(page);
  expect(enabledAt(log)! - appearedAt(log)).toBeLessThanOrEqual(1500 + 250);
});

test('v2 is unchanged: still gated by its own layout-ready handshake, not by the v1 settle gate', async ({ page }) => {
  await openEmbed(page, 'sdk-modal', 2);
  await reviewShown(page);
  // Nothing acks the layout (the harness is not a v2 host), so a v2 Approve stays blocked far past the v1 ceiling.
  await page.waitForTimeout(2200);
  expect((await samples(page)).some((s) => s.enabled === true)).toBe(false);
});

// TC-2310: a click made by a script inside the frame (a shared-note flow does this) is no longer dropped for not coming
// from the browser. What still stops a click that should not count is that Approve is not armed: while the frame is
// moving (v1 settle gate) or before the host has acknowledged the layout (v2), the button is disabled and nothing is sent.
async function approvalRequests(page: Page) {
  const seen: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/delegate/authorize-sign')) seen.push(request.url());
  });
  return seen;
}
const approveFrame = (page: Page) => page.frames().find((entry) => entry !== page.mainFrame() && entry.url().includes('/widget/embed/sign'))!;
// A script-made click, two ways: the click() method, and a dispatched click event.
const scriptClicks = (page: Page) => approveFrame(page).evaluate(() => {
  const button = document.querySelector('button.approve') as HTMLButtonElement;
  button.click();
  button.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
});

test('a v1 frame that has settled: a click made by a script approves', async ({ page }) => {
  const approvals = await approvalRequests(page);
  await openEmbed(page, 'never-resizes');
  await reviewShown(page);
  await expect.poll(async () => enabledAt(await samples(page)), { timeout: 6000 }).toBeDefined();
  await page.waitForTimeout(300);
  const approvalCount = approvals.length;
  await scriptClicks(page);
  await expect.poll(() => approvals.length).toBeGreaterThan(approvalCount);
});

test('a v1 frame that is still moving: a click made by a script does nothing, and approves once it has settled', async ({ page }) => {
  const approvals = await approvalRequests(page);
  await openEmbed(page, 'sdk-modal');
  await reviewShown(page);
  // At first display the frame is still animating: Approve is disabled.
  expect((await samples(page)).find((s) => s.enabled !== null)!.enabled).toBe(false);
  const approvalCount = approvals.length;
  await expect.poll(async () => enabledAt(await samples(page)), { timeout: 10_000 }).toBeDefined();
  await page.waitForTimeout(300);
  expect(approvals).toHaveLength(approvalCount);
  await scriptClicks(page);
  await expect.poll(() => approvals.length).toBeGreaterThan(approvalCount);
});

test('a v2 frame the host has not acknowledged: a click made by a script does nothing', async ({ page }) => {
  const approvals = await approvalRequests(page);
  await openEmbed(page, 'sdk-modal', 2);
  await reviewShown(page);
  await page.waitForTimeout(1500);
  const approvalCount = approvals.length;
  await scriptClicks(page);
  await page.waitForTimeout(500);
  expect(approvals).toHaveLength(approvalCount);
});
