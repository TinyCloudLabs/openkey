// TC-2457 / TC-2456: what the framed sign card does when the server refuses.
// A refusal that cannot change on retry (app_key_grant_refused and its siblings) must tell the app once, leave Approve
// unusable and show the reason where the owner is looking. A temporary failure must tell the app nothing, keep Approve
// usable and still show its message in view. The harness parent embeds the REAL /widget/embed/sign page in a 400 px
// frame, like the SDK modal, and records every message the frame posts to it.
import { test, expect, type Page } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';
import { HOST } from './e2e-port';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);
const REFUSAL_TEXT = "This website doesn't list the key this app asked for, so OpenKey didn't approve it.";

interface Posted { type?: string; success?: boolean; error?: { code?: string; message?: string } }
type HostWindow = Window & { posted: Posted[] };

async function openFramed(page: Page, prepare: { status: number; body: unknown }) {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  let prepares = 0;
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => {
    prepares += 1;
    return route.fulfill({ status: prepare.status, json: prepare.body });
  });
  await page.goto('/__parity_harness');
  await page.evaluate((message) => {
    const w = window as unknown as HostWindow;
    w.posted = [];
    const frame = document.createElement('iframe');
    frame.id = 'sign';
    frame.style.cssText = 'border:none;width:420px;height:400px;display:block';
    frame.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=v1-1&keyId=selected-key&protocolVersion=1`;
    document.body.append(frame);
    window.addEventListener('message', (event) => {
      if (event.source !== frame.contentWindow) return;
      if (event.data?.type === 'openkey:ready') {
        setTimeout(() => frame.contentWindow!.postMessage(
          { type: 'openkey:sign:request', requestId: 'v1-1', protocolVersion: 1, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message },
          location.origin), 300);
        return;
      }
      w.posted.push(event.data);
    });
  }, siwe);
  const armed = () => page.evaluate(() => {
    const d = (document.querySelector('iframe#sign') as HTMLIFrameElement | null)?.contentDocument;
    const button = d?.querySelector('button.approve') as HTMLButtonElement | null;
    return button ? !button.disabled : false;
  });
  await expect.poll(armed, { timeout: 45_000 }).toBe(true);
  await page.waitForTimeout(400);
  return { prepares: () => prepares };
}

const frameState = (page: Page) => page.evaluate(() => {
  const f = document.querySelector('iframe#sign') as HTMLIFrameElement;
  const d = f.contentDocument!;
  const error = d.querySelector('p.error') as HTMLElement | null;
  const approve = d.querySelector('button.approve') as HTMLButtonElement | null;
  const box = (el: Element | null) => { if (!el) return null; const r = el.getBoundingClientRect(); return { top: r.top, bottom: r.bottom }; };
  return {
    approveDisabled: approve ? approve.disabled : null,
    errorText: error?.textContent?.trim() ?? null,
    error: box(error),
    approve: box(approve),
    viewport: f.contentWindow!.innerHeight,
  };
});
const posted = (page: Page) => page.evaluate(() => (window as unknown as HostWindow).posted.filter((m) => m.type === 'openkey:sign:response'));
const clickApprove = (page: Page) => page.frameLocator('#sign').locator('button.approve').click();

for (const [code, status] of [['app_key_grant_refused', 403], ['key_delete_not_grantable', 403], ['invalid_siwe_recap', 400]] as const) {
test(`${code}: tells the app once, disables Approve and shows the reason in view`, async ({ page }) => {
  const calls = await openFramed(page, { status, body: { error: REFUSAL_TEXT, code } });
  await clickApprove(page);
  await expect.poll(() => posted(page)).toHaveLength(1);
  const [response] = await posted(page);
  expect(response!.success).toBe(false);
  expect(response!.error?.code).toBe('UNKNOWN');
  expect(response!.error?.message).toMatch(/^[A-Z_]+$/);
  expect(response!.error?.message).not.toContain(REFUSAL_TEXT);

  // Past the layout settle gate's longest wait (1.5 s): Approve is still disabled, so it is the refusal that holds it.
  await page.waitForTimeout(1800);
  const state = await frameState(page);
  expect(state.approveDisabled).toBe(true);
  expect(state.errorText).toBe(REFUSAL_TEXT);
  // The reason is inside the visible frame and sits above the Approve button, not below the fold.
  expect(state.error!.top).toBeGreaterThanOrEqual(0);
  expect(state.error!.bottom).toBeLessThanOrEqual(state.viewport);
  expect(state.error!.bottom).toBeLessThanOrEqual(state.approve!.top + 1);

  // Approve cannot be used again, and closing after the refusal does not send a second answer.
  await page.frameLocator('#sign').locator('button.approve').click({ force: true });
  await page.waitForTimeout(300);
  expect(calls.prepares()).toBe(1);
  await page.frameLocator('#sign').locator('button.cancel').click();
  await page.waitForTimeout(300);
  expect(await posted(page)).toHaveLength(1);
});
}

test('a temporary failure tells the app nothing, keeps Approve usable and shows the message in view', async ({ page }) => {
  const calls = await openFramed(page, { status: 500, body: { error: 'Something went wrong on our side.' } });
  await clickApprove(page);
  await expect.poll(async () => (await frameState(page)).errorText).toBe('Something went wrong on our side.');
  // A new message resizes the frame, so the layout settle gate holds Approve briefly; it must then come back.
  await expect.poll(async () => (await frameState(page)).approveDisabled, { timeout: 8000 }).toBe(false);
  const state = await frameState(page);
  expect(state.error!.top).toBeGreaterThanOrEqual(0);
  expect(state.error!.bottom).toBeLessThanOrEqual(state.viewport);
  expect(state.error!.bottom).toBeLessThanOrEqual(state.approve!.top + 1);
  expect(await posted(page)).toHaveLength(0);
  await clickApprove(page);
  await expect.poll(() => calls.prepares()).toBe(2);
});
