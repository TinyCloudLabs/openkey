// TC-2928: a sign-in message that grants encryption decrypt or key.create outside apps/ is refused by
// /api/keys/:keyId/sign unless the requesting site is first-party. Both sign pages refuse it before Approve: the owner
// sees the reason, Approve stays off, the app is told once with the refusal identifier and nothing is sent to sign.
import { test, expect, type Page } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const OWNER = `did:pkh:eip155:1:${address}`;
const WORDS = "This site can't ask for that access, so OpenKey didn't approve this request.";

function siwe(att: Record<string, Record<string, unknown[]>>): string {
  const recap = Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url');
  return `${HOST} wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: ${ORIGIN}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-11-13T00:00:00.000Z\nResources:\n- urn:recap:${recap}`;
}

const storage = { [`tinycloud:pkh:eip155:1:${address}:applications/kv/notes/`]: { 'tinycloud.kv/get': [{}] } };
const shareDecrypt = { ...storage, [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/decrypt': [{}], 'tinycloud.encryption/key.create': [{}] } };

interface Posted { type?: string; success?: boolean; error?: { code?: string; message?: string } }
type HostWindow = Window & { received: Posted[] };
const responses = (page: Page) => page.evaluate(() => (window as unknown as HostWindow).received.filter((m) => m.type === 'openkey:sign:response'));

async function open(page: Page, route: string, message: string) {
  let signCalls = 0;
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (r) => r.fulfill({ json: { key: { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' } } }));
  await page.route('**/api/keys/*/sign', (r) => { signCalls += 1; return r.fulfill({ status: 500, json: { error: 'not expected' } }); });
  await page.route('**/api/auth/get-session**', (r) => r.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.goto('/__parity_harness');
  await page.evaluate((path) => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign';
    iframe.style.cssText = 'width:390px;height:844px;border:0';
    iframe.src = `${path}?origin=${encodeURIComponent(location.origin)}&requestId=legacy-1&protocolVersion=1&keyId=selected-key`;
    const w = window as unknown as HostWindow;
    w.received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow && event.origin === location.origin) w.received.push(event.data);
    });
    document.body.append(iframe);
  }, route);
  await expect.poll(() => page.evaluate(() => (window as unknown as HostWindow).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  // An unversioned request: the pages sign it through /api/keys/:keyId/sign, as for apps on older SDKs.
  await page.evaluate((text) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', keyId: 'selected-key', message: text },
      location.origin,
    );
  }, message);
  return { frame: page.frameLocator('#sign'), signCalls: () => signCalls };
}

for (const route of ['/widget/embed/sign', '/widget/sign']) {
  test(`${route}: an outside site's share decrypt request is refused before Approve`, async ({ page }) => {
    const { frame, signCalls } = await open(page, route, siwe(shareDecrypt));
    await expect.poll(() => responses(page)).toEqual([expect.objectContaining({ success: false, error: { code: 'UNKNOWN', message: 'APP_KEY_GRANT_REFUSED' } })]);
    await expect(frame.getByRole('alert')).toHaveText(WORDS);
    await page.waitForTimeout(1800);
    await expect(frame.getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
    await expect(frame.getByRole('button', { name: 'Try again', exact: true })).toHaveCount(0);
    expect(await responses(page)).toHaveLength(1);
    expect(signCalls()).toBe(0);
  });

  test(`${route}: the same site asking only for storage can still approve`, async ({ page }) => {
    const { frame } = await open(page, route, siwe(storage));
    await expect(frame.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled({ timeout: 10_000 });
    await expect(frame.getByText(WORDS)).toHaveCount(0);
    expect(await responses(page)).toEqual([]);
  });
}
