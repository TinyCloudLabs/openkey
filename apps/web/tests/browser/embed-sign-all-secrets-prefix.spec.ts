// TC-3800: on the embedded sign-in frame, decrypt on `default/secrets` itself, a prefix under `secrets/`, or a path that
// only reads as one of them once lower-cased and percent-decoded (`Secrets/`, `secrets%2F`), opens the warning screen
// on the all-secrets card; one secret's own key does not. The frame's API (/authorize-sign-prepare takes each of these)
// is answered by `page.route`.

import { test, expect, type Page } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

// The selected key is the owner the grants name, so the review reads them as the owner's own secrets.
const address = FIXTURE_META.address;
const owner = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${owner}:default${rest}`;
const secretsSpace = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:secrets`;
const readSecret = { [`${secretsSpace}/kv/vault/secrets/OPENAI_API_KEY`]: { 'tinycloud.kv/get': [{}] } };

async function open(page: Page, rest: string) {
  const message = siweWithResources(
    [makeRecapResource({ ...readSecret, [urn(rest)]: { 'tinycloud.encryption/decrypt': [{}] } })],
    { domain: HOST, uri: ORIGIN },
  );
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({
    headers: { Date: new Date().toUTCString() },
    json: { authorizationContextToken: 'context-token', expiresAt: new Date(Date.now() + 300_000).toISOString() },
  }));
  await page.route('**/api/delegate/authorize-sign-preview', async (route) => {
    const ids = (route.request().postDataJSON() as { selectedActionIds: string[] }).selectedActionIds;
    const permissions = ids.map((id) => {
      const [service, space, path, ability] = id.split('\0');
      return { service, space, path, actions: [ability] };
    });
    await route.fulfill({
      headers: { Date: new Date().toUTCString() },
      json: { signedMessage: message, authorizationContextToken: 'context-token', previewApprovalToken: 'preview', previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(), selectedActionKeys: ids, permissions },
    });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=all-secrets&protocolVersion=1&keyId=selected-key`;
    (window as unknown as { received: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow) (window as unknown as { received: unknown[] }).received.push(event.data);
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate((message) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'all-secrets', protocolVersion: 1, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message },
      location.origin,
    );
  }, message);
  const frame = page.frameLocator('#sign');
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  return frame;
}

test.use({ viewport: { width: 390, height: 1100 } });

for (const rest of [
  '/secrets/', '/secrets', '/secrets/scoped/work/', '/secrets/scoped/', '/Secrets/', '/SECRETS/', '/SECRETS/x',
  '/Secrets/openai_api_key', '/secrets%2F', '/secrets%2f', '/secrets%2Fopenai_api_key', '/secrets%2fx',
]) {
  test(`decrypt on default${rest} opens the warning on the all-secrets card`, async ({ page }) => {
    const frame = await open(page, rest);
    await expect(frame.getByRole('dialog')).not.toContainText('Read the secret OPENAI_API_KEY');
    await frame.locator('button.approve').click();
    await expect(frame.locator('#elevated-title')).toContainText('is asking for more access');
    await expect(frame.locator('.elevated .card h2').first()).toContainText(/read all your secrets\?/);
  });
}

test("one secret's own key opens no all-secrets card", async ({ page }) => {
  const frame = await open(page, '/secrets/openai_api_key');
  await expect(frame.getByRole('dialog')).toContainText('Read the secret OPENAI_API_KEY');
  await frame.locator('button.approve').click();
  await expect(frame.locator('#elevated-title')).toContainText('is asking for more access');
  await expect(frame.locator('.elevated .card h2').first()).toBeVisible();
  await expect(frame.locator('.elevated')).not.toContainText('all your secrets');
});
