import { test, expect, type Page, type Route } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';
import { makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

// A message signature (the exact-byte path of the sign widget, the call a versioned-host app's personal_sign makes) that
// hosts the owner's `default` space is refused by POST /api/keys/:id/sign while the account is not set up. The refusal
// says account setup is required, so the widget shows the "Finish setup" card in the popup and in the embedded frame.
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const key = { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z', isPrimary: true };
const hostSiwe = siweWithResources([makeRecapResource({
  [`tinycloud:pkh:eip155:1:${address}:default/space`]: { 'tinycloud.space/host': [{}] },
})], { domain: HOST, uri: `http://${HOST}` });

type HostWindow = Window & { received: Record<string, unknown>[]; signWindow: Window };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function mockApi(page: Page) {
  const calls = { signs: 0, authorizeSign: 0 };
  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.context().route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'test-session' }, user: { id: 'u', email: 'n@mail.com' } });
    if (path === '/api/account/terms') return json(route, TERMS_ACCEPTED);
    if (path === '/api/keys') return json(route, { keys: [key] });
    if (path === '/api/keys/selected-key') return json(route, { key });
    if (path === '/api/keys/selected-key/sign/passkey') return json(route, { required: false });
    if (path === '/api/keys/selected-key/sign') {
      calls.signs += 1;
      return json(route, { error: 'Only TinyCloud can create your TinyCloud spaces.', code: 'host_signing_first_party_only', accountSetup: 'required' }, 403);
    }
    if (path.startsWith('/api/delegate/authorize-sign')) calls.authorizeSign += 1;
    return json(route, {});
  });
  return calls;
}

for (const surface of ['popup', 'iframe'] as const) {
  test(`${surface}: a refused message signature for an account that is not set up shows the Finish setup card`, async ({ page }) => {
    const calls = await mockApi(page);
    await page.goto('/__parity_harness');
    await page.evaluate(() => {
      const host = window as unknown as HostWindow;
      host.received = [];
      window.addEventListener('message', (event) => {
        if (event.origin === location.origin && event.source === host.signWindow) host.received.push(event.data);
      });
    });
    let view: Page | ReturnType<Page['frameLocator']> = page;
    if (surface === 'popup') {
      const opened = page.waitForEvent('popup');
      await page.evaluate(() => {
        (window as unknown as HostWindow).signWindow = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`)!;
      });
      view = await opened;
    } else {
      await page.evaluate(() => {
        const iframe = document.createElement('iframe');
        iframe.id = 'sign';
        iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=r1&protocolVersion=2&keyId=selected-key`;
        iframe.style.width = '700px';
        document.body.append(iframe);
        (window as unknown as HostWindow).signWindow = iframe.contentWindow!;
      });
      view = page.frameLocator('#sign');
    }
    await expect.poll(() => page.evaluate(() => (window as unknown as HostWindow).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
    await page.evaluate(({ message, version }) => {
      (window as unknown as HostWindow).signWindow.postMessage({
        type: 'openkey:sign:request', requestId: 'r1', protocolVersion: version, keyId: 'selected-key', message,
      }, location.origin);
    }, { message: hostSiwe, version: surface === 'iframe' ? 2 : undefined });

    const approve = view.locator('button.approve');
    await expect(async () => {
      if (surface === 'iframe') {
        await page.evaluate(() => {
          const host = window as unknown as HostWindow;
          const resize = host.received.filter((m) => m.type === 'openkey:resize').at(-1);
          if (!resize) return;
          const height = Math.min(Number(resize.height), Math.floor(innerHeight * 0.85));
          document.querySelector<HTMLIFrameElement>('#sign')!.style.height = `${height}px`;
          host.signWindow.postMessage({ type: 'openkey:layout-applied', requestId: 'r1', protocolVersion: 2, height, layoutId: resize.layoutId }, location.origin);
        });
      }
      await expect(approve).toBeEnabled({ timeout: 500 });
    }).toPass();
    await approve.click();

    await expect.poll(() => calls.signs).toBe(1);
    await expect(view.getByTestId('account-setup-card')).toBeVisible();
    await expect(view.getByText('Finish setting up your TinyCloud account')).toBeVisible();
    expect(calls.authorizeSign).toBe(0);
  });
}
