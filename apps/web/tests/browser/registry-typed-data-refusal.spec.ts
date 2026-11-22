// Hardening: typed-data signing. The real typed-data sign routes, in a frame, show the refusal INSTEAD of the sign
// card for the registry's node-location struct from an origin that is not TinyCloud One / Home: no sign control, no
// passkey offer and no /sign-typed-data call. Other typed data still reaches the sign card.
import { test, expect, type Page } from '@playwright/test';
import { TERMS_ACCEPTED } from './terms-fixtures';

const key = {
  id: 'qa-key', keyIndex: 0, isPrimary: true, keyType: 'MANAGED', label: 'Key 0',
  address: '0x1111111111111111111111111111111111111111', publicKey: '0x', createdAt: '2026-01-01T00:00:00Z',
};
const SET_NODE = {
  domain: { name: 'TinyCloudRegistry', version: '1', chainId: 1, verifyingContract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
  types: { SetNode: [{ name: 'node', type: 'string' }] },
  primaryType: 'SetNode',
  message: { node: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' },
};
const NOTE = {
  domain: { name: 'QA' }, types: { Note: [{ name: 'text', type: 'string' }] }, primaryType: 'Note', message: { text: 'hello' },
};

const TITLE = "This app's request can't be signed";
const BODY = {
  popup: "It would set which TinyCloud node holds your data. Only TinyCloud's own apps can ask for that, so this app can't. Nothing was signed. You can close this window.",
  embed: "It would set which TinyCloud node holds your data. Only TinyCloud's own apps can ask for that, so this app can't. Nothing was signed. You can go back to the app.",
};

type Response = { type: string; success?: boolean; error?: { code: string; message: string } };
type Recording = Window & { received?: Response[] };

async function open(page: Page, surface: string, typedData: unknown) {
  const apiCalls: string[] = [];
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'qa-session'));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({
    json: { session: { id: 'qa-session', userId: 'qa-user' }, user: { id: 'qa-user' } },
  }));
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await page.route('**/api/keys', (route) => route.fulfill({ json: { keys: [key] } }));
  await page.route('**/api/keys/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === 'POST') {
      apiCalls.push(path);
      return route.fulfill({ json: path.endsWith('/passkey') ? { required: false } : { signature: '0x1234', address: key.address } });
    }
    return route.fulfill({ json: { key } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(({ surface, typedData }) => {
    const iframe = document.createElement('iframe');
    iframe.id = 'typed-data';
    iframe.style.width = '600px';
    iframe.style.height = '900px';
    iframe.src = `/widget/${surface}?origin=${encodeURIComponent(location.origin)}`;
    (window as Recording).received = [];
    window.addEventListener('message', (event) => {
      if (event.source !== iframe.contentWindow || event.origin !== location.origin) return;
      (window as Recording).received?.push(event.data);
      if (event.data?.type === 'openkey:ready') {
        iframe.contentWindow?.postMessage({ type: 'openkey:signTypedData:request', data: typedData }, location.origin);
      }
    });
    document.body.append(iframe);
  }, { surface, typedData });
  return { frame: page.frameLocator('#typed-data'), apiCalls };
}

const received = (page: Page) => page.evaluate(() => (window as Recording).received ?? []);

for (const surface of [
  { name: 'popup', route: 'sign-typed-data', variant: 'popup' as const, button: 'Close' },
  { name: 'embed', route: 'embed/sign-typed-data', variant: 'embed' as const, button: 'Back to the app' },
]) {
  test(`${surface.name} typed-data page refuses the registry struct from another origin`, async ({ page }) => {
    const { frame, apiCalls } = await open(page, surface.route, SET_NODE);
    const refusal = frame.getByTestId('registry-record-refusal');
    await expect(refusal).toBeVisible();
    await expect(refusal).toContainText(TITLE);
    await expect(refusal).toContainText(BODY[surface.variant]);
    await expect(refusal.getByRole('button', { name: surface.button })).toBeVisible();
    await expect(frame.getByRole('button', { name: 'Sign Data', exact: true })).toHaveCount(0);
    await expect.poll(async () => (await received(page)).find((m) => m.type === 'openkey:signTypedData:response')?.error)
      .toEqual({ code: 'UNKNOWN', message: 'REGISTRY_RECORD_SIGN_REFUSED' });
    expect((await received(page)).some((m) => m.type === 'openkey:signTypedData:response' && m.success === true)).toBe(false);
    expect(apiCalls).toEqual([]);
  });

  test(`${surface.name} typed-data page refuses the registry domain with another struct`, async ({ page }) => {
    const { frame, apiCalls } = await open(page, surface.route, { ...NOTE, domain: { name: ' tinycloudregistry ' } });
    await expect(frame.getByTestId('registry-record-refusal')).toBeVisible();
    expect(apiCalls).toEqual([]);
  });

  test(`${surface.name} typed-data page still shows the sign card for other typed data`, async ({ page }) => {
    const { frame } = await open(page, surface.route, NOTE);
    await expect(frame.getByRole('button', { name: 'Sign Data', exact: true })).toBeVisible();
    await expect(frame.getByTestId('registry-record-refusal')).toHaveCount(0);
    expect((await received(page)).some((m) => m.type === 'openkey:signTypedData:response')).toBe(false);
  });
}
