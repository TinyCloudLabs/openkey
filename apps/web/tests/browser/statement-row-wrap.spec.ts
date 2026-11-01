// A long unbroken key id in an approval row (a Courier-style 32-hex share id) must wrap inside its card at 390 px:
// nothing scrolls sideways and the Sensitive badge stays in view. Display only; the row text is unchanged.
import { test, expect } from '@playwright/test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { HOST } from './e2e-port';

const owner = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const shareId = '3f9c1a7e5b2d48a09c6e1f7a2b4d8c03';
const exactKey = `urn:tinycloud:encryption:did:pkh:eip155:1:${owner}:default/share/${shareId}`;
const siwe = prepareSession({
  address: owner,
  chainId: 1,
  domain: HOST,
  issuedAt: new Date().toISOString(),
  expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
  spaceId: `tinycloud:pkh:eip155:1:${owner}:default`,
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  abilities: {},
  rawAbilities: { [exactKey]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] },
} as never).siwe;

test.use({ viewport: { width: 390, height: 844 } });

test('a 32-hex key id in an approval row wraps: no sideways scroll, the Sensitive badge stays in view', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address: owner, publicKey: '0x02', keyIndex: 0,
    label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({ json: { authorizationContextToken: 'context-token' } }));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign';
    iframe.style.cssText = 'width:390px;height:844px;border:0';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=wrap-1&protocolVersion=2&keyId=selected-key`;
    const ready = window as unknown as Window & { ready: boolean };
    ready.ready = false;
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow && event.origin === location.origin && event.data?.type === 'openkey:ready') ready.ready = true;
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { ready: boolean }).ready)).toBe(true);
  await page.evaluate((message) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'wrap-1', protocolVersion: 2, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message },
      location.origin,
    );
  }, siwe);
  const frame = page.frameLocator('#sign');
  const row = frame.locator('.summary-statement', { hasText: shareId }).first(); // layout only: no row wording pinned
  await expect(row).toBeVisible();
  await expect(row.locator('.summary-sensitive-pill')).toBeVisible();
  await expect.poll(() => frame.locator('body').evaluate(() => ({
    sideways: document.documentElement.scrollWidth > document.documentElement.clientWidth,
    badgeRightOfView: [...document.querySelectorAll('.summary-sensitive-pill')].some((pill) => pill.getBoundingClientRect().right > document.documentElement.clientWidth),
    rowRightOfCard: [...document.querySelectorAll('.summary-statement')].some((li) => {
      const card = li.closest('.summary')!.getBoundingClientRect();
      return li.getBoundingClientRect().right > card.right + 0.5 || [...li.querySelectorAll('*')].some((el) => el.getBoundingClientRect().right > card.right + 0.5);
    }),
  }))).toEqual({ sideways: false, badgeRightOfView: false, rowRightOfCard: false });
  await page.screenshot({ path: test.info().outputPath('row-wrap-390.png') });
});
