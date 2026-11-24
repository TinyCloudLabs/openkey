import { test, expect, type Page } from '@playwright/test';

const id = 'abcdefghijklmnopqrstuvwxyz';
const fragment = `#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const path = `/a/${id}`;
const storageKey = `openkey.approval.${id}`;

async function serve(page: Page, response: { status?: number; body?: unknown } = {}) {
  const calls: string[] = [];
  await page.route('**/api/**', async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    calls.push(pathname);
    expect(request.url()).not.toContain(fragment.slice(1));
    if (pathname === '/api/auth/get-session') {
      return route.fulfill({ json: null });
    }
    if (pathname === `/api/approval-requests/${id}/load`) {
      expect(request.postDataJSON()).toEqual({ reference: path + fragment });
      return route.fulfill({ status: response.status ?? 200, json: response.body ?? {
        requestId: id, expiresAt: new Date(Date.now() + 3600_000).toISOString(), approved: false,
        request: { targetDid: 'did:key:requester', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
          nodeOrigin: 'https://node.tinycloud.xyz', permissions: [{ service: 'tinycloud.kv', space: 'applications', path: 'todos/', actions: ['tinycloud.kv/get'] }],
          grantLifetimeSeconds: 7200, reason: 'Read Todos for two hours' },
      } });
    }
    return route.fulfill({ status: 404, json: { error: 'Unexpected request' } });
  });
  return calls;
}

test('complete short link survives sign-in navigation and repeated previews without authorizing', async ({ page }) => {
  const calls = await serve(page);
  await page.goto(path + fragment);
  await expect(page.getByRole('link', { name: 'Continue with email' })).toBeVisible();
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(key => sessionStorage.getItem(key), storageKey)).toBe(fragment);
  await page.getByRole('link', { name: 'Continue with email' }).click();
  await expect(page).toHaveURL(new RegExp('/auth/login\\?redirect='));
  expect(new URL(page.url()).searchParams.get('redirect')).toBe(path);
  await page.goto(path);
  await expect(page.getByRole('link', { name: 'Continue with email' })).toBeVisible();
  expect(calls.filter(value => value === `/api/approval-requests/${id}/load`)).toHaveLength(2);
  expect(calls.filter(value => value.startsWith('/api/delegate') || value.startsWith('/api/approval-results'))).toEqual([]);
});

test('a preview without a fragment cannot load or consume approval', async ({ page }) => {
  const calls = await serve(page);
  await page.goto(path);
  await expect(page.getByRole('heading', { name: 'This link is missing its last part' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
  expect(calls.filter(value => value.includes('approval') || value.includes('delegate'))).toEqual([]);
});

test('blocked browser storage scrubs the key and explains external-browser recovery', async ({ page }) => {
  await page.addInitScript(() => {
    Storage.prototype.setItem = () => { throw new DOMException('Storage disabled', 'SecurityError'); };
  });
  const calls = await serve(page);
  await page.goto(path + fragment);
  const stop = page.getByTestId('stop-page');
  await expect(stop.getByRole('heading', { name: 'This browser can’t hold on to the request' })).toBeVisible();
  await expect(stop).toContainText('Open the original link in Safari or Chrome instead.');
  expect(new URL(page.url()).hash).toBe('');
  expect(calls.filter(value => value.includes('approval') || value.includes('delegate'))).toEqual([]);
});

for (const scenario of [
  { status: 400, code: 'expired', heading: 'This request expired' },
  { status: 400, code: 'gone', heading: 'This request can’t be found' },
  { status: 400, code: 'link_cid_mismatch', heading: 'This link doesn’t match the request it points to' },
  { status: 503, code: 'retention_not_configured', heading: 'Couldn’t load this request' },
]) {
  test(`request failure ${scenario.code} offers recovery without approval controls`, async ({ page }) => {
    await serve(page, { status: scenario.status, body: { code: scenario.code, error: 'opaque decoder details' } });
    await page.goto(path + fragment);
    const stop = page.getByTestId('stop-page');
    await expect(stop.getByRole('heading', { name: scenario.heading })).toBeVisible();
    await expect(stop).not.toContainText('opaque decoder details');
    await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
    if (scenario.code === 'expired') expect(await page.evaluate(key => sessionStorage.getItem(key), storageKey)).toBeNull();
  });
}

test('legacy truncated link stops before sign-in or key selection', async ({ page }) => {
  const calls = await serve(page);
  await page.goto('/delegate?did=did:key:requester');
  await expect(page.getByRole('heading', { name: 'This link is cut off' })).toBeVisible();
  await expect(page.getByTestId('stop-page')).toContainText('Ask the app or agent to send it again on its own line');
  await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
  expect(calls.filter(value => value === '/api/keys' || value.startsWith('/api/delegate'))).toEqual([]);
});

test('client navigation to another request never reuses the previous approval', async ({ page }) => {
  const calls = await serve(page);
  await page.goto(path + fragment);
  await expect(page.getByRole('link', { name: 'Continue with email' })).toBeVisible();
  const nextPath = `/a/${'b'.repeat(26)}`;
  await page.evaluate(target => {
    const link = document.createElement('a');
    link.id = 'next-approval';
    link.href = target;
    link.textContent = 'Next approval';
    document.body.append(link);
  }, nextPath);
  await page.locator('#next-approval').click();
  await expect(page.getByRole('heading', { name: 'This link is missing its last part' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
  expect(calls.filter(value => value === `/api/approval-requests/${id}/load`)).toHaveLength(1);
});

test('query-contaminated approval links are rejected before resolution', async ({ page }) => {
  const calls = await serve(page);
  await page.goto(path + '?tracking=chat' + fragment);
  await expect(page.getByRole('heading', { name: 'This link is cut off' })).toBeVisible();
  await expect(page.getByTestId('stop-page')).toContainText('Ask the app or agent to send it again on its own line');
  expect(new URL(page.url()).hash).toBe('');
  expect(calls.filter(value => value.includes('approval') || value.includes('delegate'))).toEqual([]);
});
