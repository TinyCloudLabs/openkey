// The OAuth consent page tells the owner which host they return to (from the
// signed redirect_uri) and lists the TinyCloud and stay-connected permissions
// when they are requested. Every API call is answered by `page.route`.

import { expect, test, type Page, type Route } from '@playwright/test';

const sessionBody = {
  session: { id: 'session-1', userId: 'user-1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  user: { id: 'user-1', email: 'owner@example.test', name: 'Owner' },
};
const json = (route: Route, body: unknown, status = 200) => route.fulfill({
  status, contentType: 'application/json', body: JSON.stringify(body),
});

async function mockApi(page: Page) {
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/get-session')) return json(route, sessionBody);
    if (path.endsWith('/oauth2/public-client')) return json(route, { client_name: 'Sample App' });
    return json(route, {});
  });
}

/** `signed` params come before `sig`, as the authorize endpoint signs them; `unsigned` follow it. */
async function openConsent(page: Page, opts: { scope: string; redirectUri?: string; unsigned?: string }) {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page);
  const params = new URLSearchParams({ client_id: 'sample-client', scope: opts.scope });
  if (opts.redirectUri !== undefined) params.set('redirect_uri', opts.redirectUri);
  params.set('state', 'abc');
  params.set('sig', 'test');
  await page.goto(`/oauth/consent?${params}${opts.unsigned ?? ''}`);
  await expect(page.getByRole('heading', { name: 'Sample App' })).toBeVisible();
}

const returnLine = (page: Page) => page.getByText(/After you allow, you'll return to/);

test.describe('consent return host', () => {
  test('shows only the host of the redirect URI, never its path or query', async ({ page }) => {
    await openConsent(page, { scope: 'openid tinycloud:mcp', redirectUri: 'https://claude.ai/api/mcp/auth_callback?session=secret-value' });
    await expect(returnLine(page)).toHaveText("After you allow, you'll return to claude.ai");
    await expect(page.locator('body')).not.toContainText('auth_callback');
    await expect(page.locator('body')).not.toContainText('secret-value');
  });

  test('shows a loopback redirect with its port', async ({ page }) => {
    await openConsent(page, { scope: 'openid', redirectUri: 'http://127.0.0.1:53124/callback' });
    await expect(returnLine(page)).toHaveText("After you allow, you'll return to 127.0.0.1:53124");
  });

  test('an internationalized host is shown in its punycode form', async ({ page }) => {
    await openConsent(page, { scope: 'openid', redirectUri: 'https://cl\u0430ude.ai/callback' });
    await expect(returnLine(page)).toHaveText("After you allow, you'll return to xn--clude-5ve.ai");
  });

  test('renders nothing when there is no usable redirect URI', async ({ page }) => {
    for (const redirectUri of [undefined, '', 'not a url', 'https://', 'javascript:alert(1)', 'myapp://callback/x', 'https://user:pw@claude.ai/cb', 'http://claude.ai/cb']) {
      await openConsent(page, { scope: 'openid', redirectUri });
      await expect(returnLine(page)).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
    }
  });

  test('a redirect_uri after the signature is not trusted', async ({ page }) => {
    await openConsent(page, { scope: 'openid', unsigned: `&redirect_uri=${encodeURIComponent('https://evil.example/cb')}` });
    await expect(returnLine(page)).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText('evil.example');
  });

  test('without a signature nothing is shown', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await mockApi(page);
    await page.goto(`/oauth/consent?client_id=sample-client&scope=openid&redirect_uri=${encodeURIComponent('https://claude.ai/cb')}`);
    await expect(page.getByRole('heading', { name: 'Sample App' })).toBeVisible();
    await expect(returnLine(page)).toHaveCount(0);
  });
});

test.describe('consent permission lines', () => {
  const mcpLine = 'Connect to TinyCloud. You approve access to your data separately.';
  const stayLine = 'Stay connected for up to 30 days, or until you disconnect it.';

  test('lists TinyCloud access and staying connected when both are requested', async ({ page }) => {
    await openConsent(page, { scope: 'openid email tinycloud:mcp offline_access', redirectUri: 'https://claude.ai/cb' });
    await expect(page.getByText('wants to connect to your TinyCloud', { exact: true })).toBeVisible();
    await expect(page.getByText('wants to verify your identity')).toHaveCount(0);
    await expect(page.getByText(mcpLine, { exact: true })).toBeVisible();
    await expect(page.getByText(stayLine, { exact: true })).toBeVisible();
    await expect(page.getByText('This app gets only the access listed above.', { exact: true })).toBeVisible();
    await expect(page.getByText("This app can't sign anything or use your TinyCloud data.")).toHaveCount(0);
  });

  test('tinycloud:mcp without offline_access shows no stay-connected line', async ({ page }) => {
    await openConsent(page, { scope: 'openid tinycloud:mcp', redirectUri: 'https://claude.ai/cb' });
    await expect(page.getByText(mcpLine, { exact: true })).toBeVisible();
    await expect(page.getByText(stayLine, { exact: true })).toHaveCount(0);
  });

  test('every scope with a plain description gets its row and the note says only that access is listed', async ({ page }) => {
    await openConsent(page, { scope: 'openid email keys tinycloud:session', redirectUri: 'https://app.example.test/cb' });
    for (const row of [
      'See your email address',
      'See the addresses of your OpenKey keys',
      'Request one-hour TinyCloud sessions (read and write key-value data) signed by your OpenKey key',
    ]) {
      await expect(page.getByText(row, { exact: true })).toBeVisible();
    }
    await expect(page.getByText('This app gets only the access listed above.', { exact: true })).toBeVisible();
  });

  test('a scope with no plain description is named and the "only the access listed" note is dropped', async ({ page }) => {
    await openConsent(page, { scope: 'openid email vendor:custom', redirectUri: 'https://app.example.test/cb' });
    await expect(page.getByText('Use the “vendor:custom” permission', { exact: true })).toBeVisible();
    await expect(page.getByText('This app gets only the access listed above.')).toHaveCount(0);
    await expect(page.getByText("This app can't sign anything or use your TinyCloud data.")).toHaveCount(0);
  });

  test('without tinycloud:mcp the stay-connected row makes no 30-day claim', async ({ page }) => {
    await openConsent(page, { scope: 'openid offline_access', redirectUri: 'https://app.example.test/cb' });
    await expect(page.getByText('Stay connected until the connection expires or you disconnect it.', { exact: true })).toBeVisible();
    await expect(page.getByText(/30 days/)).toHaveCount(0);
  });

  test('a scope appended after the signature does not change what is shown', async ({ page }) => {
    await openConsent(page, { scope: 'openid', unsigned: '&scope=tinycloud:mcp%20offline_access' });
    await expect(page.getByText('wants to verify your identity', { exact: true })).toBeVisible();
    await expect(page.getByText(mcpLine, { exact: true })).toHaveCount(0);
    await expect(page.getByText(stayLine, { exact: true })).toHaveCount(0);
  });

  test('identity-only consent shows neither line and keeps the identity header and note', async ({ page }) => {
    await openConsent(page, { scope: 'openid email tinycloud:identity', redirectUri: 'https://viewer.example.test/cb' });
    await expect(page.getByText(mcpLine, { exact: true })).toHaveCount(0);
    await expect(page.getByText(stayLine, { exact: true })).toHaveCount(0);
    await expect(page.getByText('wants to verify your identity', { exact: true })).toBeVisible();
    await expect(page.getByText('wants to connect to your TinyCloud')).toHaveCount(0);
    await expect(page.getByText("This app can't sign anything or use your TinyCloud data.", { exact: true })).toBeVisible();
  });
});
