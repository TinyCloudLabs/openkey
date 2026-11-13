import { expect, test, type Page } from '@playwright/test';

test.use({ viewport: { width: 390, height: 844 } });

const address = '0x1111111111111111111111111111111111111111';
const space = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
const permissions = ['default', 'secrets'].flatMap((name) => [
  { service: 'tinycloud.kv', space: space(name), path: 'notes/', actions: ['tinycloud.kv/get'] },
  { service: 'tinycloud.capabilities', space: space(name), path: '', actions: ['tinycloud.capabilities/read'] },
]);

async function deviceApi(page: Page, options: { signedIn?: boolean; admin?: boolean; max?: number; suggested?: number; multiSpace?: boolean; reason?: string; lookupStatus?: number; malformed?: boolean } = {}) {
  const max = options.max ?? 604_800;
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/device-authorizations/lookup' && options.lookupStatus && options.lookupStatus !== 200) {
      return route.fulfill({ status: options.lookupStatus, json: { error: 'private upstream detail' } });
    }
    let body: unknown = {};
    if (path === '/api/auth/get-session') body = options.signedIn ? {
      session: { id: 'session-fixture', userId: 'owner-fixture', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
      user: { id: 'owner-fixture', name: 'QA owner', email: 'owner@example.test' },
    } : null;
    else if (path === '/api/organizations') body = { organizations: [{ id: 'org-fixture', role: options.admin ? 'ADMIN' : 'MEMBER' }] };
    else if (path === '/api/device-authorizations/lookup') body = {
      id: 'device-fixture', userCode: 'ABCDEFGH', sessionDid: 'did:key:z6MkFixture',
      publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, relayPublicJwk: {},
      permissions: options.malformed ? null : options.multiSpace ? permissions : permissions.slice(0, 2),
      nodeOrigin: 'https://node.example.test', shareOrigin: 'https://share.example.test',
      delegationTtlSeconds: max,
      ...(options.suggested !== undefined ? { suggestedTtlSeconds: options.suggested } : {}),
      ...(options.reason !== undefined ? { reason: options.reason } : {}),
      transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(),
      delegationExpiresAt: new Date(Date.now() + (max + 600) * 1000).toISOString(),
    };
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
  });
}

test('a signed-in multi-space device request stays renderable', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await deviceApi(page, { signedIn: true, multiSpace: true });
  await page.goto('/device?user_code=ABCD-EFGH');
  await expect(page.locator('main h1')).toBeVisible();
  await expect(page.locator('a[href^="/delegate?"]')).toBeVisible();
  expect(errors).toEqual([]);
});

for (const signedIn of [false, true]) {
  test(`non-admin navigation stays hidden (${signedIn ? 'member' : 'signed out'})`, async ({ page }) => {
    await deviceApi(page, { signedIn });
    await page.goto('/device');
    await expect(page.locator('main h1')).toBeVisible();
    await expect(page.getByRole('link', { name: 'OpenKey Admin console' })).toHaveCount(0);
  });
}

test('server-confirmed admins retain their console navigation', async ({ page }) => {
  await deviceApi(page, { signedIn: true, admin: true });
  await page.goto('/device');
  await expect(page.getByRole('link', { name: 'OpenKey Admin console' })).toBeVisible();
});

for (const [max, suggested, expected] of [[604_800, undefined, 3_600], [604_800, 1_800, 1_800], [600, undefined, 600]] as const) {
  test(`device default is the shortest offered lifetime (${max}/${suggested ?? 'none'})`, async ({ page }) => {
    await deviceApi(page, { max, suggested });
    await page.goto('/device?user_code=ABCD-EFGH');
    await expect(page.locator('a[href^="/delegate?"]')).toBeVisible();
    const href = await page.locator('a[href^="/delegate?"]').getAttribute('href');
    const selected = new URL(href!, 'https://openkey.example.test').searchParams.get('expiry');
    expect(selected).toBe(`${expected}s`);
    expect(expected).toBeLessThanOrEqual(max);
  });
}

test('a transient lookup failure offers recovery without exposing the upstream detail', async ({ page }) => {
  const options = { lookupStatus: 503 };
  await deviceApi(page, options);
  await page.goto('/device?user_code=ABCD-EFGH');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('alert')).not.toContainText('private upstream detail');
  await expect(page.locator('a[href^="/delegate?"]')).toHaveCount(0);
  options.lookupStatus = 200;
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.locator('a[href^="/delegate?"]')).toBeVisible();
});

test('an expired request cannot be retried as an approval', async ({ page }) => {
  await deviceApi(page, { lookupStatus: 404 });
  await page.goto('/device?user_code=ABCD-EFGH');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Try again' })).toHaveCount(0);
  await expect(page.locator('a[href^="/delegate?"]')).toHaveCount(0);
});

test('a request that cannot render fails closed and can recover', async ({ page }) => {
  const options = { malformed: true };
  await deviceApi(page, options);
  await page.goto('/device?user_code=ABCD-EFGH');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.locator('main h1')).toBeVisible();
  await expect(page.locator('a[href^="/delegate?"]')).toHaveCount(0);
  options.malformed = false;
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.locator('a[href^="/delegate?"]')).toBeVisible();
});
