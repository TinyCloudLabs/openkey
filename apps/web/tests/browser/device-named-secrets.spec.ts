import { expect, test } from '@playwright/test';

test.use({ viewport: { width: 390, height: 844 } });

test('the device screen lists each named secret and the decrypt lifetime', async ({ page }) => {
  const permissions = [
    { service: 'tinycloud.capabilities', space: 'secrets', path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/FIRST_KEY', actions: ['tinycloud.kv/get'] },
    { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/SECOND_KEY', actions: ['tinycloud.kv/put', 'tinycloud.kv/list'] },
    { service: 'tinycloud.kv', space: 'secrets', path: 'vault/secrets/', actions: ['tinycloud.kv/list'] },
    { service: 'tinycloud.encryption', space: 'default', path: '', actions: ['tinycloud.encryption/decrypt'] },
  ];
  await page.route('**/api/**', async (route) => {
    const { pathname } = new URL(route.request().url());
    if (pathname === '/api/auth/get-session') return route.fulfill({ json: null });
    if (pathname !== '/api/device-authorizations/lookup') return route.fulfill({ json: {} });
    return route.fulfill({ json: {
      id: 'device-fixture', userCode: 'ABCDEFGH', sessionDid: 'did:key:z6MkFixture',
      publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, relayPublicJwk: {},
      permissions,
      nodeOrigin: 'https://node.example.test', shareOrigin: 'https://share.example.test',
      delegationTtlSeconds: 604_800,
      suggestedTtlSeconds: 1_800,
      transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(),
      delegationExpiresAt: new Date(Date.now() + 605_400_000).toISOString(),
    } });
  });

  await page.goto('/device?user_code=ABCD-EFGH');
  const access = page.getByRole('list', { name: 'Requested access' }).getByRole('listitem');
  await expect(access).toHaveCount(5);
  await expect(access.nth(0)).toContainText('FIRST_KEY · Read');
  await expect(access.nth(1)).toContainText('SECOND_KEY · Write, List');
  await expect(access.nth(2)).toContainText('See the names of all your secrets (not their contents)');
  await expect(access.nth(3)).toContainText('Decrypt protected data for 30 minutes');
});
