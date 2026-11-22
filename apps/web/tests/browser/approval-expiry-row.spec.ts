import { expect, test } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { address, approvalLink, json, mockApi } from './approval-end-pages-fixtures';
import { ORIGIN } from './e2e-port';

test('the approval face and Expires row use the same prepared lifetime', async ({ page }, testInfo) => {
  const day = 86_400;
  const issuedAt = new Date('2026-11-19T20:00:00.000Z');
  const expiresAt = (seconds: number) => new Date(issuedAt.getTime() + seconds * 1000).toISOString();
  const space = `tinycloud:pkh:eip155:1:${address}:default`;
  const audience = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const ability = 'tinycloud.kv/get';
  const permissionKey = `tinycloud.kv\0${space}\0notes/`;
  const actionKey = `${permissionKey}\0${ability}`;
  const started = Promise.withResolvers<void>();
  const response = Promise.withResolvers<void>();

  await mockApi(page, { signedIn: true });
  await page.clock.setFixedTime(issuedAt);
  await page.route('**/api/approval-requests/*/load', (route) => json(route, 200, {
    expiresAt: expiresAt(3600),
    request: {
      targetDid: audience,
      targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
      nodeOrigin: ORIGIN,
      permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [ability] }],
      grantLifetimeSeconds: 30 * day,
    },
  }));
  await page.route('**/api/delegate/prepare', async (route) => {
    const { expiry } = route.request().postDataJSON() as { expiry: string };
    const seconds = Number(expiry.slice(0, -1));
    if (seconds === day) {
      started.resolve();
      await response.promise;
    }
    const siwe = [
      'app.example.test wants you to sign in with your Ethereum account:', address, '',
      `URI: ${audience}#${audience.slice('did:key:'.length)}`,
      'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', `Issued At: ${issuedAt.toISOString()}`,
      `Expiration Time: ${expiresAt(seconds)}`, 'Resources:',
      `- ${makeRecapResource({ [`${space}/kv/notes/`]: { [ability]: [{}] } })}`,
    ].join('\n');
    return json(route, 200, {
      prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, address, chainId: 1,
      permissions: [{
        key: permissionKey, service: 'kv', path: 'notes/', resourcePath: 'kv/notes/',
        actions: [{ key: actionKey, action: 'get', ability, required: false }],
      }],
      selectedActionKeys: [actionKey],
      authorizationContext: { token: 'preview', expiresAt: issuedAt.getTime() + 600_000, baselineAbilitiesDigest: 'digest' },
    });
  });

  await page.goto(approvalLink);
  const face = page.getByTestId('approval-expiry-line');
  const expiryRow = page.getByRole('region', { name: 'Signing identity' }).locator('.row').filter({
    has: page.getByText('Expires', { exact: true }),
  });
  const expiryValue = expiryRow.locator('.value');
  await expect(face).toHaveText(/^This app's access to your data lasts 30 days, until /);
  await page.getByText('Advanced details', { exact: true }).click();
  await expect(expiryValue).toHaveText(expiresAt(30 * day));
  await testInfo.attach('30-day prepared expiry', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });

  await page.getByText('How long it lasts', { exact: true }).click();
  const oneDay = page.getByRole('button', { name: '24 hours', exact: true });
  await oneDay.click();
  try {
    await started.promise;
    await expect(oneDay).toBeDisabled();
    expect(await face.innerText()).toMatch(/^This app's access to your data lasts 30 days, until /);
    await expect(expiryValue).toHaveText(expiresAt(30 * day));
  } finally {
    response.resolve();
  }

  await expect(face).toHaveText("This app's access to your data lasts 1 day.");
  await expect(expiryValue).toHaveText(expiresAt(day));
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  await testInfo.attach('shortened prepared expiry', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
});
