import { createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, type JsonWebKey, type KeyObject } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const id = 'device-renewal-fixture';
const address = '0x1111111111111111111111111111111111111111';
const owner = `did:pkh:eip155:1:${address}`;
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const host = 'https://node.tinycloud.xyz';
const did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) };
const permissions = [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }];
const renewal = {
  version: 1, approvedLeaseLifetimeSeconds: 30 * 86_400, approvedAt: '2026-11-23T13:00:00.000Z',
  receipt: {
    originalCid: 'grant-cid', leaseCid: 'lease-cid', leaseAuthorization: 'signed-lease',
    leaseExpiresAt: '2026-12-23T13:00:00.000Z', leaseGeneration: 1,
    nodeIdentity: { nodeDid: 'node-did', renewerDid: 'renewer-did' },
  },
};
const renewalFailures = [
  { status: 503, code: 'renewal_failed', error: "OpenKey couldn't set up renewal. This device is waiting for your approval. You can approve it without renewal." },
  { status: 400, code: 'renewal_disabled', error: "Renewal isn't available for this sign-in. You can approve it without renewal." },
] as const;
type Choice = { choice: 'finite' | 'leased'; leaseLifetimeSeconds?: number; sensitiveConfirmed?: true };
const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });
const renewalBox = (page: Page) => page.locator('input.renewal-box');

function relayPayload(relay: { ephemeralPublicJwk: JsonWebKey; nonce: string; ciphertext: string }, privateKey: KeyObject) {
  const publicKey = createPublicKey({ key: relay.ephemeralPublicJwk, format: 'jwk' });
  const shared = diffieHellman({ privateKey, publicKey });
  const key = Buffer.from(hkdfSync('sha256', shared, id, 'openkey-device-relay-v1', 32));
  const ciphertext = Buffer.from(relay.ciphertext, 'base64url');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(relay.nonce, 'base64url'));
  decipher.setAAD(Buffer.from(id));
  decipher.setAuthTag(ciphertext.subarray(-16));
  return JSON.parse(Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]).toString());
}

async function openDevice(page: Page, options: { ask?: boolean; sensitive?: boolean; keyType?: 'EXTERNAL' | 'MANAGED'; setupFailure?: typeof renewalFailures[number]; suggestedTtlSeconds?: number } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const choices: Array<Choice | undefined> = [];
  const grantWindows: string[] = [];
  let relayApproval: Record<string, any> | undefined;
  let expiresAt = '';
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const { pathname } = new URL(request.url());
    if (pathname === '/api/auth/get-session') return route.fulfill({ json: {
      session: { id: 'phone', userId: 'owner', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
      user: { id: 'owner', name: 'Owner', email: 'owner@example.test' },
    } });
    if (pathname === '/api/keys') return route.fulfill({ json: { keys: [{
      id: 'key', address, publicKey: address, keyIndex: 0, label: null, keyType: options.keyType ?? 'MANAGED',
      isPrimary: true, createdAt: new Date().toISOString(),
    }] } });
    if (pathname === '/api/device-authorizations/lookup') return route.fulfill({ json: {
      id, userCode: 'ABCDEFGH', sessionDid: did, publicJwk: jwk, relayPublicJwk: publicKey.export({ format: 'jwk' }),
      permissions, nodeOrigin: host, shareOrigin: 'https://share.tinycloud.xyz', delegationTtlSeconds: 30 * 86_400,
      suggestedTtlSeconds: options.suggestedTtlSeconds,
      transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(),
      delegationExpiresAt: new Date(Date.now() + (30 * 86_400 + 600) * 1000).toISOString(),
      ...(options.ask === false ? {} : { renewal: { version: 1, leaseLifetimeSeconds: 30 * 86_400 } }),
    } });
    if (pathname === '/api/delegate/prepare') {
      const body = request.postDataJSON();
      choices.push(body.renewal);
      grantWindows.push(body.expiry);
      expect(body.deviceTransactionId).toBe(id);
      const issuedAt = new Date();
      expiresAt = new Date(issuedAt.getTime() + Number.parseInt(body.expiry, 10) * 1000).toISOString();
      const att: Record<string, Record<string, unknown[]>> = { [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}] } };
      if (options.sensitive) att[`urn:tinycloud:encryption:${owner}:default/secrets/fixture`] = { 'tinycloud.encryption/decrypt': [{}] };
      const siwe = [
        'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '', '',
        `URI: ${did}`, 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
        `Issued At: ${issuedAt.toISOString()}`, `Expiration Time: ${expiresAt}`,
        'Resources:', `- ${makeRecapResource(att)}`,
      ].join('\n');
      const groupKey = `tinycloud.kv\0${space}\0notes/`;
      const actionKey = `${groupKey}\0tinycloud.kv/get`;
      return route.fulfill({ json: {
        prepared: { siwe, spaceId: space, jwk }, spaceId: space, ownerDid: owner, address, chainId: 1,
        host, permissions: [{ key: groupKey, service: 'kv', path: 'notes/', label: 'kv', resourcePath: 'kv/notes/',
          actions: [{ key: actionKey, action: 'get', ability: 'tinycloud.kv/get', required: false }] }],
        selectedActionKeys: [actionKey], authorizationContext: { token: 'bound-preview' },
      } });
    }
    if (pathname === '/api/delegate') {
      expect(request.postDataJSON()).toMatchObject({ authorizationContextToken: 'bound-preview', deviceTransactionId: id });
      expect(request.postDataJSON()).not.toHaveProperty('renewal');
      if (options.setupFailure && choices.at(-1)?.choice === 'leased') {
        const { status, code, error } = options.setupFailure;
        return route.fulfill({ status, json: { code, error } });
      }
      return route.fulfill({ json: { hostActivated: true, expiresAt, permissions, delegationCid: 'grant-cid',
        ...(choices.at(-1)?.choice === 'leased' ? { renewal } : { renewal: null, renewalReason: 'renewal_declined' }),
      } });
    }
    if (pathname === `/api/device-authorizations/${id}/approve`) {
      relayApproval = request.postDataJSON();
      return route.fulfill({ json: { approved: true } });
    }
    return route.fulfill({ json: {} });
  });
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await page.goto('/device?user_code=ABCD-EFGH');
  await page.getByRole('link', { name: 'Yes, it matches. Review the request' }).click();
  await expect(approve(page)).toBeEnabled();
  return { choices, grantWindows, payload: () => relayApproval ? relayPayload(relayApproval.relay, privateKey) : null, approval: () => relayApproval };
}

test('starts with renewal on and encrypts the signed receipt with the device grant', async ({ page }) => {
  const device = await openDevice(page);
  await expect(renewalBox(page)).toBeChecked();
  await expect(page.getByTestId('approval-expiry-line')).toHaveText('This permission renews automatically for up to 30 days.');
  expect(device.choices.at(-1)).toEqual({ choice: 'leased', leaseLifetimeSeconds: 30 * 86_400 });
  expect(device.grantWindows.at(-1)).toBe('3600s');
  await approve(page).click();
  await expect.poll(device.payload).toMatchObject({ renewal, delegationCid: 'grant-cid' });
  expect(device.approval()).toMatchObject({ binding: { transactionId: id, sessionDid: did, nodeOrigin: host, permissions } });
  expect(device.approval()).not.toHaveProperty('renewal');
  expect(JSON.stringify(device.approval())).not.toContain('signed-lease');
});

for (const failure of renewalFailures) {
  test(`shows ${failure.code} and delivers finite approval after unticking`, async ({ page }) => {
    const device = await openDevice(page, { setupFailure: failure });
    await expect(renewalBox(page)).toBeChecked();
    await approve(page).click();
    await expect(page.getByText(failure.error, { exact: true })).toBeVisible();
    expect(device.approval()).toBeUndefined();
    await renewalBox(page).uncheck();
    await expect(approve(page)).toBeEnabled();
    await expect(page.getByTestId('approval-expiry-line')).toHaveText("This device's access to your data lasts 1 hour.");
    expect(device.choices.at(-1)).toEqual({ choice: 'finite' });
    await approve(page).click();
    await expect.poll(device.payload).toMatchObject({ renewal: null, renewalReason: 'renewal_declined' });
  });
}

test('starts sensitive grants unticked and binds explicit confirmation with the shorter signed window', async ({ page }) => {
  const device = await openDevice(page, { sensitive: true });
  await expect(renewalBox(page)).not.toBeChecked();
  expect(device.choices.at(-1)).toEqual({ choice: 'finite' });
  await renewalBox(page).click();
  await expect(page.getByRole('alertdialog', { name: 'Renew sensitive access?' })).toContainText('Each renewal lasts up to 7 days.');
  await page.getByRole('button', { name: 'Turn on renewal' }).click();
  await expect(renewalBox(page)).toBeChecked();
  expect(device.choices.at(-1)).toEqual({ choice: 'leased', leaseLifetimeSeconds: 30 * 86_400, sensitiveConfirmed: true });
  expect(device.grantWindows.at(-1)).toBe('3600s');
});

test('shows the wallet note and binds finite approval for an external key', async ({ page }) => {
  const device = await openDevice(page, { keyType: 'EXTERNAL' });
  await expect(renewalBox(page)).toHaveCount(0);
  await expect(page.getByText("Your wallet signs in for a set time, so this device's access ends at the time shown.")).toBeVisible();
  expect(device.choices.at(-1)).toEqual({ choice: 'finite' });
});

test('has no renewal choice for an older transaction', async ({ page }) => {
  const device = await openDevice(page, { ask: false });
  await expect(renewalBox(page)).toHaveCount(0);
  expect(device.choices.at(-1)).toBeUndefined();
});

for (const [suggestedDays, windowDays] of [[2, 2], [7, 7], [14, 7]] as const) {
  test(`uses a ${windowDays}-day renewable window for a ${suggestedDays}-day suggestion and restores the finite default`, async ({ page }) => {
    const device = await openDevice(page, { suggestedTtlSeconds: suggestedDays * 86_400 });
    await expect(renewalBox(page)).toBeChecked();
    expect(device.grantWindows.at(-1)).toBe(`${windowDays * 86_400}s`);
    await expect(page.getByRole('region', { name: 'Device request' })).toContainText(`${windowDays} days`);

    await renewalBox(page).uncheck();
    await expect(approve(page)).toBeEnabled();
    expect(device.choices.at(-1)).toEqual({ choice: 'finite' });
    expect(device.grantWindows.at(-1)).toBe('3600s');
    await expect(page.getByTestId('approval-expiry-line')).toHaveText("This device's access to your data lasts 1 hour.");
  });
}

test('keeps an explicit one-hour window when the owner toggles renewal', async ({ page }) => {
  const device = await openDevice(page, { suggestedTtlSeconds: 7 * 86_400 });
  expect(device.grantWindows.at(-1)).toBe('604800s');
  await page.getByText('Advanced details', { exact: true }).click();
  await page.getByText('How long it lasts', { exact: true }).click();
  await page.getByRole('button', { name: '1 hour', exact: true }).click();
  await expect(approve(page)).toBeEnabled();
  expect(device.grantWindows.at(-1)).toBe('3600s');

  await renewalBox(page).uncheck();
  await expect(approve(page)).toBeEnabled();
  expect(device.grantWindows.at(-1)).toBe('3600s');
  await renewalBox(page).check();
  await expect(approve(page)).toBeEnabled();
  expect(device.choices.at(-1)?.choice).toBe('leased');
  expect(device.grantWindows.at(-1)).toBe('3600s');
});
