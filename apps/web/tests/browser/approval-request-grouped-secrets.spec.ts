import { expect, test, type Page } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { address, json } from './approval-end-pages-fixtures';
import { ORIGIN } from './e2e-port';
import { TERMS_ACCEPTED } from './terms-fixtures';

const id = 'abcdefghijklmnopqrstuvwxyz';
const owner = `did:pkh:eip155:1:${address}`;
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const audience = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const names = Array.from({ length: 25 }, (_, i) => `test_key_${String(i + 1).padStart(2, '0')}`);
const secretGrants = names.map((name) => {
  const path = `urn:tinycloud:encryption:${owner}:default/secrets/${name}`;
  return { service: 'tinycloud.encryption', space: 'encryption', path, resource: path, ability: 'tinycloud.encryption/decrypt' };
});
const notes = {
  service: 'tinycloud.kv', space, path: 'notes/', resource: `${space}/kv/notes/`, ability: 'tinycloud.kv/get',
};

async function openReview(page: Page, grants: typeof secretGrants) {
  const permissions = grants.map(({ service, space, path, ability }) => {
    const key = `${service}\0${space}\0${path}`;
    const short = service.slice('tinycloud.'.length);
    return {
      key, service: short, path, label: short, resourcePath: `${short}/${path}`,
      actions: [{ key: `${key}\0${ability}`, ability, action: ability.split('/')[1], required: false }],
    };
  });
  const actionKeys = permissions.map(({ actions }) => actions[0]!.key);
  const selections: string[][] = [];

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const now = Date.now();
    const issuedAt = new Date(now).toISOString();
    const expiresAt = new Date(now + 3_600_000).toISOString();
    if (path === '/api/account/terms') return json(route, 200, TERMS_ACCEPTED);
    if (path === '/api/auth/get-session') {
      return json(route, 200, {
        session: { id: 'session', userId: 'owner', expiresAt },
        user: { id: 'owner', email: 'owner@example.test' },
      });
    }
    if (path === '/api/keys') {
      return json(route, 200, { keys: [{
        id: 'key', address, publicKey: '0x', keyIndex: 0, label: null,
        keyType: 'MANAGED', isPrimary: true, createdAt: issuedAt,
      }] });
    }
    if (path === `/api/approval-requests/${id}/load`) {
      return json(route, 200, {
        requestId: id, expiresAt, approved: false, renewalAvailable: true,
        request: {
          targetDid: audience, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
          nodeOrigin: ORIGIN, grantLifetimeSeconds: 3_600,
          renewal: { version: 1, leaseLifetimeSeconds: 86_400 },
          permissions: grants.map(({ service, space, path, ability }) => ({ service, space, path, actions: [ability] })),
        },
      });
    }
    if (path === '/api/delegate/prepare') {
      const { actionKeys: selectedActionKeys = actionKeys } = route.request().postDataJSON() as { actionKeys?: string[] };
      selections.push(selectedActionKeys);
      const recap = makeRecapResource(Object.fromEntries(grants.flatMap(({ resource, ability }, i) =>
        selectedActionKeys.includes(actionKeys[i]!) ? [[resource, { [ability]: [{}] }]] : [],
      )));
      const siwe = [
        'app.example.test wants you to sign in with your Ethereum account:', address, '', '',
        `URI: ${audience}#${audience.slice('did:key:'.length)}`, 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
        `Issued At: ${issuedAt}`, `Expiration Time: ${expiresAt}`, 'Resources:', `- ${recap}`,
      ].join('\n');
      return json(route, 200, {
        prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: owner, address, chainId: 1,
        permissions, selectedActionKeys, edited: selectedActionKeys.length < actionKeys.length,
        authorizationContext: { token: 'preview', expiresAt: now + 600_000, baselineAbilitiesDigest: 'digest' },
      });
    }
    return json(route, 404, { error: `Unmocked ${path}` });
  });
  await page.goto(`/a/${id}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  return { actionKeys, selections };
}

const secretRows = (names: readonly string[]) => names.map((name) => `Read the secret ${name}`);
const requestedAccess = (page: Page) => page.getByRole('region', { name: 'Requested access' });

test('25 exact keys occupy one row and disclose each name', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openReview(page, secretGrants);
  const summary = requestedAccess(page);
  await expect(summary.locator('.summary-statement')).toHaveCount(1);
  await expect(summary.getByText('Read 25 secrets', { exact: true })).toBeVisible();
  await expect(summary.getByText(names[0]!, { exact: true })).toBeHidden();

  await summary.getByText('Show the secrets', { exact: true }).click();
  await expect(summary.locator('.secret-statements > li')).toHaveText(names);
  await expect(summary.locator('.secret-statements code.mono')).toHaveText(names);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await summary.getByText('Hide the secrets', { exact: true }).click();
  await expect(summary.getByText(names[0]!, { exact: true })).toBeHidden();

  await page.getByRole('checkbox').click();
  const confirm = page.getByRole('alertdialog', { name: 'Renew sensitive access?' });
  await expect(confirm).toHaveCount(1);
  await expect(confirm).toBeVisible();
  await confirm.getByRole('button', { name: "Don't renew" }).click();
  await expect(confirm).toHaveCount(0);
});

test('a mixed request keeps its other permission and can narrow one exact key', async ({ page }) => {
  const { selections, actionKeys } = await openReview(page, [...secretGrants, notes]);
  const summary = requestedAccess(page);
  await expect(summary.locator('.summary-statement')).toHaveCount(2);
  await expect(summary.getByText('Read application data', { exact: true })).toBeVisible();
  await expect(page.getByText('25 permissions are marked Sensitive', { exact: true })).toBeVisible();

  await page.getByText('Advanced details', { exact: true }).click();
  const exactGrants = page.getByRole('region', { name: 'Exact grants' });
  await exactGrants.getByRole('button', { name: 'Edit', exact: true }).click();
  const firstGrant = exactGrants.locator('.grant').filter({
    has: page.getByLabel(`Exact resource: ${secretGrants[0]!.path}`, { exact: true }),
  });
  await firstGrant.getByRole('checkbox').uncheck();
  await expect.poll(() => selections.at(-1)).toEqual(actionKeys.slice(1));
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  await expect(summary.getByText('Read 24 secrets', { exact: true })).toBeVisible();
  await expect(page.getByText('24 permissions are marked Sensitive', { exact: true })).toBeVisible();
  await summary.getByText('Show the secrets', { exact: true }).click();
  await expect(summary.locator('.secret-statements > li')).toHaveText(names.slice(1));
});

test('three exact keys retain their individual summary rows', async ({ page }) => {
  await openReview(page, secretGrants.slice(0, 3));
  const summary = requestedAccess(page);
  await expect(summary.locator('.summary-statement .statement-primary')).toHaveText(secretRows(names.slice(0, 3)));
  await expect(summary.getByText('Show the secrets', { exact: true })).toHaveCount(0);
});
