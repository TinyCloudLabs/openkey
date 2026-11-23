import { test, expect, type Page } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const day = 86_400;
const address = '0x0123456789012345678901234567890123456789';
const space = `tinycloud:pkh:eip155:1:${address}:applications`;
const ability = 'tinycloud.capabilities/read';
const optionKey = `tinycloud.capabilities\0${space}\0`;
const actionKey = `${optionKey}\0${ability}`;
const finite = { choice: 'finite' } as const;
type Choice = typeof finite | { choice: 'leased'; leaseLifetimeSeconds: number; sensitiveConfirmed?: true };
const leased: Choice = { choice: 'leased', leaseLifetimeSeconds: 90 * day };
const failedMessage = "OpenKey couldn't set up renewal. Nothing was approved. Try again.";

function message(seconds: number) {
  return [
    'openkey.so wants you to sign in with your Ethereum account:', address, '', '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-11-23T13:00:00.000Z',
    `Expiration Time: ${new Date(Date.parse('2026-11-23T13:00:00.000Z') + seconds * 1000).toISOString()}`,
    'Resources:', `- ${makeRecapResource({ [`${space}/capabilities`]: { [ability]: [{}] } })}`,
  ].join('\n');
}

async function setup(page: Page, { available = true, standing = true, sensitive = false, failFirst = false } = {}) {
  const requests: { prepares: Array<{ renewal?: Choice }>; approvals: Array<{ revision: number; digest: string; renewal?: Choice }> } = {
    prepares: [], approvals: [],
  };
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return route.fulfill({ json: {
      session: { id: 'session', userId: 'user', expiresAt: new Date(Date.now() + 3600_000).toISOString() },
      user: { id: 'user', name: 'Native User', email: 'native@example.test' },
    } });
    if (path === '/api/account/terms') return route.fulfill({ json: TERMS_ACCEPTED });
    if (path.endsWith('/branding')) return route.fulfill({ json: { clientId: 'native-client', name: 'TinyChat', icon: null } });
    if (path.endsWith('/prepare')) {
      const body = route.request().postDataJSON() as { renewal?: Choice };
      const revision = requests.prepares.push(body);
      const renewal = available ? body.renewal ?? finite : undefined;
      const ttlSeconds = renewal?.choice === 'leased' ? day : 3600;
      return route.fulfill({ json: {
        requestId: 'standing-request', kind: 'SIGNIN', revision, digest: `digest-${revision}`,
        client: { name: 'TinyChat' }, address, keyId: 'managed', redirectScheme: 'xyz.tinycloud.test',
        tinycloudHost: 'https://node.tinycloud.xyz', hostPlan: null, ttlSeconds, grantLifetimeSeconds: 30 * day,
        sessionSiwe: message(ttlSeconds), selectedActionKeys: [actionKey], permissionOptions: [
          { key: optionKey, service: 'capabilities', path: '', label: 'Capabilities', resourcePath: 'capabilities',
            actions: [{ key: actionKey, action: 'read', ability, required: true }] },
        ],
        renewalAvailable: available, renewal, renewalPurpose: standing ? 'standing' : 'task',
        renewalMaxLeaseLifetimeSeconds: 182 * day, renewalSensitiveConfirmationRequired: sensitive,
      } });
    }
    if (path.endsWith('/approve')) {
      const count = requests.approvals.push(route.request().postDataJSON());
      if (count === 1 && failFirst) return route.fulfill({ status: 503, json: { error: 'renewal_failed', error_description: failedMessage } });
      return route.fulfill({ json: { status: 'APPROVED', hosting: 'existing' } });
    }
    if (path.endsWith('/oauth2/consent')) return route.fulfill({ json: { url: 'https://example.test/callback?code=ok' } });
    return route.fulfill({ status: 404, json: { error: `unmocked ${path}` } });
  });
  await page.route('https://example.test/**', route => route.fulfill({ status: 200, body: 'App' }));
  await page.goto('/oauth/consent?client_id=native-client&tinycloud_request=standing-request&sig=test');
  return requests;
}

test('a standing ask prepares the lease and unticking after a setup failure approves a finite window', async ({ page }) => {
  const requests = await setup(page, { failFirst: true });
  const box = page.getByRole('checkbox', { name: 'Renew access automatically' });
  await expect(box).toBeChecked();
  await expect(page.getByText('Your TinyCloud node renews this access for up to 90 days.')).toBeVisible();
  const details = page.locator('details.details');
  await details.locator(':scope > summary').click();
  await expect(details.getByText('Each renewal lasts', { exact: true })).toBeVisible();
  await expect(details.getByText('Each renewal lasts up to 1 day.', { exact: true })).toBeVisible();
  expect(requests.prepares.map(body => body.renewal)).toEqual([undefined, leased]);
  const allow = page.getByRole('button', { name: 'Allow', exact: true });
  await allow.click();
  await expect(page.getByRole('alert')).toHaveText(failedMessage);
  expect(requests.approvals[0]).toMatchObject({ revision: 2, digest: 'digest-2', renewal: leased, sessionSiwe: message(day) });
  await box.click();
  await expect(box).not.toBeChecked();
  await allow.click();
  await page.waitForURL('https://example.test/callback?code=ok');
  expect(requests.approvals[1]).toMatchObject({ revision: 3, digest: 'digest-3', renewal: finite, sessionSiwe: message(3600) });
});

test('sensitive renewal is explicit and increasing its duration requires confirming the new term', async ({ page }) => {
  const requests = await setup(page, { sensitive: true });
  const box = page.getByRole('checkbox', { name: 'Renew access automatically' });
  await expect(box).toBeVisible();
  await expect(box).not.toBeChecked();
  await box.click();
  const confirmation = page.getByRole('alertdialog', { name: 'Renew sensitive access?' });
  await expect(confirmation).toBeVisible();
  await expect(confirmation.getByText('This lets TinyChat keep the sensitive access listed here for up to 90 days. You can stop renewal under Renewing permissions in Settings.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeDisabled();
  expect(requests.prepares).toHaveLength(1);
  await page.getByRole('button', { name: 'Turn on renewal' }).click();
  await expect(box).toBeChecked();
  await page.getByText('Renewal duration', { exact: true }).click();
  await page.getByRole('button', { name: '6 months', exact: true }).click();
  await expect(confirmation).toContainText('up to 6 months');
  await page.getByRole('button', { name: 'Turn on renewal' }).click();
  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await page.waitForURL('https://example.test/callback?code=ok');
  expect(requests.prepares.map(body => body.renewal)).toEqual([
    undefined, { ...leased, sensitiveConfirmed: true }, { choice: 'leased', leaseLifetimeSeconds: 182 * day, sensitiveConfirmed: true },
  ]);
  expect(requests.approvals[0]).toMatchObject({ revision: 3, digest: 'digest-3', renewal: requests.prepares[2]!.renewal });
});

test('a task ask starts unchecked and an unavailable offer has no control', async ({ page }) => {
  const task = await setup(page, { standing: false });
  const box = page.getByRole('checkbox', { name: 'Renew access automatically' });
  await expect(box).toBeVisible();
  await expect(box).not.toBeChecked();
  expect(task.prepares).toHaveLength(1);
  await page.unroute('**/api/**');
  const unavailable = await setup(page, { available: false });
  await expect(page.getByRole('heading', { name: 'TinyChat wants access' })).toBeVisible();
  await expect(box).toHaveCount(0);
  expect(unavailable.prepares).toHaveLength(1);
});
