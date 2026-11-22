// TC-3800: a signed approval request for one secret's own key (`default/secrets/<name>`) starts at what the app
// suggested and may be lengthened up to what it signed, never past 7 days; a whole-network decrypt starts at one hour
// and shows the all-secrets card. Every API call is answered by `page.route`; no API server runs.

import { expect, test, type Locator, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { ORIGIN } from './e2e-port';
import { TERMS_ACCEPTED } from './terms-fixtures';

const HOUR = 3_600;
const DAY = 86_400;
const ID = 'abcdefghijklmnopqrstuvwxyz';
const ADDRESS = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const SECRETS = `tinycloud:pkh:eip155:1:${ADDRESS}:secrets`;
const AUDIENCE = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const DECRYPT = 'tinycloud.encryption/decrypt';

const secret = {
  service: 'tinycloud.kv', space: SECRETS, path: 'vault/secrets/OPENAI_API_KEY', ability: 'tinycloud.kv/get',
  resource: `${SECRETS}/kv/vault/secrets/OPENAI_API_KEY`,
};
const network = `urn:tinycloud:encryption:${OWNER}:default`;
const secretKey = `${network}/secrets/openai_api_key`;
const keyDecrypt = { service: 'tinycloud.encryption', space: 'encryption', path: secretKey, ability: DECRYPT, resource: secretKey };
const keyCreate = { service: 'tinycloud.encryption', space: 'encryption', path: secretKey, ability: 'tinycloud.encryption/key.create', resource: secretKey };
const networkDecrypt = { service: 'tinycloud.encryption', space: 'encryption', path: network, ability: DECRYPT, resource: network };

function respond(route: Route, body: unknown, status = 200) {
  return route.fulfill({ status, json: body });
}

async function openReview(page: Page, options: {
  grants: (typeof secret)[];
  grantLifetimeSeconds: number;
  suggestedLifetimeSeconds?: number;
}) {
  const { grants, grantLifetimeSeconds, suggestedLifetimeSeconds } = options;
  const expiries: string[] = [];
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) return route.abort();
    if (!url.pathname.startsWith('/api/')) return route.continue();

    const now = Date.now();
    if (url.pathname === '/api/auth/get-session') {
      return respond(route, {
        session: { id: 'session', userId: 'owner', expiresAt: new Date(now + 3_600_000).toISOString() },
        user: { id: 'owner', email: 'owner@example.test' },
      });
    }
    if (url.pathname === '/api/keys') {
      return respond(route, { keys: [{
        id: 'key', address: ADDRESS, publicKey: '0x', keyIndex: 0, label: null,
        keyType: 'MANAGED', isPrimary: true, createdAt: new Date(now).toISOString(),
      }] });
    }
    if (url.pathname === `/api/approval-requests/${ID}/load`) {
      return respond(route, {
        requestId: ID, expiresAt: new Date(now + 3_600_000).toISOString(), approved: false,
        request: {
          targetDid: AUDIENCE, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
          nodeOrigin: ORIGIN, reason: 'Read one secret',
          grantLifetimeSeconds, suggestedLifetimeSeconds,
          permissions: grants.map(({ service, space, path, ability }) => ({ service, space, path, actions: [ability] })),
        },
      });
    }
    if (url.pathname === '/api/delegate/prepare') {
      const { expiry } = route.request().postDataJSON() as { expiry: string };
      expiries.push(expiry);
      const recap = makeRecapResource(Object.fromEntries(grants.map(({ resource, ability }) => [resource, { [ability]: [{}] }])));
      const expiration = new Date(now + Number(expiry.slice(0, -1)) * 1000);
      const siwe = [
        'app.example.test wants you to sign in with your Ethereum account:', ADDRESS, '',
        `URI: ${AUDIENCE}#${AUDIENCE.slice('did:key:'.length)}`,
        'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', `Issued At: ${new Date(now).toISOString()}`,
        `Expiration Time: ${expiration.toISOString()}`, 'Resources:', `- ${recap}`,
      ].join('\n');
      const permissions = grants.map(({ service, space, path, ability }) => {
        const key = `${service}\0${space}\0${path}`;
        const short = service.slice('tinycloud.'.length);
        return {
          key, service: short, path, label: short, resourcePath: `${short}/${path}`,
          actions: [{ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required: false }],
        };
      });
      return respond(route, {
        prepared: { siwe, spaceId: SPACE, jwk: {} }, spaceId: SPACE, ownerDid: OWNER, address: ADDRESS, chainId: 1,
        permissions, selectedActionKeys: permissions.flatMap((permission) => permission.actions.map((action) => action.key)),
        authorizationContext: { token: 'preview', expiresAt: now + 600_000, baselineAbilitiesDigest: 'digest' },
      });
    }
    return respond(route, { error: `Unmocked ${url.pathname}` }, 404);
  });
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));

  await page.goto(`/a/${ID}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`);
  return expiries;
}

const line = (page: Page) => page.getByTestId('approval-expiry-line');
const lengthNote = (page: Page) => page.getByTestId('approval-expiry-length-note');
const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });

async function openFold(page: Page) {
  await page.getByText('Advanced details', { exact: true }).click();
  await page.getByText('How long it lasts', { exact: true }).click();
  return page.getByRole('group', { name: /Expires after/ });
}

async function typeTime(fold: Locator, value: string) {
  await fold.getByLabel('Or type a time').fill(value);
  await fold.getByRole('button', { name: 'Set' }).click();
}

test('one secret\'s key starts at the suggested hour and may be lengthened up to the signed 7 days', async ({ page }, testInfo) => {
  const expiries = await openReview(page, { grants: [secret, keyDecrypt], grantLifetimeSeconds: 7 * DAY, suggestedLifetimeSeconds: HOUR });
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toHaveText("This app's access to your data lasts 1 hour.");
  await expect(lengthNote(page)).toHaveText('This request starts at 1 hour, as the app asked. You can choose up to 7 days.');
  await expect(page.getByTestId('approval-expiry-once-note')).toHaveCount(0);
  await expect(page.getByTestId('all-secrets-card')).toHaveCount(0);
  await expect(page.getByRole('dialog').locator('.summary-statement .statement-primary')).toHaveText(['Read the secret OPENAI_API_KEY']);
  await expect(page.getByRole('dialog')).toContainText('Lets it open only this secret.');
  expect(expiries.at(-1)).toBe(`${HOUR}s`);
  await testInfo.attach('one secret, 1 hour of 7 days', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });

  const fold = await openFold(page);
  await typeTime(fold, '3d');
  await expect(line(page)).toContainText('3 days');
  expect(expiries.at(-1)).toBe(`${3 * DAY}s`);

  await typeTime(fold, '8d');
  await expect(fold.getByRole('alert')).toHaveText('This approval can last up to 7 days.');
  expect(expiries.at(-1)).toBe(`${3 * DAY}s`);
});

test('a request that starts at its 7-day maximum says so, and still offers shorter', async ({ page }) => {
  const expiries = await openReview(page, { grants: [secret, keyDecrypt], grantLifetimeSeconds: 7 * DAY, suggestedLifetimeSeconds: 7 * DAY });
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toContainText('7 days');
  await expect(lengthNote(page)).toHaveText("This request lasts 7 days, as the app asked. That's the most it can be.");
  expect(expiries.at(-1)).toBe(`${7 * DAY}s`);

  const fold = await openFold(page);
  await fold.getByRole('button', { name: '24 hours', exact: true }).click();
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toHaveText("This app's access to your data lasts 1 day.");
  expect(expiries.at(-1)).toBe(`${DAY}s`);
});

test('an app that signs 30 days for a secret gets 7 days at most', async ({ page }) => {
  const expiries = await openReview(page, { grants: [secret, keyDecrypt], grantLifetimeSeconds: 30 * DAY });
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toContainText('7 days');
  await expect(lengthNote(page)).toHaveText("This request lasts 7 days, as the app asked. That's the most it can be.");
  expect(expiries.at(-1)).toBe(`${7 * DAY}s`);

  const fold = await openFold(page);
  await typeTime(fold, '8d');
  await expect(fold.getByRole('alert')).toHaveText('This approval can last up to 7 days.');
  expect(expiries.at(-1)).toBe(`${7 * DAY}s`);
});

test('an app that signs 30 days to create a key for a secret gets 7 days at most', async ({ page }) => {
  const expiries = await openReview(page, { grants: [secret, keyCreate], grantLifetimeSeconds: 30 * DAY });
  await expect(approve(page)).toBeEnabled();
  const fold = await openFold(page);
  await typeTime(fold, '8d');
  await expect(fold.getByRole('alert')).toHaveText('This approval can last up to 7 days.');
  await typeTime(fold, '7d');
  await expect(fold.getByRole('alert')).toHaveCount(0);
  expect(expiries.at(-1)).toBe(`${7 * DAY}s`);
});

test('decrypt on the whole network starts at one hour and shows the all-secrets card', async ({ page }, testInfo) => {
  const expiries = await openReview(page, { grants: [secret, networkDecrypt], grantLifetimeSeconds: 7 * DAY, suggestedLifetimeSeconds: HOUR });
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toHaveText("This app's access to your data lasts 1 hour.");
  await expect(lengthNote(page)).toHaveCount(0);
  const card = page.getByTestId('all-secrets-card');
  await expect(card.getByRole('heading')).toHaveText('Let this app open all your encrypted data?');
  await expect(card).toContainText("That covers every secret and everything else you've encrypted in TinyCloud. Allow this only for an app you trust.");
  await expect(card).toContainText("OpenKey can't confirm which site asked.");
  await expect(page.getByRole('dialog')).not.toContainText('Read the secret OPENAI_API_KEY');
  expect(expiries.at(-1)).toBe(`${HOUR}s`);
  await testInfo.attach('whole network, all-secrets card', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });

  const fold = await openFold(page);
  await typeTime(fold, '2h');
  await expect(fold.getByRole('alert')).toHaveText('This approval can last up to 1 hour.');
  expect(expiries.at(-1)).toBe(`${HOUR}s`);
});

// Every grant OpenKey shows as all secrets: `secrets` itself, a prefix under it, or a path that only reads as one of
// them once lower-cased and percent-decoded. The API's /prepare refuses each of these today; the page still never
// shows them as one secret if bytes carrying one reach it.
for (const rest of [
  '/secrets/', '/secrets', '/secrets/scoped/work/', '/secrets/scoped/', '/Secrets/', '/SECRETS/', '/SECRETS/x',
  '/Secrets/openai_api_key', '/secrets%2F', '/secrets%2f', '/secrets%2Fopenai_api_key', '/secrets%2fx',
]) {
  test(`decrypt on default${rest} shows the all-secrets card, never the one-secret card`, async ({ page }) => {
    const resource = `${network}${rest}`;
    const decrypt = { service: 'tinycloud.encryption', space: 'encryption', path: resource, ability: DECRYPT, resource };
    const expiries = await openReview(page, { grants: [secret, decrypt], grantLifetimeSeconds: 7 * DAY, suggestedLifetimeSeconds: 7 * DAY });
    await expect(approve(page)).toBeEnabled();
    const card = page.getByTestId('all-secrets-card');
    await expect(card.getByRole('heading')).toHaveText('Let this app read all your secrets?');
    await expect(page.getByRole('dialog')).not.toContainText('Read the secret OPENAI_API_KEY');
    await expect(page.getByRole('dialog')).not.toContainText('Lets it open only this secret.');
    await expect(page.getByRole('dialog')).not.toContainText(/to use one secret/);
    await expect(line(page)).toHaveText("This app's access to your data lasts 1 hour.");
    expect(expiries.at(-1)).toBe(`${HOUR}s`);
  });
}

test("one secret's own key still shows the one-secret card, with no all-secrets card", async ({ page }) => {
  await openReview(page, { grants: [secret, keyDecrypt], grantLifetimeSeconds: 7 * DAY, suggestedLifetimeSeconds: 7 * DAY });
  await expect(approve(page)).toBeEnabled();
  await expect(page.getByTestId('all-secrets-card')).toHaveCount(0);
  await expect(page.getByRole('dialog').locator('.summary-statement .statement-primary')).toHaveText(['Read the secret OPENAI_API_KEY']);
  await expect(page.getByRole('dialog')).toContainText('Lets it open only this secret.');
  await expect(page.getByRole('dialog')).toContainText(/to use one secret/);
});
