import { expect, test, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { ORIGIN } from './e2e-port';
import { TERMS_ACCEPTED } from './terms-fixtures';

const DAY = 86_400;
const ID = 'abcdefghijklmnopqrstuvwxyz';
const ADDRESS = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const AUDIENCE = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const KV_GET = 'tinycloud.kv/get';

const notes = { service: 'tinycloud.kv', space: SPACE, path: 'notes/', ability: KV_GET, resource: `${SPACE}/kv/notes/` };
const SECRETS_SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:secrets`;
const secret = { service: 'tinycloud.kv', space: SECRETS_SPACE, path: 'vault/secrets/', ability: KV_GET, resource: `${SECRETS_SPACE}/kv/vault/secrets/` };
const network = `urn:tinycloud:encryption:${OWNER}:default`;
const decrypt = {
  service: 'tinycloud.encryption',
  space: 'encryption',
  path: network,
  ability: 'tinycloud.encryption/decrypt',
  resource: network,
};

function respond(route: Route, body: unknown, status = 200) {
  return route.fulfill({ status, json: body });
}

async function openReview(page: Page, options: {
  grants?: (typeof notes)[];
  grantLifetimeSeconds?: number;
  suggestedLifetimeSeconds?: number;
  rejectOncePreview?: boolean;
  rejectExpiry?: string;
} = {}) {
  const {
    grants = [notes], grantLifetimeSeconds = 30 * DAY, suggestedLifetimeSeconds, rejectOncePreview = false, rejectExpiry,
  } = options;
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
          nodeOrigin: ORIGIN, reason: 'Read app data',
          grantLifetimeSeconds, suggestedLifetimeSeconds,
          permissions: grants.map(({ service, space, path, ability }) => ({ service, space, path, actions: [ability] })),
        },
      });
    }
    if (url.pathname === '/api/delegate/prepare') {
      const { expiry } = route.request().postDataJSON() as { expiry: string };
      expiries.push(expiry);
      if (rejectOncePreview && expiry === '3600s') return respond(route, { error: 'Preview unavailable' }, 500);
      // Only a re-prepare fails: the first preview of the request must still open the review.
      if (rejectExpiry === expiry && expiries.length > 1) return respond(route, { error: 'Preview unavailable' }, 500);

      const recap = makeRecapResource(Object.fromEntries(grants.map(({ resource, ability }) => [resource, { [ability]: [{}] }])));
      const expiration = new Date(now + Number(expiry.slice(0, -1)) * 1000);
      const siwe = [
        'app.example.test wants you to sign in with your Ethereum account:', ADDRESS, '',
        '',
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
const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });

async function openFold(page: Page) {
  await page.getByText('Advanced details', { exact: true }).click();
  await page.getByText('How long it lasts', { exact: true }).click();
  return page.getByRole('group', { name: /Expires after/ });
}

test('the approval face shows the requested 30 days', async ({ page }, testInfo) => {
  const expiries = await openReview(page);
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toHaveText(/^This app's access to your data lasts 30 days, until /);
  await expect(page.getByText('How long it lasts', { exact: true })).toBeHidden();
  await expect(page.getByTestId('approval-expiry-once-choice')).toHaveCount(0);
  expect(expiries.at(-1)).toBe(`${30 * DAY}s`);
  await testInfo.attach('30-day approval face', { body: await line(page).innerText(), contentType: 'text/plain' });
  await testInfo.attach('30-day approval face', { body: await page.screenshot(), contentType: 'image/png' });
});

for (const [name, grants] of [['secrets', [notes, secret]], ['decrypt', [notes, decrypt]]] as const) {
  test(`one ${name} grant starts the entire 30-day request at one hour and explains why`, async ({ page }, testInfo) => {
    const expiries = await openReview(page, { grants: [...grants] });
    const secrets = name === 'secrets';
    const choice = page.getByRole('group', { name: secrets ? 'How long access lasts' : 'How long', exact: true });
    const caution = page.getByTestId(secrets ? 'approval-expiry-compact-caution' : 'approval-expiry-once-caution');
    const lengthText = secrets ? page.getByTestId('approval-expiry-announcement') : line(page);
    await expect(approve(page)).toBeEnabled();
    if (secrets) await expect(lengthText).toHaveText(/^Access lasts 1 hour, until /);
    else await expect(lengthText).toHaveText("This app's access to your data lasts 1 hour.");
    await expect(choice).toBeVisible();
    await expect(choice.getByRole('radio', { name: '1 hour' })).toBeChecked();
    await expect(choice.getByRole('radio', { name: secrets ? '7 days' : '7 days (the longest allowed)', exact: true })).not.toBeChecked();
    await expect(caution).toHaveText(secrets ? 'Covers every secret in your vault.' : 'This access can open all your encrypted data.');
    expect(expiries.at(-1)).toBe('3600s');
    await testInfo.attach(`${name} approval face`, {
      body: `${await lengthText.innerText()}\n${await choice.innerText()}\n${await caution.innerText()}`, contentType: 'text/plain',
    });

    if (name === 'secrets') {
      await testInfo.attach('secrets approval face', { body: await page.screenshot(), contentType: 'image/png' });
    }

    const fold = await openFold(page);
    await expect(fold.getByRole('button', { name: '24 hours' })).toBeVisible();
    await fold.getByLabel('Or type a time').fill('2h');
    await fold.getByRole('button', { name: 'Set' }).click();
    if (secrets) await expect(page.getByTestId('approval-expiry-length-line')).toHaveText(/^Access lasts 2 hours, until /);
    else await expect(line(page)).toHaveText("This app's access to your data lasts 2 hours.");
    expect(expiries.at(-1)).toBe('7200s');
    await fold.getByLabel('Or type a time').fill('31d');
    await fold.getByRole('button', { name: 'Set' }).click();
    const limit = fold.getByRole('alert');
    await expect(limit).toHaveText('This approval can last up to 7 days.');
    expect(expiries.at(-1)).toBe('7200s');
    if (name === 'secrets') {
      await testInfo.attach('secrets expiry limit', { body: await limit.innerText(), contentType: 'text/plain' });
      await testInfo.attach('secrets expiry limit', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
    }

    await fold.getByLabel('Or type a time').fill('30m');
    await fold.getByRole('button', { name: 'Set' }).click();
    await expect(approve(page)).toBeEnabled();
    if (secrets) await expect(page.getByTestId('approval-expiry-length-line')).toHaveText(/^Access lasts 30 minutes, until /);
    else await expect(line(page)).toHaveText("This app's access to your data lasts 30 minutes.");
    expect(expiries.at(-1)).toBe('1800s');
  });
}

test('the one-time choice on an approval request sends the length it shows, and 1 hour again sends 1 hour', async ({ page }) => {
  const expiries = await openReview(page, { grants: [notes, decrypt] });
  const choice = page.getByRole('group', { name: 'How long', exact: true });
  await expect(choice.getByRole('radio', { name: '1 hour' })).toBeChecked();
  await choice.getByRole('radio', { name: '7 days (the longest allowed)' }).check();
  await expect(choice.getByRole('radio', { name: '7 days (the longest allowed)' })).toBeChecked();
  await expect(line(page)).toContainText('7 days');
  expect(expiries.at(-1)).toBe(`${7 * DAY}s`);
  await choice.getByRole('radio', { name: '1 hour' }).check();
  await expect(choice.getByRole('radio', { name: '1 hour' })).toBeChecked();
  await expect(line(page)).toHaveText("This app's access to your data lasts 1 hour.");
  expect(expiries.at(-1)).toBe('3600s');
  await expect(page.getByTestId('approval-expiry-once-caution')).toBeVisible();
});

test('an approval request that asked for exactly 7 days reads what the app asked', async ({ page }) => {
  await openReview(page, { grants: [notes, decrypt], grantLifetimeSeconds: 7 * DAY });
  await expect(page.getByRole('group', { name: 'How long', exact: true }).getByRole('radio', { name: '7 days (what the app asked)' })).not.toBeChecked();
});

test('the fold can lengthen a suggestion up to the signed maximum', async ({ page }) => {
  const expiries = await openReview(page, { grantLifetimeSeconds: 60 * DAY, suggestedLifetimeSeconds: 30 * DAY });
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toContainText('30 days');

  const fold = await openFold(page);
  await fold.getByLabel('Or type a time').fill('31d');
  await fold.getByRole('button', { name: 'Set' }).click();
  await expect(line(page)).toContainText('31 days');
  expect(expiries.at(-1)).toBe(`${31 * DAY}s`);

  await fold.getByRole('button', { name: '7 days', exact: true }).click();
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toContainText('7 days');
  expect(expiries.at(-1)).toBe(`${7 * DAY}s`);
});

test('a failed one-hour preview leaves the longer secrets approval unavailable', async ({ page }) => {
  const expiries = await openReview(page, { grants: [notes, secret], rejectOncePreview: true });
  await expect.poll(() => expiries.at(-1)).toBe('3600s');
  await expect(page.getByRole('alert')).toContainText('(Error 500)');
  await expect(approve(page)).toBeDisabled();
  await expect(line(page)).toHaveCount(0);
});

// TC-4156: a length the owner picked but that could not be prepared is not what will be signed; the radios show
// the length that was prepared last.
test('a failed re-prepare leaves the one-time choice on the length that will be signed', async ({ page }) => {
  const expiries = await openReview(page, { grants: [notes, decrypt], rejectExpiry: `${7 * DAY}s` });
  const choice = page.getByRole('group', { name: 'How long', exact: true });
  await expect(choice.getByRole('radio', { name: '1 hour' })).toBeChecked();
  await choice.getByRole('radio', { name: '7 days (the longest allowed)' }).click();
  await expect.poll(() => expiries.at(-1)).toBe(`${7 * DAY}s`);
  await expect(page.getByRole('alert')).toContainText('(Error 500)');
  await expect(choice.getByRole('radio', { name: '1 hour' })).toBeChecked();
  await expect(choice.getByRole('radio', { name: '7 days (the longest allowed)' })).not.toBeChecked();
  await expect(line(page)).toHaveText("This app's access to your data lasts 1 hour.");
});
