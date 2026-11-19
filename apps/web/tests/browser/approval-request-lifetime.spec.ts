import { expect, test, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { ORIGIN } from './e2e-port';

const DAY = 86_400;
const ID = 'abcdefghijklmnopqrstuvwxyz';
const ADDRESS = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const AUDIENCE = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const KV_GET = 'tinycloud.kv/get';
const ONCE_NOTE = '1 hour is the most for a request that includes secrets or decryption.';

const notes = { service: 'tinycloud.kv', space: SPACE, path: 'notes/', ability: KV_GET, resource: `${SPACE}/kv/notes/` };
const secret = { service: 'tinycloud.kv', space: SPACE, path: 'vault/secrets/DEPLOY_KEY', ability: KV_GET, resource: `${SPACE}/kv/vault/secrets/DEPLOY_KEY` };
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
} = {}) {
  const {
    grants = [notes], grantLifetimeSeconds = 30 * DAY, suggestedLifetimeSeconds, rejectOncePreview = false,
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
  await expect(line(page)).toHaveText(/^This permission expires in 30 days, on /);
  await expect(page.getByText('How long it lasts', { exact: true })).toBeHidden();
  await expect(page.getByTestId('approval-expiry-once-note')).toHaveCount(0);
  expect(expiries.at(-1)).toBe(`${30 * DAY}s`);
  await testInfo.attach('30-day approval face', { body: await line(page).innerText(), contentType: 'text/plain' });
  await testInfo.attach('30-day approval face', { body: await page.screenshot(), contentType: 'image/png' });
});

for (const [name, grants] of [['secrets', [notes, secret]], ['decrypt', [notes, decrypt]]] as const) {
  test(`one ${name} grant starts the entire 30-day request at one hour and explains why`, async ({ page }, testInfo) => {
    const expiries = await openReview(page, { grants: [...grants] });
    const note = page.getByTestId('approval-expiry-once-note');
    await expect(approve(page)).toBeEnabled();
    await expect(line(page)).toHaveText('These permissions expire in 1 hour');
    await expect(note).toBeVisible();
    await expect(note).toHaveText(ONCE_NOTE);
    expect(expiries.at(-1)).toBe('3600s');
    await testInfo.attach(`${name} approval face`, {
      body: `${await line(page).innerText()}\n${await note.innerText()}`, contentType: 'text/plain',
    });

    if (name === 'secrets') {
      await testInfo.attach('secrets approval face', { body: await page.screenshot(), contentType: 'image/png' });
    }

    const fold = await openFold(page);
    await expect(fold.getByRole('button', { name: '24 hours' })).toHaveCount(0);
    await fold.getByLabel('Or type a time').fill('2h');
    await fold.getByRole('button', { name: 'Set' }).click();
    const limit = fold.getByRole('alert');
    await expect(limit).toHaveText('This approval can last up to 1 hour.');
    expect(expiries.at(-1)).toBe('3600s');
    if (name === 'secrets') {
      await testInfo.attach('secrets expiry limit', { body: await limit.innerText(), contentType: 'text/plain' });
      await testInfo.attach('secrets expiry limit', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
    }

    await fold.getByLabel('Or type a time').fill('30m');
    await fold.getByRole('button', { name: 'Set' }).click();
    await expect(approve(page)).toBeEnabled();
    await expect(line(page)).toHaveText('These permissions expire in 30 minutes');
    expect(expiries.at(-1)).toBe('1800s');
  });
}

test('the fold can shorten a 30-day suggestion but cannot use the longer signed maximum', async ({ page }) => {
  const expiries = await openReview(page, { grantLifetimeSeconds: 60 * DAY, suggestedLifetimeSeconds: 30 * DAY });
  await expect(approve(page)).toBeEnabled();
  await expect(line(page)).toContainText('30 days');

  const fold = await openFold(page);
  await fold.getByLabel('Or type a time').fill('31d');
  await fold.getByRole('button', { name: 'Set' }).click();
  await expect(fold.getByRole('alert')).toHaveText('This approval can last up to 30 days.');
  expect(expiries.at(-1)).toBe(`${30 * DAY}s`);

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
