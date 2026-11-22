// A one-tap request to use one named secret (read `vault/secrets/NAME` and decrypt on that secret's own key) gets its own heading and rows.
// Its signer is not a listed TinyCloud One key, so the page names no requester and says it is not verified.
// Every API call is answered by `page.route`; no API server runs.

import { expect, test, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { approvalLink, mockApi } from './approval-end-pages-fixtures';
import { approve, delegation } from './approval-code-fixtures';
import { ORIGIN } from './e2e-port';

const DAY = 86_400;
const ID = 'abcdefghijklmnopqrstuvwxyz';
const ADDRESS = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const AUDIENCE = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const KV_GET = 'tinycloud.kv/get';

const notes = { service: 'tinycloud.kv', space: SPACE, path: 'notes/', ability: KV_GET, resource: `${SPACE}/kv/notes/` };
const SECRETS = `tinycloud:pkh:eip155:1:${ADDRESS}:secrets`;
const secret = { service: 'tinycloud.kv', space: SECRETS, path: 'vault/secrets/OPENAI_API_KEY', ability: KV_GET, resource: `${SECRETS}/kv/vault/secrets/OPENAI_API_KEY` };
const secretKey = `urn:tinycloud:encryption:${OWNER}:default/secrets/openai_api_key`;
const decrypt = {
  service: 'tinycloud.encryption',
  space: 'encryption',
  path: secretKey,
  ability: 'tinycloud.encryption/decrypt',
  resource: secretKey,
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
          issuer: AUDIENCE, targetDid: AUDIENCE, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
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

const DECRYPT_NOTE = 'Lets it open only this secret.';

test('one named secret: plain heading and rows, no requester claimed', async ({ page }) => {
  await openReview(page, { grants: [secret, decrypt] });
  const dialog = page.getByRole('dialog');
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  await expect(dialog.getByRole('heading', { level: 2 })).toHaveText('A request to use one secret');
  await expect(dialog).toContainText('Review it, choose how long, then approve.');
  await expect(dialog).toContainText('Requested by Not verified');
  await expect(dialog).toContainText('OpenKey can’t confirm who made this link.');
  await expect(dialog).not.toContainText('TinyCloud One');
  await expect(dialog).not.toContainText('TinyCloud CLI');
  await expect(page.getByRole('region', { name: 'Delegation destination' }).getByText('Returned to')).toHaveCount(0);
  await expect(dialog.locator('.summary-statement .statement-primary')).toHaveText(['Read the secret OPENAI_API_KEY']);
  await expect(dialog.locator('.summary-statement').nth(0)).toContainText(DECRYPT_NOTE);
});

test('anything beyond the one secret keeps the ordinary heading and rows', async ({ page }) => {
  await openReview(page, { grants: [secret, decrypt, notes] });
  const dialog = page.getByRole('dialog');
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  await expect(dialog.getByRole('heading', { level: 2 })).toHaveText('Authorize capabilities');
  await expect(dialog).toContainText('Review the access this app is asking for.');
  await expect(dialog).toContainText('Read the secret OPENAI_API_KEY');
  await expect(dialog).not.toContainText(DECRYPT_NOTE);
});

test('an unverified approval ends without naming anyone to go back to', async ({ page }) => {
  await mockApi(page, { signedIn: true, approveReply: { status: 200, body: delegation } });
  await page.goto(approvalLink);
  await approve(page);
  await expect(page.getByRole('heading', { name: 'Approved. Go back to your agent.' })).toBeVisible();
  await expect(page.getByText('You can close this window.', { exact: true })).toBeVisible();
  await expect(page.getByText(/TinyCloud CLI|the CLI/)).toHaveCount(0);
});
