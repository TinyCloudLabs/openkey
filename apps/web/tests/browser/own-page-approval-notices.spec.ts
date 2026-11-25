// TC-4115: on OpenKey's own approval pages, the owner is told that approving creates their TinyCloud space only when the server
// says the approval sets it up, and that the requester's name and reason are the requester's own words. A link says how it returns the delegation, so the server can tell
// an owner approving a CLI link from a link that is neither. Real pages, API fixtures only.
import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { ORIGIN } from './e2e-port';
import { TERMS_ACCEPTED } from './terms-fixtures';

const ID = 'abcdefghijklmnopqrstuvwxyz';
const ADDRESS = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const AUDIENCE = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const KV_GET = 'tinycloud.kv/get';
const NOTES = { service: 'tinycloud.kv', space: SPACE, path: 'notes/', ability: KV_GET, resource: `${SPACE}/kv/notes/` };

const CREATES = 'Approving also creates your TinyCloud space, where your data from this request is kept.';
const NO_SPACE_NOTE = /If you don't have a TinyCloud space|approving creates one/;
const REQUESTER_TEXT = "Written by whoever sent this request. OpenKey can't confirm it.";
const UNVERIFIED_LINK = 'OpenKey can’t confirm who made this link.';

type SpaceSetup = { space: string; plan: 'setup' | 'auto-sign-off' | 'no-setup' | 'external-wallet' };

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

/** What /prepare returns for one `notes/` read, with the notice the server chose for this account (or none). */
function prepareResponse(spaceSetup: SpaceSetup | null) {
  const now = Date.now();
  const recap = makeRecapResource({ [NOTES.resource]: { [KV_GET]: [{}] } });
  const siwe = [
    'app.example.test wants you to sign in with your Ethereum account:', ADDRESS, '',
    '',
    `URI: ${AUDIENCE}#${AUDIENCE.slice('did:key:'.length)}`,
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', `Issued At: ${new Date(now).toISOString()}`,
    `Expiration Time: ${new Date(now + 3_600_000).toISOString()}`, 'Resources:', `- ${recap}`,
  ].join('\n');
  const key = `${NOTES.service}\0${NOTES.space}\0${NOTES.path}`;
  const permissions = [{
    key, service: 'kv', path: NOTES.path, label: 'kv', resourcePath: `kv/${NOTES.path}`,
    actions: [{ key: `${key}\0${KV_GET}`, action: 'get', ability: KV_GET, required: false }],
  }];
  return {
    prepared: { siwe, spaceId: SPACE, jwk: {} }, spaceId: SPACE, ownerDid: OWNER, address: ADDRESS, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions,
    selectedActionKeys: permissions.flatMap((permission) => permission.actions.map((action) => action.key)),
    authorizationContext: { token: 'preview', expiresAt: now + 600_000, baselineAbilitiesDigest: 'digest' },
    ...(spaceSetup ? { spaceSetup } : {}),
  };
}

/** Answers every API call; returns the bodies the page sent to /prepare. */
async function mockApi(page: Page, spaceSetup: SpaceSetup | null) {
  const prepareBodies: Array<Record<string, unknown>> = [];
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) return route.abort();
    if (!url.pathname.startsWith('/api/')) return route.continue();
    const now = Date.now();
    if (url.pathname === '/api/auth/get-session') {
      return json(route, {
        session: { id: 'session', userId: 'owner', expiresAt: new Date(now + 3_600_000).toISOString() },
        user: { id: 'owner', email: 'owner@example.test' },
      });
    }
    if (url.pathname === '/api/keys') {
      return json(route, { keys: [{
        id: 'key', address: ADDRESS, publicKey: '0x', keyIndex: 0, label: null,
        keyType: 'MANAGED', isPrimary: true, createdAt: new Date(now).toISOString(),
      }] });
    }
    if (url.pathname === '/api/account/terms') return json(route, TERMS_ACCEPTED);
    if (url.pathname === `/api/approval-requests/${ID}/load`) {
      return json(route, {
        requestId: ID, expiresAt: new Date(now + 3_600_000).toISOString(), approved: false,
        request: {
          issuer: AUDIENCE, targetDid: AUDIENCE, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
          nodeOrigin: ORIGIN, reason: 'Read app data', grantLifetimeSeconds: 30 * 86_400,
          permissions: [{ service: NOTES.service, space: NOTES.space, path: NOTES.path, actions: [KV_GET] }],
        },
      });
    }
    if (url.pathname === '/api/delegate/prepare') {
      prepareBodies.push(route.request().postDataJSON() as Record<string, unknown>);
      return json(route, prepareResponse(spaceSetup));
    }
    return json(route, { error: `Unmocked ${url.pathname}` }, 404);
  });
  return prepareBodies;
}

const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const linkPath = (extra = '') => `/delegate?did=did:key:z6Mk&jwk=${jwk}${extra}`;
const approveButton = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });
const requestPath = `/a/${ID}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;

async function shot(page: Page, name: string) {
  if (process.env.TC4115_SCREEN_DIR) await page.screenshot({ path: `${process.env.TC4115_SCREEN_DIR}/${name}-390.png`, fullPage: true });
}

const OLD_REASON_NOTE = 'This reason comes from the caller and is not verified.';

/** The requester's reason is shown with the one label, and nothing else on the page says it a second time. */
async function expectReasonLabel(page: Page, reason: string) {
  const box = page.getByRole('region', { name: 'Reason for request' });
  await expect(box).toContainText(reason);
  await expect(box).toContainText(REQUESTER_TEXT);
  await expect(page.getByText(REQUESTER_TEXT)).toHaveCount(1);
  await expect(page.getByText(OLD_REASON_NOTE)).toHaveCount(0);
}

test.use({ viewport: { width: 390, height: 844 } });

test.describe('an approval request page', () => {
  test('says who wrote the request text, and says nothing about creating a space when the server reports no setup', async ({ page }) => {
    const bodies = await mockApi(page, null);
    await page.goto(requestPath);
    await expect(approveButton(page)).toBeEnabled();

    // The server reports no space to set up (a reviewer, or a space that exists): the page does not say one is created.
    await expect(page.getByText(NO_SPACE_NOTE)).toHaveCount(0);
    await expect(page.getByText(CREATES)).toHaveCount(0);
    await expectReasonLabel(page, 'Read app data');
    // The unverified-link line stays as it is.
    await expect(page.getByRole('dialog')).toContainText(UNVERIFIED_LINK);
    // A signed request carries its own attribution: the page never sends a link delivery for it.
    expect(bodies.length).toBeGreaterThan(0);
    for (const body of bodies) expect(body).not.toHaveProperty('linkDelivery');
    await shot(page, 'approval-request');
  });

  test('says approving creates the space when the account is known to have none', async ({ page }) => {
    await mockApi(page, { space: 'default', plan: 'setup' });
    await page.goto(requestPath);
    await expect(approveButton(page)).toBeEnabled();

    await expect(page.getByRole('note').filter({ hasText: CREATES })).toHaveText(CREATES);
    await expect(page.getByText(NO_SPACE_NOTE)).toHaveCount(0);
    await shot(page, 'approval-request-creates');
  });
});

test.describe('a link', () => {
  test('a CLI link that returns to a loopback listener says it returns by callback', async ({ page }) => {
    const callback = 'http://127.0.0.1:8123/callback';
    const bodies = await mockApi(page, { space: 'default', plan: 'setup' });
    await page.goto(linkPath(`&callback=${encodeURIComponent(callback)}&reason=${encodeURIComponent('Sync notes from my laptop')}`));
    await expect(approveButton(page)).toBeEnabled();

    expect(bodies.at(-1)).toMatchObject({ linkDelivery: 'callback', linkCallback: callback });
    await expect(page.getByRole('note').filter({ hasText: CREATES })).toHaveText(CREATES);
    await expectReasonLabel(page, 'Sync notes from my laptop');
    await shot(page, 'link-callback');
  });

  test('a link with no callback says it is pasted', async ({ page }) => {
    const bodies = await mockApi(page, { space: 'default', plan: 'setup' });
    await page.goto(linkPath());
    await expect(approveButton(page)).toBeEnabled();

    expect(bodies.at(-1)).toMatchObject({ linkDelivery: 'paste' });
    expect(bodies.at(-1)).not.toHaveProperty('linkCallback');
  });

  test('a link the server will not set an account up for does not promise a setup', async ({ page }) => {
    await mockApi(page, { space: 'default', plan: 'no-setup' });
    await page.goto(linkPath('&callback=' + encodeURIComponent('https://mcp.tinycloud.xyz/chatgpt/connect/callback')));
    await expect(approveButton(page)).toBeEnabled();

    await expect(page.getByText(CREATES)).toHaveCount(0);
    await expect(page.getByText(NO_SPACE_NOTE)).toHaveCount(0);
    await expect(page.getByRole('note').filter({ hasText: "Approving this link won't set it up." })).toBeVisible();
    await shot(page, 'link-no-setup');
  });
});

test.describe('a device request', () => {
  const DEVICE_REASON = 'Sync my notes';

  test('the code page and the review page label the reason the same way', async ({ page }) => {
    await mockApi(page, null);
    await page.route('**/api/device-authorizations/lookup?*', (route) => route.fulfill({ json: {
      id: 'device-fixture', userCode: 'ABCDEFGH', sessionDid: AUDIENCE,
      publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
      relayPublicJwk: { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'A'.repeat(43) },
      permissions: [{ service: NOTES.service, space: NOTES.space, path: NOTES.path, actions: [KV_GET] }],
      reason: DEVICE_REASON, nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz',
      delegationTtlSeconds: 30 * 86_400,
      transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(),
      delegationExpiresAt: new Date(Date.now() + (30 * 86_400 + 600) * 1000).toISOString(),
    } }));
    await page.goto('/device?user_code=ABCD-EFGH');
    await expect(page.getByText(DEVICE_REASON)).toBeVisible();
    await expect(page.getByText(REQUESTER_TEXT)).toHaveCount(1);
    await expect(page.getByText(OLD_REASON_NOTE)).toHaveCount(0);
    await shot(page, 'device-code');

    await page.getByRole('link', { name: 'Yes, it matches. Review the request' }).click();
    await expect(approveButton(page)).toBeEnabled();
    await expectReasonLabel(page, DEVICE_REASON);
    await expect(page.getByText(NO_SPACE_NOTE)).toHaveCount(0);
    await expect(page.getByText(CREATES)).toHaveCount(0);
    await shot(page, 'device-review');
  });
});
