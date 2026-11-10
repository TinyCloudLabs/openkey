// The approval page's sign path answers 409 or 410 in the owner's words: any
// 409 says the request is already being approved, a 410 says it has already
// been answered or has ended, and the server's own text is never shown. Other
// statuses keep the server text. The screenshots (SHOT_DIR) are the 390px
// phone width.
import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const fragment = `#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const path = `/a/${id}`;
const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const CAPS_READ = 'tinycloud.capabilities/read';
const KV_GET = 'tinycloud.kv/get';
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

function prepared() {
  const siwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
    'Resources:',
    `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] }, [`${space}/kv/notes/`]: { [KV_GET]: [{}] } })}`,
  ].join('\n');
  const option = (service: string, short: string, p: string, ability: string, required: boolean) => {
    const optionKey = `${service}\0${space}\0${p}`;
    return { key: optionKey, service: short, path: p, label: short, resourcePath: p ? `${short}/${p}` : short,
      actions: [{ key: `${optionKey}\0${ability}`, action: ability.split('/')[1], ability, required }] };
  };
  const permissions = [option('tinycloud.capabilities', 'capabilities', '', CAPS_READ, true), option('tinycloud.kv', 'kv', 'notes/', KV_GET, false)];
  return {
    prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

const BUSY = 'This request is already being approved. Wait a moment.';
const ENDED = 'This request has already been answered or has ended.';

/** Answers the page's calls. `delegate` answers the POST /api/delegate (Approve). */
async function serve(page: Page, options: { delegate?: { status: number; body: unknown } } = {}) {
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    }
    if (url.pathname === '/api/keys') {
      return json(route, 200, { keys: [{ id: 'key_0', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }] });
    }
    if (url.pathname === `/api/approval-requests/${id}/load`) {
      const request = { targetDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
        nodeOrigin: 'https://node.tinycloud.xyz', permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] }],
        grantLifetimeSeconds: 7200, reason: 'Read notes for two hours' };
      return json(route, 200, { requestId: id, expiresAt: new Date(Date.now() + 3600_000).toISOString(), approved: false, denied: false, request });
    }
    if (url.pathname === '/api/delegate' && route.request().method() === 'POST') {
      return options.delegate ? json(route, options.delegate.status, options.delegate.body)
        : json(route, 200, { hostActivated: true, delegationHeader: { Authorization: 'x' }, delegationCid: 'bafy-delegation' });
    }
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared());
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
}

const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });

async function openReview(page: Page, options: { delegate?: { status: number; body: unknown } } = {}) {
  await serve(page, options);
  await page.goto(path + fragment);
  await expect(approve(page)).toBeEnabled();
}

test.describe('Approve on the approval-request review page', () => {
  test('a 409 with approval_in_progress shows the busy wording, not the server text', async ({ page }) => {
    await openReview(page, { delegate: { status: 409, body: { code: 'approval_in_progress', error: 'Approval request is already being approved' } } });
    await approve(page).click();
    await expect(page.getByRole('alert')).toHaveText(BUSY);
    await expect(page.getByText('Approval request is already being approved')).toHaveCount(0);
  });

  test('a bare 409 shows the busy wording', async ({ page }) => {
    await openReview(page, { delegate: { status: 409, body: { error: 'Conflict' } } });
    await approve(page).click();
    await expect(page.getByRole('alert')).toHaveText(BUSY);
    await expect(page.getByText('Conflict')).toHaveCount(0);
  });

  test('a 410 with expired_request shows the ended wording, not the server text', async ({ page }) => {
    await openReview(page, { delegate: { status: 410, body: { code: 'expired_request', error: 'Approval request is no longer pending' } } });
    await approve(page).click();
    await expect(page.getByRole('alert')).toHaveText(ENDED);
    await expect(page.getByText('Approval request is no longer pending')).toHaveCount(0);
  });

  test('other statuses show the generic line, not the server text', async ({ page }) => {
    await openReview(page, { delegate: { status: 500, body: { error: 'delegation service unavailable' } } });
    await approve(page).click();
    await expect(page.getByRole('alert')).toHaveText('Delegation failed');
    await expect(page.getByText('delegation service unavailable')).toHaveCount(0);
  });
});

for (const [name, reply] of [
  ['busy', { status: 409, body: { code: 'approval_in_progress', error: 'Approval request is already being approved' } }],
  ['ended', { status: 410, body: { code: 'expired_request', error: 'Approval request is no longer pending' } }],
] as const) {
  test(`screenshots at 390: the ${name} message`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await openReview(page, { delegate: reply });
    await approve(page).click();
    await expect(page.getByRole('alert')).toBeVisible();
    const shots = process.env.SHOT_DIR;
    if (shots) await page.screenshot({ path: `${shots}/approve-${name}-390.png`, fullPage: false });
  });
}
