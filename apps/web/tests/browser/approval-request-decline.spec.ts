// TC-2459: an owner can decline an approval request from its review page. Every API call is answered by
// `page.route`; no API server runs. Buttons are found by role or test id; the sentences the owner reads are
// checked where they are the point of the test (the declined and failure messages).
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

type Options = { denied?: boolean; denyReplies?: Array<{ status: number; body: unknown } | 'network-failure'> };

/** Answers the page's calls and records them. `denyReplies` answers each press of Decline in order. */
async function serve(page: Page, options: Options = {}) {
  const calls: Array<{ path: string; body: unknown; url: string }> = [];
  const denyReplies = [...(options.denyReplies ?? [{ status: 200, body: { status: 'denied' } }])];
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    calls.push({ path: url.pathname, body: request.postDataJSON?.() ?? null, url: request.url() });
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    }
    if (url.pathname === '/api/keys') {
      return json(route, 200, { keys: [{ id: 'key_0', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }] });
    }
    if (url.pathname === `/api/approval-requests/${id}/load`) {
      return json(route, 200, {
        requestId: id, expiresAt: new Date(Date.now() + 3600_000).toISOString(), approved: false, denied: options.denied ?? false,
        request: { targetDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
          nodeOrigin: 'https://node.tinycloud.xyz', permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] }],
          grantLifetimeSeconds: 7200, reason: 'Read notes for two hours' },
      });
    }
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared());
    if (url.pathname === `/api/approval-requests/${id}/deny`) {
      const reply = denyReplies.shift() ?? { status: 200, body: { status: 'denied' } };
      if (reply === 'network-failure') return route.abort('failed');
      return json(route, reply.status, reply.body);
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  return calls;
}

const dismiss = (page: Page) => page.getByTestId('signing-dismiss');
const decline = (page: Page) => page.getByTestId('signing-decline');
const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });
const denies = <Call extends { path: string }>(calls: Call[]) => calls.filter((call) => call.path === `/api/approval-requests/${id}/deny`);
const DECLINED = 'Declined. You can close this page.';

async function openReview(page: Page, options: Options = {}) {
  const calls = await serve(page, options);
  await page.goto(path + fragment);
  await expect(approve(page)).toBeEnabled();
  return calls;
}

test.describe('Decline on the approval-request review page', () => {
  test('the card offers Decline left of Approve, and Back as a link above the pair', async ({ page }) => {
    await openReview(page);
    await expect(decline(page)).toBeVisible();
    const [declineBox, approveBox, backBox] = [await decline(page).boundingBox(), await approve(page).boundingBox(), await dismiss(page).boundingBox()];
    expect(declineBox!.x).toBeLessThan(approveBox!.x);
    expect(backBox!.y + backBox!.height).toBeLessThanOrEqual(declineBox!.y + 1);
  });

  test('one press makes exactly one /deny call with the link in the body only, then the page is declined', async ({ page }) => {
    const calls = await openReview(page);
    await decline(page).dblclick();
    await expect(page.getByText(DECLINED)).toBeVisible();
    expect(denies(calls)).toHaveLength(1);
    expect(denies(calls)[0]!.body).toEqual({ reference: path + fragment });
    // The key fragment never travels in a URL.
    for (const call of calls) expect(call.url).not.toContain(fragment.slice(1));
    await expect(approve(page)).toHaveCount(0);
    await expect(decline(page)).toHaveCount(0);
    expect(calls.filter((call) => call.path === '/api/delegate' || call.path.startsWith('/api/approval-results'))).toEqual([]);
  });

  test('a decline that cannot be sent says nothing changed, keeps the card usable, and can be tried again', async ({ page }) => {
    const calls = await openReview(page, { denyReplies: [{ status: 503, body: { code: 'service_unavailable' } }, 'network-failure', { status: 200, body: { status: 'denied' } }] });
    await decline(page).click();
    await expect(page.getByRole('alert')).toContainText('Could not decline right now. Nothing was changed. Try again.');
    await expect(approve(page)).toBeEnabled();
    await expect(decline(page)).toBeEnabled();
    await decline(page).click();
    await expect(page.getByRole('alert')).toContainText('Could not decline right now. Nothing was changed. Try again.');
    await decline(page).click();
    await expect(page.getByText(DECLINED)).toBeVisible();
    expect(denies(calls)).toHaveLength(3);
  });

  test('a request that was already approved cannot be declined, and the card stays', async ({ page }) => {
    await openReview(page, { denyReplies: [{ status: 409, body: { code: 'already_approved' } }] });
    await decline(page).click();
    await expect(page.getByRole('alert')).toContainText('This request was already approved, so it cannot be declined.');
    await expect(page.getByText(DECLINED)).toHaveCount(0);
  });

  test('a request that expired before the decline shows the expired message alone, with no card and no declined page', async ({ page }) => {
    const calls = await openReview(page, { denyReplies: [{ status: 410, body: { code: 'expired_request' } }] });
    await decline(page).click();
    await expect(page.getByRole('alert')).toContainText('This approval request has expired.');
    await expect(approve(page)).toHaveCount(0);
    await expect(page.getByText(DECLINED)).toHaveCount(0);
    expect(denies(calls)).toHaveLength(1);
  });

  test('Back returns to key selection and sends no request', async ({ page }) => {
    const calls = await openReview(page);
    const before = calls.length;
    await dismiss(page).click();
    await expect(approve(page)).toHaveCount(0);
    expect(calls.slice(before).filter((call) => call.path.includes('/deny') || call.path === '/api/delegate')).toEqual([]);
    expect(denies(calls)).toHaveLength(0);
  });

  test('reopening a declined link shows the declined page, with no review card and nothing prepared', async ({ page }) => {
    const calls = await serve(page, { denied: true });
    await page.goto(path + fragment);
    await expect(page.getByText(DECLINED)).toBeVisible();
    await expect(approve(page)).toHaveCount(0);
    await expect(decline(page)).toHaveCount(0);
    expect(calls.filter((call) => call.path === '/api/delegate/prepare')).toEqual([]);
  });
});

for (const [name, viewport] of [['390', { width: 390, height: 844 }], ['1280', { width: 1280, height: 900 }]] as const) {
  test(`screenshots at ${name}: the card with Decline, and the declined page`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await openReview(page);
    const shots = process.env.SHOT_DIR;
    await decline(page).scrollIntoViewIfNeeded();
    if (shots) await page.screenshot({ path: `${shots}/decline-1-card-${name}.png`, fullPage: false });
    await decline(page).click();
    await expect(page.getByText(DECLINED)).toBeVisible();
    if (shots) await page.screenshot({ path: `${shots}/decline-2-declined-${name}.png`, fullPage: false });
  });
}
