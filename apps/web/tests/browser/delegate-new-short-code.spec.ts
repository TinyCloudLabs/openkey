// TC-2665: an expired short paste code on the /delegate result page is replaced with
// "Get a new code" for the same approval. The real /delegate route runs with every API
// call answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const KV_GET = 'tinycloud.kv/get', KV_PUT = 'tinycloud.kv/put', CAPS_READ = 'tinycloud.capabilities/read';
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] }, [`${space}/kv/notes/`]: { [KV_GET]: [{}], [KV_PUT]: [{}] } })}`,
].join('\n');
const option = (service: string, short: string, path: string, abilities: [string, boolean][]) => {
  const key = `${service}\0${space}\0${path}`;
  return { key, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
    actions: abilities.map(([ability, required]) => ({ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required })) };
};
const permissionOptions = [option('tinycloud.capabilities', 'capabilities', '', [[CAPS_READ, true]]), option('tinycloud.kv', 'kv', 'notes/', [[KV_GET, false], [KV_PUT, false]])];
const prepared = { prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
  host: 'https://node.tinycloud.xyz', permissions: permissionOptions,
  selectedActionKeys: permissionOptions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
  authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' } };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const oneKey = [{ id: 'key_1', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', createdAt: new Date().toISOString() }];

async function mock(page: Page) {
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys: oneKey });
    if (url.pathname === '/api/delegate/prepare') {
      const body = route.request().postDataJSON() as { actionKeys?: unknown };
      return body.actionKeys === undefined ? json(route, 200, prepared) : json(route, 503, { error: 'Service unavailable' });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
}
const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });

function delegationExpiring(expirationTime: string) {
  return {
    delegationHeader: { Authorization: 'Bearer signed' },
    delegationCid: 'bafy-signed',
    spaceId: space,
    verificationMethod: 'did:key:z6Mk',
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    expirationTime,
    hostActivated: true,
  };
}

test('an expired short code can be re-minted for the same approval', async ({ page }) => {
  const receivedAt = new Date('2026-11-09T09:00:00.000Z');
  await page.clock.install({ time: receivedAt });
  await page.setViewportSize({ width: 390, height: 844 });
  await mock(page);
  const delegation = delegationExpiring('2026-11-09T10:00:00.000Z');
  const delegationCalls: unknown[] = [];
  const codeCalls: unknown[] = [];
  const codeBodies: string[] = [];
  const codeGets: string[] = [];
  let minted = 0;
  await page.route('**/api/delegate', (route) => {
    delegationCalls.push(route.request().postDataJSON());
    return json(route, 200, delegation);
  });
  await page.route('**/api/delegation-codes**', async (route) => {
    const url = new URL(route.request().url());
    if (route.request().method() !== 'POST') {
      codeGets.push(url.pathname);
      return json(route, 404, { error: 'not found' });
    }
    codeCalls.push(route.request().postDataJSON());
    codeBodies.push(route.request().postData() ?? '');
    minted += 1;
    if (minted === 2) {
      const { promise, resolve } = Promise.withResolvers<void>();
      setTimeout(resolve, 200);
      await promise;
    }
    const now = new Date();
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      headers: { date: now.toUTCString() },
      body: JSON.stringify({ code: minted === 1 ? 'AAAA-BBBB' : 'CCCC-DDDD', expiresAt: new Date(Date.parse(now.toUTCString()) + 300_000).toISOString() }),
    });
  });
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText('AAAA-BBBB')).toBeVisible();
  const copy = page.getByRole('button', { name: 'Copy code', exact: true });
  await expect(copy).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Get a new code' })).toHaveCount(0);
  await expect(page.getByRole('timer')).toContainText('Code valid for');
  await expect(copy).toHaveText('Copy code');

  const copyBox = await copy.boundingBox();

  await page.clock.fastForward(300_001);
  const showAgain = page.getByRole('button', { name: 'Get a new code', exact: true });
  await expect(showAgain).toBeVisible();
  await expect(page.getByRole('timer')).toHaveText('Code expired. Get a new code, or start again in the CLI.');
  await expect(page.getByText('Works once.', { exact: true })).toHaveCount(0);
  await expect(copy).toHaveCount(0);
  const showBox = await showAgain.boundingBox();
  expect(showBox).not.toBeNull();
  expect(copyBox).not.toBeNull();
  expect(showBox!.y).toBe(copyBox!.y);
  expect(showBox!.height).toBe(copyBox!.height);
  expect(showBox!.x + showBox!.width / 2).toBeCloseTo(copyBox!.x + copyBox!.width / 2, 0);
  await expect(page.getByText('AAAA-BBBB')).toHaveClass(/line-through/);
  await showAgain.dblclick();
  await expect(page.getByText('CCCC-DDDD')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Copy code', exact: true })).toHaveText('Copy code');
  await expect(page.getByRole('button', { name: 'Get a new code' })).toHaveCount(0);
  await expect(page.getByRole('timer')).toContainText('Code valid for');
  expect(codeCalls).toHaveLength(2);
  expect(codeCalls[1]).toEqual(codeCalls[0]);
  expect(codeBodies[1]).toBe(codeBodies[0]);
  expect(delegationCalls).toHaveLength(1);
  expect(codeCalls[0]).toEqual({ delegation });
  expect(codeGets).toEqual([]);
});

test('a failed re-mint keeps the expired code and allows retry', async ({ page }) => {
  const receivedAt = new Date('2026-11-09T09:00:00.000Z');
  await page.clock.install({ time: receivedAt });
  await page.setViewportSize({ width: 390, height: 844 });
  await mock(page);
  const delegation = delegationExpiring('2026-11-09T10:00:00.000Z');
  let minted = 0;
  await page.route('**/api/delegate', (route) => json(route, 200, delegation));
  await page.route('**/api/delegation-codes', (route) => {
    minted += 1;
    if (minted === 2) return json(route, 500, { error: 'Unavailable' });
    if (minted === 3) return json(route, 401, { error: 'Unauthorized' });
    const now = new Date();
    return route.fulfill({ status: 201, contentType: 'application/json', headers: { date: now.toUTCString() }, body: JSON.stringify({ code: 'AAAA-BBBB', expiresAt: new Date(Date.parse(now.toUTCString()) + 300_000).toISOString() }) });
  });
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText('AAAA-BBBB')).toBeVisible();
  await page.clock.fastForward(300_001);
  const showAgain = page.getByRole('button', { name: 'Get a new code', exact: true });
  await showAgain.click();
  await expect(page.getByRole('button', { name: 'Get a new code', exact: true })).toBeVisible();
  await expect(page.getByText('AAAA-BBBB')).toHaveClass(/line-through/);
  await expect(page.getByText("Couldn't get a new code. Try again, or start again in the CLI.", { exact: true })).toBeVisible();
  await expect(showAgain).toBeEnabled();
  await showAgain.click();
  await expect(page.getByText("Couldn't get a new code. Try again, or start again in the CLI.", { exact: true })).toBeVisible();
  await expect(showAgain).toBeEnabled();
  expect(minted).toBe(3);
});

test('an expired approval cannot re-mint its short code', async ({ page }) => {
  const receivedAt = new Date('2026-11-09T09:00:00.000Z');
  await page.clock.install({ time: receivedAt });
  await mock(page);
  const delegation = delegationExpiring('2026-11-09T09:02:00.000Z');
  let minted = 0;
  await page.route('**/api/delegate', (route) => json(route, 200, delegation));
  await page.route('**/api/delegation-codes', (route) => {
    minted += 1;
    const now = new Date();
    return route.fulfill({ status: 201, contentType: 'application/json', headers: { date: now.toUTCString() }, body: JSON.stringify({ code: 'AAAA-BBBB', expiresAt: new Date(Date.parse(now.toUTCString()) + 300_000).toISOString() }) });
  });
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText('AAAA-BBBB')).toBeVisible();
  await page.clock.fastForward(300_001);
  await expect(page.getByRole('button', { name: 'Get a new code' })).toHaveCount(0);
  await expect(page.getByRole('timer')).toHaveText('Code expired, and so has this approval. Start again in the CLI.');
  await expect(page.getByRole('status').filter({ hasText: 'Code expired, and so has this approval. Start again in the CLI.' })).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Copy code' })).toHaveCount(0);
  expect(minted).toBe(1);
});

test('a missing or invalid server date uses the five-minute receipt deadline', async ({ page }) => {
  const receivedAt = new Date('2026-11-09T09:00:00.000Z');
  await page.clock.install({ time: receivedAt });
  await mock(page);
  const delegation = delegationExpiring('2026-11-09T10:00:00.000Z');
  await page.route('**/api/delegate', (route) => json(route, 200, delegation));
  await page.route('**/api/delegation-codes', (route) => json(route, 201, { code: 'AAAA-BBBB', expiresAt: 'invalid' }));
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByRole('timer')).toContainText('Code valid for');
  await expect(page.getByRole('button', { name: 'Get a new code' })).toHaveCount(0);
  await page.clock.fastForward(300_001);
  await expect(page.getByRole('button', { name: 'Get a new code', exact: true })).toBeVisible();
});

test('does not loop the approval-expiry timer for a 30-day delegation', async ({ page }) => {
  const receivedAt = new Date('2026-11-09T09:00:00.000Z');
  await page.clock.install({ time: receivedAt });
  await mock(page);
  const delegation = delegationExpiring(new Date(receivedAt.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString());
  await page.route('**/api/delegate', (route) => json(route, 200, delegation));
  await page.route('**/api/delegation-codes', (route) => route.fulfill({
    status: 201,
    contentType: 'application/json',
    headers: { date: receivedAt.toUTCString() },
    body: JSON.stringify({ code: 'AAAA-BBBB', expiresAt: new Date(receivedAt.getTime() + 300_000).toISOString() }),
  }));
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText('AAAA-BBBB')).toBeVisible();
  await page.evaluate(() => {
    let calls = 0;
    document.documentElement.dataset.timeoutCalls = '0';
    Object.defineProperty(window, 'setTimeout', {
      configurable: true,
      value: new Proxy(window.setTimeout.bind(window), {
        apply(target, thisArg, args) {
          calls += 1;
          document.documentElement.dataset.timeoutCalls = String(calls);
          return Reflect.apply(target, thisArg, args);
        },
      }),
    });
  });

  await page.clock.fastForward(300_001);
  await expect(page.getByRole('timer')).toContainText('Code expired');
  const callsAtExpiry = await page.evaluate(() => Number(document.documentElement.dataset.timeoutCalls));
  await page.clock.runFor(100);
  const callsAfter100Ms = await page.evaluate(() => Number(document.documentElement.dataset.timeoutCalls));
  expect(callsAfter100Ms - callsAtExpiry).toBeLessThan(10);
});
