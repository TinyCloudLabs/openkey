// Synthetic API fixtures exercise the production durable confirmation screen.
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

async function confirm(page: Page, fallback: boolean) {
  await page.clock.install();
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys: [{ id: 'key_0', address, publicKey: '0x', keyIndex: 0, label: 'Approval key', keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }] });
    if (url.pathname === `/api/approval-requests/${id}/load`) return json(route, 200, {
      requestId: id, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), approved: false,
      request: { targetDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
        nodeOrigin: 'https://node.tinycloud.xyz', permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] }], grantLifetimeSeconds: 7200, reason: 'Read notes for two hours' },
    });
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared());
    if (url.pathname === '/api/delegate') return route.fulfill({ status: 200, contentType: 'application/json', headers: { date: new Date().toUTCString() }, body: JSON.stringify({
      hostActivated: true, delegationHeader: { Authorization: 'synthetic' }, delegationCid: 'bafy-delegation',
      approvalCode: fallback ? null : { code: 'ABCD-EFGH', expiresAt: new Date(Date.now() + 300_000).toISOString() },
    }) });
    return json(route, 404, { error: 'Unmocked fixture endpoint' });
  });
  await page.goto(path + fragment);
  const approve = page.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  await approve.click();
  await expect(page.getByRole('heading', { name: 'Approved', exact: true })).toBeVisible();
}

for (const viewport of [{ name: 'mobile', width: 390, height: 844 }, { name: 'desktop', width: 1280, height: 900 }]) {
  for (const state of ['live', 'expired', 'fallback'] as const) {
    test(`${viewport.name} durable confirmation: ${state}`, async ({ page, context }) => {
      await page.setViewportSize(viewport);
      const errors: string[] = [];
      page.on('pageerror', error => errors.push(error.message));
      await confirm(page, state === 'fallback');
      const copy = page.getByRole('button', { name: 'Copy code', exact: true });
      if (state === 'fallback') {
        await expect(copy).toHaveCount(0);
        await expect(page.getByText('Tell your agent to check your request.', { exact: true })).toBeVisible();
      } else {
        await expect(page.getByText('ABCD-EFGH', { exact: true })).toBeVisible();
        if (state === 'expired') {
          await page.clock.fastForward(301_000);
          await expect(copy).toBeDisabled();
          await expect(page.getByText("Tell your agent you've approved.", { exact: true })).toBeVisible();
        } else {
          await expect(copy).toBeEnabled();
          await expect(page.getByText("Tell your agent you've approved, or paste this code into your chat.", { exact: true })).toBeVisible();
          await context.grantPermissions(['clipboard-read', 'clipboard-write']);
          await copy.click();
          expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('ABCD-EFGH');
          await page.clock.fastForward(2100);
        }
        const box = await copy.boundingBox();
        expect(box!.y + box!.height).toBeLessThan(viewport.height);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.evaluate(() => scrollTo(0, 0));
      if (process.env.TC2489_SCREEN_DIR) await page.screenshot({ path: `${process.env.TC2489_SCREEN_DIR}/${viewport.name}-${state}.png` });
      expect(errors).toEqual([]);
    });
  }
}
