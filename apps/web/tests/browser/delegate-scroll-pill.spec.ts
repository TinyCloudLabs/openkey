import { test, expect, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0x1111111111111111111111111111111111111111';
const space = `tinycloud:pkh:eip155:1:${address}:secrets`;
const abilities = ['tinycloud.kv/get', 'tinycloud.kv/set', 'tinycloud.kv/delete', 'tinycloud.kv/sync', 'tinycloud.kv/list', 'tinycloud.kv/watch'];
const permissions = abilities.map((ability, index) => ({ service: 'tinycloud.kv', space, path: `vault/secrets/permission-${index}`, actions: [ability] }));
const siwe = ['cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '', 'URI: did:key:z6Mk', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Resources:', `- ${makeRecapResource(Object.fromEntries(permissions.map((permission, index) => [`${space}/kv/${permission.path}`, { [abilities[index]]: [{}] }])))}`].join('\n');
const permissionRows = permissions.map((permission, index) => {
  const key = `tinycloud.kv\0${space}\0${permission.path}`;
  return { key, service: 'kv', path: permission.path, label: 'kv', resourcePath: `kv/${permission.path}`, actions: [{ key: `${key}\0${abilities[index]}`, action: abilities[index].split('/')[1], ability: abilities[index], required: false }] };
});
const selectedActionKeys = permissionRows.flatMap((row) => row.actions.map((action) => action.key));
const preparedResponse = { prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1, host: 'https://node.tinycloud.xyz', permissions: permissionRows, selectedActionKeys, edited: false, authorizationContext: { token: 'context-token', expiresAt: Date.now() + 600000, baselineAbilitiesDigest: 'digest' } };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
for (const [width, height] of [[390, 844], [1280, 800]]) {
  test(`scroll affordance stays clear of permission text at ${width}x${height}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await page.route('**/api/**', (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'alice@example.test' } });
      if (path === '/api/keys') return json(route, 200, { keys: [{ id: 'key_1', address, publicKey: '0x', keyIndex: 0, label: 'Main', keyType: 'MANAGED', createdAt: new Date().toISOString() }] });
      if (path === '/api/delegate/prepare') return json(route, 200, preparedResponse);
      return json(route, 404, { error: `unmocked ${path}` });
    });
    const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
    await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}&permissions=${encodeBase64UrlJson({ permissions })}`);
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeAttached({ timeout: 45_000 });
    // The affordance is recomputed on resize and scroll; once the page has settled, ask for the first computation.
    await page.evaluate(() => window.dispatchEvent(new Event('resize')));
    const pill = page.getByTestId('scroll-to-approve');
    await expect(pill).toBeVisible({ timeout: 45_000 });
    const pillBox = await pill.boundingBox();
    const textBoxes = await page.locator('text=permission-').evaluateAll((nodes) => nodes.map((node) => { const range = document.createRange(); range.selectNodeContents(node); return Array.from(range.getClientRects()).map((rect) => ({ x: rect.x, y: rect.y, right: rect.right, bottom: rect.bottom })); }).flat());
    expect(pillBox).not.toBeNull();
    expect(pillBox!.x + pillBox!.width).toBeGreaterThan(width / 2);
    expect(width - (pillBox!.x + pillBox!.width)).toBeLessThanOrEqual(24);
    expect(height - (pillBox!.y + pillBox!.height)).toBeLessThanOrEqual(24);
    for (const text of textBoxes) expect(pillBox!.x >= text.right || pillBox!.x + pillBox!.width <= text.x || pillBox!.y >= text.bottom || pillBox!.y + pillBox!.height <= text.y).toBe(true);
    await pill.click();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeInViewport();
  });
}
