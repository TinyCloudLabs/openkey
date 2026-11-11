import { test, expect, type Page } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const path = `/a/${id}`;
const fragment = `#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const read = 'tinycloud.kv/get';
const capabilities = 'tinycloud.capabilities/read';
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const abilityKey = (ability: string) => `${ability === capabilities ? 'tinycloud.capabilities' : 'tinycloud.kv'}\0${space}\0${ability === capabilities ? '' : 'notes/'}\0${ability}`;
const session = {
  session: { id: 'session-1', userId: 'new-user', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  user: { id: 'new-user', email: 'new@example.test', name: 'New User' },
};

function prepared() {
  const siwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    `URI: ${target}#${target}`, 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
    'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
    'Resources:', `- ${makeRecapResource({ [`${space}/capabilities`]: { [capabilities]: [{}] }, [`${space}/kv/notes/`]: { [read]: [{}] } })}`,
  ].join('\n');
  const permissions = [[capabilities], [read]].map(abilities => {
    const ability = abilities[0]!;
    const service = ability === capabilities ? 'capabilities' : 'kv';
    const key = abilityKey(ability);
    return { key: key.slice(0, key.lastIndexOf('\0')), service, path: ability === capabilities ? '' : 'notes/', label: service,
      resourcePath: service, actions: abilities.map(action => ({ key: abilityKey(action), ability: action, action: action.split('/')[1], required: action === capabilities })) };
  });
  return {
    prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap(permission => permission.actions.map(action => action.key)),
    edited: false, authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

async function mockApprovalAndGoogleSignup(page: Page) {
  const calls: Array<{ path: string; body: Record<string, unknown> | null; url: URL }> = [];
  let signedIn = false;
  await page.context().route('**/api/**', async route => {
    const request = route.request();
    const url = new URL(request.url());
    const pathname = url.pathname;
    const body = request.method() === 'POST' ? request.postDataJSON() as Record<string, unknown> : null;
    calls.push({ path: pathname, body, url });
    const json = (value: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
    if (pathname === '/api/auth/get-session') return json(signedIn ? session : null);
    if (pathname === '/api/auth/providers') return json({ providers: ['google'] });
    if (pathname === '/api/auth/sign-in/social') {
      return json({ url: 'https://accounts.google.com/o/oauth2/auth?client_id=test&state=test', redirect: false });
    }
    if (pathname === '/api/auth/social/continuation') return json({ providerId: 'google', name: 'New User', outcome: 'new_account', email: 'new@example.test', isPrivateEmail: false });
    if (pathname === '/api/auth/social/confirm') {
      signedIn = true;
      return json({ token: 'new-account-session', user: { id: 'new-user', email: 'new@example.test' } });
    }
    if (pathname === '/api/keys') return json({ keys: [{ id: 'key-1', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }] });
    if (pathname === '/api/auth/passkey/list-user-passkeys') return json([]);
    if (pathname === `/api/approval-requests/${id}/load`) return json({
      requestId: id, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), approved: false, denied: false,
      request: { targetDid: target, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, nodeOrigin: 'https://node.tinycloud.xyz',
        permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [read] }], grantLifetimeSeconds: 7200, reason: 'Read notes for two hours' },
    });
    if (pathname === '/api/delegate/prepare') return json(prepared());
    return json({ error: `Unmocked ${pathname}` }, 404);
  });
  await page.context().route('https://accounts.google.com/**', async route => {
    const start = calls.findLast(call => call.path === '/api/auth/sign-in/social');
    const callback = String(start?.body?.callbackURL);
    const returnUrl = new URL(callback);
    returnUrl.searchParams.set('error', 'new_account');
    returnUrl.searchParams.set('continuation', 'google-continuation');
    return route.fulfill({ status: 200, contentType: 'text/html', body: `<!doctype html><script>location.replace(${JSON.stringify(returnUrl.href)});</script>` });
  });
  return calls;
}

test('Google signup from an approval link returns a new user to its consent screen', async ({ page }) => {
  const calls = await mockApprovalAndGoogleSignup(page);
  const mainFrameNavigations: string[] = [];
  page.on('framenavigated', frame => {
    if (frame === page.mainFrame()) mainFrameNavigations.push(new URL(frame.url()).pathname);
  });

  await page.goto(path + fragment);
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeVisible();
  await page.getByRole('link', { name: 'Register', exact: true }).click();
  await expect(page).toHaveURL(/\/auth\/register\?/);
  expect(new URL(page.url()).searchParams.get('returnTo')).toBe(path);
  const popup = page.waitForEvent('popup');
  await page.getByRole('button', { name: 'Continue with Google' }).click();
  const popupPage = await popup;
  await popupPage.waitForEvent('close');

  await expect(page).toHaveURL(new RegExp(`${path}$`));
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  expect(mainFrameNavigations).not.toContain('/dashboard');
  expect(calls.some(call => call.path === '/api/auth/social/confirm' && call.body?.continuation === 'google-continuation')).toBe(true);
  expect(calls.some(call => call.path === `/api/approval-requests/${id}/load`)).toBe(true);
});
