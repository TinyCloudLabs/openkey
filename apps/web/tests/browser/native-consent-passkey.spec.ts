// TC-3442: native app consent asks for the passkey on Allow when the prepared revision says the account's setting
// needs it. The assertion answers that revision's challenge; a passkey refusal shows the API's words and the page
// prepares again, so the next Allow answers a new challenge.
import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:applications`;
const caps = 'tinycloud.capabilities/read';
const siwe = [
  'openkey.so wants you to sign in with your Ethereum account:', address, '',
  '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-07T04:00:00.000Z',
  'Expiration Time: 2026-10-07T05:00:00.000Z', 'Resources:',
  `- ${makeRecapResource({ [`${space}/capabilities`]: { [caps]: [{}] } })}`,
].join('\n');
const optionKey = `tinycloud.capabilities\0${space}\0`;
const permissionOptions = [{ key: optionKey, service: 'capabilities', path: '', label: 'capabilities', resourcePath: 'capabilities',
  actions: [{ key: `${optionKey}\0${caps}`, action: 'read', ability: caps, required: true }] }];
const selected = [`${optionKey}\0${caps}`];
const base = { requestId: 'native-1', kind: 'SIGNIN', userId: 'u', keyId: 'key-1', address, client: { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' },
  redirectScheme: 'xyz.tinycloud.exo', sessionDid: 'did:key:z6Mk', tinycloudHost: 'https://tee.node.tinycloud.xyz', ttlSeconds: 3600,
  grantLifetimeSeconds: 2592000, hostPlan: null, permissionOptions, sessionSiwe: siwe, selectedActionKeys: selected };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const sessionBody = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } };
const credentialId = randomBytes(16);
const INVALID = "Your passkey didn't confirm this. Tap Approve to try again.";

function offer(token: string) {
  return {
    required: true, challengeToken: token, options: {
      challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
      allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
    },
  };
}

async function virtualAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  } });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: {
    credentialId: credentialId.toString('base64'), isResidentCredential: true, rpId: 'localhost',
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    userHandle: Buffer.from('u').toString('base64'), signCount: 0,
  } });
}

/** Opens native consent; each prepare answers with the next passkey offer, and each approve with the next reply. */
async function setup(page: Page, offers: unknown[], approveReplies: { status: number; body: unknown }[] = []) {
  const calls = { prepares: 0, approves: [] as Record<string, unknown>[] };
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, sessionBody);
    if (path === '/api/oauth/tinycloud/clients/exo-native/branding') return json(route, { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' });
    if (path.endsWith('/prepare')) {
      const passkey = offers[Math.min(calls.prepares, offers.length - 1)];
      calls.prepares += 1;
      return json(route, { ...base, revision: calls.prepares, digest: `digest-${calls.prepares}`, passkey });
    }
    if (path.endsWith('/approve')) {
      calls.approves.push(route.request().postDataJSON());
      const r = approveReplies[calls.approves.length - 1] ?? { status: 200, body: { status: 'APPROVED', hosting: 'existing' } };
      return json(route, r.body, r.status);
    }
    if (path === '/api/auth/oauth2/consent') return json(route, { url: 'https://example.test/callback?code=code' });
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await page.route('https://example.test/**', route => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>app</p>' }));
  await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
  await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeEnabled();
  return calls;
}

test('Allow answers the revision\'s passkey challenge and sends the assertion with the approval', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, [offer('token-1')]);
  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await expect.poll(() => calls.approves.length).toBe(1);
  expect(calls.approves[0]).toMatchObject({
    revision: 1, digest: 'digest-1',
    passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });
  await page.waitForURL('https://example.test/callback?code=code');
});

test('when the setting does not ask, Allow sends no assertion', async ({ page }) => {
  const calls = await setup(page, [{ required: false }]);
  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await expect.poll(() => calls.approves.length).toBe(1);
  expect(calls.approves[0]).not.toHaveProperty('passkeyAssertion');
});

test('a passkey refusal shows the API\'s words, and the next Allow answers a new challenge', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, [offer('token-1'), offer('token-2')], [
    { status: 403, body: { error: INVALID, code: 'passkey_approval_invalid' } },
  ]);
  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText(INVALID);
  await expect.poll(() => calls.prepares).toBe(2);

  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await expect.poll(() => calls.approves.length).toBe(2);
  expect(calls.approves[1]).toMatchObject({ revision: 2, passkeyAssertion: { challengeToken: 'token-2' } });
});
