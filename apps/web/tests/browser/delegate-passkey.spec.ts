// TC-3442: the delegate approval page asks for the passkey on Approve when /prepare says the account's setting needs
// it. The assertion answers that preview's challenge; a passkey refusal shows the API's words and the page prepares
// again, so the next Approve answers a new challenge.
import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const fragment = `#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const path = `/a/${id}`;
const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const CAPS_READ = 'tinycloud.capabilities/read';
const KV_GET = 'tinycloud.kv/get';
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const credentialId = randomBytes(16);
const INVALID = "Your passkey didn't confirm this. Tap Approve to try again.";

function prepared(token: string, passkey: unknown) {
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
    authorizationContext: { token, expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' }, passkey,
  };
}

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

/** Opens the approval page; each /prepare answers with the next passkey offer, each Approve with the next reply. */
async function open(page: Page, offers: unknown[], delegateReplies: { status: number; body: unknown }[] = []) {
  const calls = { prepares: 0, delegates: [] as Record<string, unknown>[] };
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
      calls.delegates.push(route.request().postDataJSON());
      const r = delegateReplies[calls.delegates.length - 1]
        ?? { status: 200, body: { hostActivated: true, delegationHeader: { Authorization: 'x' }, delegationCid: 'bafy-delegation' } };
      return json(route, r.status, r.body);
    }
    if (url.pathname === '/api/delegate/prepare') {
      const passkey = offers[Math.min(calls.prepares, offers.length - 1)];
      calls.prepares += 1;
      return json(route, 200, prepared(`context-${calls.prepares}`, passkey));
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  await page.goto(path + fragment);
  await expect(approve(page)).toBeEnabled();
  return calls;
}

const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });

test('Approve answers the preview\'s passkey challenge and sends the assertion with the approval', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await open(page, [offer('token-1')]);
  await approve(page).click();
  await expect.poll(() => calls.delegates.length).toBe(1);
  expect(calls.delegates[0]).toMatchObject({
    authorizationContextToken: 'context-1',
    passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });
});

test('when the setting does not ask, Approve sends no assertion', async ({ page }) => {
  const calls = await open(page, [{ required: false }]);
  await approve(page).click();
  await expect.poll(() => calls.delegates.length).toBe(1);
  expect(calls.delegates[0]).not.toHaveProperty('passkeyAssertion');
});

test('a passkey refusal shows the API\'s words, and the next Approve answers a new challenge', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await open(page, [offer('token-1'), offer('token-2')], [
    { status: 403, body: { error: INVALID, code: 'passkey_approval_invalid' } },
  ]);
  const preparesBefore = calls.prepares;
  await approve(page).click();
  await expect(page.getByRole('alert')).toHaveText(INVALID);
  await expect.poll(() => calls.prepares).toBe(preparesBefore + 1);

  await approve(page).click();
  await expect.poll(() => calls.delegates.length).toBe(2);
  expect(calls.delegates[1]).toMatchObject({
    authorizationContextToken: `context-${preparesBefore + 1}`, passkeyAssertion: { challengeToken: 'token-2' },
  });
});
