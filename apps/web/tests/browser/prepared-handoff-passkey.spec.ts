// TC-3442: the prepared CLI sign-in page asks for the passkey on Approve when the preview says the account's setting
// needs it. The assertion answers the preview's challenge; a passkey refusal shows the API's words and the page
// previews again, so the next Approve answers a new challenge.
import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const host = 'https://node.tinycloud.xyz';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const handoffId = 'B'.repeat(43);
const state = 'A'.repeat(43);
const cancelSecret = 'C'.repeat(43);
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'I further authorize these capabilities.', '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-16T17:00:00.000Z', 'Expiration Time: 2026-10-23T17:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/sync': [{}] } })}`,
].join('\n');
const fullKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/get`;
const syncKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/sync`;
const key = { id: 'key-one', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: '2026-10-16T17:00:00.000Z' };
const rawResult = { protocolVersion: 1, address, signature: '0xsigned', signedMessage: siwe, selectedActionKeys: [fullKey, syncKey], permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/sync'] }] };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
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

/** Opens the prepared page; each preview answers with the next passkey offer, and each sign with the next reply. */
async function setup(page: Page, offers: unknown[], signReplies: { status: number; body: unknown }[] = []) {
  const calls = { previews: 0, signs: [] as Record<string, unknown>[] };
  await page.clock.setFixedTime(new Date('2026-10-16T17:00:00.000Z'));
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: [key] });
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') return json(route, 201, { transportVersion: 2, ticket: handoffId, expiresAt: '2026-10-16T17:05:00.000Z' });
    if (path === '/api/delegate/authorize-sign-prepare') {
      return json(route, 200, { authorizationContextToken: 'bound-context', allowedActionIds: [fullKey, syncKey], initialSelectionActionIds: [fullKey, syncKey], address });
    }
    if (path === '/api/delegate/authorize-sign-preview') {
      const passkey = offers[Math.min(calls.previews, offers.length - 1)];
      calls.previews += 1;
      return json(route, 200, { ...rawResult, previewApprovalToken: `preview-${calls.previews}`, passkey });
    }
    if (path === '/api/delegate/authorize-sign') {
      calls.signs.push(route.request().postDataJSON());
      const r = signReplies[calls.signs.length - 1] ?? { status: 200, body: { ...rawResult, deliveryState: state, selectedKeyId: key.id } };
      return json(route, r.status, r.body);
    }
    return json(route, 404, { error: `unexpected ${path}` });
  });
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  const input = { transportVersion: 2, request: { protocolVersion: 1, siwe, jwk, host, sessionDid: 'did:key:cli-session', keyId: key.id }, delivery: { handoffId, state, cancelSecret } };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`);
  return calls;
}

test('Approve answers the preview\'s passkey challenge and sends the assertion with the approval', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, [offer('token-1')]);
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect.poll(() => calls.signs.length).toBe(1);
  expect(calls.signs[0]).toMatchObject({
    previewApprovalToken: 'preview-1',
    passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });
});

test('when the setting does not ask, Approve sends no assertion', async ({ page }) => {
  const calls = await setup(page, [{ required: false }]);
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect.poll(() => calls.signs.length).toBe(1);
  expect(calls.signs[0]).not.toHaveProperty('passkeyAssertion');
});

test('a passkey refusal shows the API\'s words, and the next Approve answers a new challenge', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, [offer('token-1'), offer('token-2')], [
    { status: 403, body: { error: INVALID, code: 'passkey_approval_invalid' } },
  ]);
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText(INVALID);
  await expect.poll(() => calls.previews).toBe(2);

  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect.poll(() => calls.signs.length).toBe(2);
  expect(calls.signs[1]).toMatchObject({
    previewApprovalToken: 'preview-2', passkeyAssertion: { challengeToken: 'token-2' },
  });
});
