import { expect, test, type Page } from '@playwright/test';
import { ORG_ADMIN_ORIGIN as ORIGIN } from './org-admin-origin';

// HTTP UI fixtures only. Real database and passkey checks run in the API integration suite.
const personalDid = 'did:pkh:eip155:1:0x52908400098527886E0F7030069857D2E4169EE7';
const key = { id: 'org-key', address: '0x0000000000000000000000000000000000000001', orgKey: { orgId: 'org-example', orgName: 'Example Learning', controllerDid: 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001' } };
const expires = new Date(Date.now() + 7 * 86400000).toISOString();
async function fixture(page: Page, state: 'owner' | 'accept' | 'generic' | 'masked' | 'identity' | 'expired' | 'cancelled') {
  const now = new Date().toISOString();
  const user = { id: 'invitee', name: 'Example Person', email: 'person@example.test', emailVerified: true, createdAt: now, updatedAt: now };
  const session = { id: 'ui-session', userId: user.id, token: 'ui-only', expiresAt: expires, createdAt: now, updatedAt: now };
  await page.routeWebSocket('**/*', socket => socket.close());
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) { await route.abort(); return; }
    if (!url.pathname.startsWith('/api/')) { await route.continue(); return; }
    if (url.pathname === '/api/auth/get-session') { await route.fulfill({ json: { user, session } }); return; }
    if (url.pathname === '/api/org-keys/org-key/admins') {
      await route.fulfill({ json: { role: 'OWNER', key, handle: 'example', events: [], grants: [
        { id: 'owner', role: 'OWNER', granteeUserId: 'owner-account', grantee: { name: 'Example Owner', email: 'owner@example.test' }, acceptedAt: now },
        { id: 'pending', role: 'ADMIN', invitedEmail: 'person@example.test', acceptedAt: null, invitationExpiresAt: expires },
      ] } }); return;
    }
    if (url.pathname === '/api/org-key-invitations/invitation') {
      await route.fulfill({ json: state === 'expired' || state === 'cancelled' ? { state } : state === 'generic' ? { maskedEmail: null } : state === 'masked' ? { maskedEmail: 'p•••@example.test' } : {
        key, handle: 'example', inviter: { name: 'Example Owner', email: 'owner@example.test' }, invitedEmail: user.email, personalDid: state === 'identity' ? null : personalDid, accepted: false, expiresAt: expires,
      } }); return;
    }
    await route.fulfill({ status: 404, json: {} });
  });
}
for (const width of [390, 1440]) {
  for (const state of ['owner', 'accept', 'generic', 'masked', 'identity', 'expired', 'cancelled'] as const) {
    test(`${state} at ${width}px preserves the organisation and personal identity boundary`, async ({ page }) => {
      await page.setViewportSize({ width, height: 1000 });
      await fixture(page, state);
      await page.goto(state === 'owner' ? '/dashboard/org-keys/org-key/admins' : '/org-key-invitations/invitation');
      if (state === 'owner') await expect(page.getByRole('heading', { name: 'People with access' })).toBeVisible();
      else if (state === 'accept') {
        await expect(page.getByRole('button', { name: 'Accept with passkey' })).toBeVisible();
        await expect(page.getByText('Your account', { exact: true })).toBeVisible();
      } else if (state === 'identity') {
        await expect(page.getByRole('link', { name: 'Set up OpenKey' })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Accept with passkey' })).toHaveCount(0);
      } else if (state === 'expired' || state === 'cancelled') {
        await expect(page.getByText('Ask the organisation owner for a new invitation.')).toBeVisible();
        await expect(page.getByRole('button', { name: 'Accept with passkey' })).toHaveCount(0);
      } else {
        await expect(page.getByRole('button', { name: 'Sign in with email' })).toBeVisible();
        await expect(page.getByText('Example Learning', { exact: true })).toHaveCount(0);
        await expect(page.getByText('person@example.test', { exact: true })).toHaveCount(0);
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.screenshot({ path: `/tmp/tc1518-${state}-${width}.png`, fullPage: true });
      if (state === 'owner') {
        await page.getByRole('button', { name: 'Invite admin' }).click();
        await expect(page.getByRole('heading', { name: 'Who would you like to invite?' })).toBeVisible();
        await page.screenshot({ path: `/tmp/tc1518-invite-${width}.png`, fullPage: true });
      }
    });
  }
}

for (const delivery of ['created', 'failed', 'rate', 'cap'] as const) {
  test(`invitation ${delivery} notice at 390px follows a real browser passkey ceremony`, async ({ page, context }) => {
    const { generateKeyPairSync } = await import('node:crypto');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const credential = Buffer.alloc(16, 7);
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    } });
    await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: {
      credentialId: credential.toString('base64'), isResidentCredential: true, rpId: 'localhost',
      privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      signCount: 0, userHandle: Buffer.from('invitee').toString('base64'),
    } });
    await page.setViewportSize({ width: 390, height: 1000 });
    await fixture(page, 'owner');
    await page.route('**/api/org-keys/org-key/admin-invitations**', async route => {
      if (new URL(route.request().url()).pathname.endsWith('/challenge')) {
        await route.fulfill({ json: { challenge: { nonce: 'ui-nonce', challenge: Buffer.alloc(32, 8).toString('base64url'), allowCredentials: [{ id: credential.toString('base64url'), type: 'public-key' }] } } });
      } else if (delivery === 'rate' || delivery === 'cap') await route.fulfill({ status: delivery === 'rate' ? 429 : 409, json: { error: 'Forbidden', code: delivery === 'rate' ? 'invitation_rate_limited' : 'pending_invitation_limit' } });
      else await route.fulfill({ json: { invitationId: 'ui-invitation', ...(delivery === 'failed' ? { delivery: 'failed' } : {}) } });
    });
    await page.goto('/dashboard/org-keys/org-key/admins');
    await page.getByRole('button', { name: 'Invite admin' }).click();
    await page.getByLabel('Email address').fill('person@example.test');
    await page.getByRole('button', { name: 'Send invitation' }).click();
    await expect(page.getByText(delivery === 'rate' ? "You've sent several invitations in the last minute. Wait a minute, then try again." : delivery === 'cap' ? 'This organisation key already has 50 pending invitations. Cancel one, or wait for one to expire, then invite again.' : delivery === 'failed'
      ? "The invitation is ready, but the email couldn't be sent. Copy the invitation link and send it to them yourself."
      : "Invitation created for person@example.test. If they don't get the email, copy the invitation link and send it to them.")).toBeVisible();
    if (delivery === 'cap') await expect(page.getByRole('button', { name: 'Try again', exact: true })).toHaveCount(0);
    if (delivery === 'rate') await expect(page.getByRole('button', { name: 'Try again', exact: true })).toBeVisible();
    await page.screenshot({ path: `/tmp/tc1518-delivery-${delivery}-390.png`, fullPage: true });
  });
}
