// TC-2234: a share invitation approval shows who is invited to what and until when, and the one key OpenKey
// issues for it, without the key's id. The page sends no permissions of its own.
import { test, expect, type Page } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const target = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const path = `/a/${id}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const shareKeyId = '3f9a6c0e1b2d4f5a8c7e9d0b1a2c3e4f';
const shareKey = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default/share/${shareKeyId}`;
const create = 'tinycloud.encryption/key.create';
const decrypt = 'tinycloud.encryption/decrypt';
const acceptanceExpiresAt = new Date(Math.floor((Date.now() + 23 * 3600_000) / 1000) * 1000).toISOString();
const context = {
  kind: 'share-invitation', version: 1, invitationId: '01JC5Z8Q0000000000000000AB',
  recipientEmail: 'alex@example.test', subjectKind: 'session', subjectName: 'Project notes',
  acceptanceExpiresAt, accessExpiresAt: acceptanceExpiresAt,
};

async function open(page: Page, request: Record<string, unknown>, resource: string, abilities: string[]) {
  const prepares: Record<string, unknown>[] = [];
  await page.route('**/api/**', async route => {
    const pathname = new URL(route.request().url()).pathname;
    const raw: unknown = route.request().postData() ? route.request().postDataJSON() : {};
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('Expected an object request');
    const body = raw as Record<string, unknown>; // Object shape checked above; fields are still unknown.
    const reply = (status: number, json: unknown) => route.fulfill({ status, json });
    if (pathname === '/api/auth/get-session') return reply(200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    if (pathname === '/api/keys') return reply(200, { keys: [{ id: 'owner-key', address, publicKey: '0x', keyIndex: 0, keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }] });
    if (pathname === `/api/approval-requests/${id}/load`) return reply(200, {
      requestId: id, expiresAt: acceptanceExpiresAt, approved: false,
      request: { targetDid: target, targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, nodeOrigin: 'https://node.tinycloud.xyz',
        grantLifetimeSeconds: 82800, ...request },
    });
    if (pathname === '/api/delegate/prepare') {
      prepares.push(body);
      const keyFor = (ability: string) => `tinycloud.encryption\0encryption\0${resource}\0${ability}`;
      const siwe = ['cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '', `URI: ${target}#${target}`,
        'Version: 1', 'Chain ID: 1', 'Nonce: qa123451', `Issued At: ${new Date().toISOString()}`,
        `Expiration Time: ${new Date(Date.parse(acceptanceExpiresAt) - 5000).toISOString()}`,
        ...('context' in request ? [`Request ID: urn:tinycloud:approval-request:${id}:bafkreia${'a'.repeat(52)}`] : []), 'Resources:',
        `- ${makeRecapResource({ [resource]: Object.fromEntries(abilities.map(ability => [ability, [{}]])) })}`].join('\n');
      return reply(200, { prepared: { siwe, spaceId: '', jwk: body.jwk }, spaceId: '', host: body.host, address, chainId: 1,
        permissions: [{ key: `tinycloud.encryption\0encryption\0${resource}`, service: 'encryption', path: resource, label: 'encryption', resourcePath: resource,
          actions: abilities.map(ability => ({ key: keyFor(ability), ability, action: ability.split('/')[1], required: false })) }],
        selectedActionKeys: abilities.map(keyFor), edited: false,
        authorizationContext: { token: 'context-1', expiresAt: Date.now() + 300000 } });
    }
    return reply(404, { error: `Unexpected QA request ${pathname}` });
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(path);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  return prepares;
}

const UNLOCK = {
  session: 'Unlock Project notes with this invitation\'s key',
  file: 'Unlock Project notes with this invitation\'s key',
} as const;
const CONTINUATION = 'Once accepted, access can continue after this date. If you remove it, access ends within 7 days.';

for (const subjectKind of ['session', 'file'] as const) {
  test(`a ${subjectKind} invitation shows its recipient, subject, deadline and one key, never the key id or an expiry picker`, async ({ page }) => {
    const prepares = await open(page, { permissions: [], context: { ...context, subjectKind } }, shareKey, [create, decrypt]);
    await expect(page.getByRole('heading', { name: 'Invite alex@example.test to Project notes' })).toBeVisible();
    // Acceptance is 23 hours after this file loaded, so a moment later at page load it is 22 whole hours away.
    await expect(page.getByLabel('Invitation')).toContainText(`${subjectKind === 'file' ? 'Approve' : 'Accept'} within 22 hours, by ${await shownDate(page, acceptanceExpiresAt)}`);
    await expect(page.getByText(CONTINUATION)).toHaveCount(subjectKind === 'session' ? 1 : 0);
    const summary = page.getByLabel('Requested access');
    await expect(summary.getByText('Create an encryption key for this invitation only')).toBeVisible();
    await expect(summary.getByText(UNLOCK[subjectKind])).toBeVisible();
    await expect(page.getByText('Open this shared file')).toHaveCount(0);
    await expect(page.getByText('Approval expires')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Change' })).toHaveCount(0);
    const main = await page.locator('main').innerText();
    expect(main).not.toContain(shareKeyId);
    expect(main).not.toContain('approval-request');
    expect(main).not.toContain('bafkreia');
    expect(prepares[0]).not.toHaveProperty('permissions');
    const dir = process.env.QA_SCREENSHOT_DIR;
    if (dir) await page.screenshot({ path: `${dir}/share-invitation-${subjectKind}-390.png`, fullPage: true });
    // The detail and edit view names the key's actions the same way.
    await page.locator('summary').filter({ hasText: 'Advanced details' }).click();
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await expect(page.getByRole('checkbox', { name: UNLOCK[subjectKind] })).toBeVisible();
    await expect(page.getByRole('checkbox', { name: 'Create an encryption key for this invitation only' })).toBeVisible();
    await expect(page.getByText('Open this shared file')).toHaveCount(0);
    if (dir) await page.screenshot({ path: `${dir}/share-invitation-${subjectKind}-detail-390.png`, fullPage: true });
  });
}

/** The date the approval page shows for `iso`, formatted in the page as the summary formats it. */
const shownDate = (page: Page, iso: string) => page.evaluate((instant) => new Intl.DateTimeFormat(undefined, {
  year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short',
}).format(new Date(instant)), iso);

// Access deadlines set an hour past a whole number of days from now, so the rounded-down words are exact.
const DAY = 24 * 3600_000;
for (const [label, access, words] of [
  ['the CLI default 7 days', () => new Date(Date.now() + 7 * DAY + 3600_000).toISOString(), '7 days'],
  ['30 days', () => new Date(Date.now() + 30 * DAY + 3600_000).toISOString(), '30 days'],
  ['90 days', () => new Date(Date.now() + 90 * DAY + 3600_000).toISOString(), '90 days'],
  ['equal dates', () => acceptanceExpiresAt, '22 hours'],
] as const) {
  test(`a file invitation with ${label} of access shows both signed dates with their durations`, async ({ page }) => {
    const accessExpiresAt = access();
    await open(page, { permissions: [], context: { ...context, subjectKind: 'file', accessExpiresAt } }, shareKey, [create, decrypt]);
    const box = page.getByLabel('Invitation');
    await expect(box).toContainText(`Approve within 22 hours, by ${await shownDate(page, acceptanceExpiresAt)}`);
    await expect(box).toContainText(`alex@example.test can open Project notes for ${words}, until ${await shownDate(page, accessExpiresAt)}`);
    await expect(page.getByText(CONTINUATION)).toHaveCount(0);
    const dir = process.env.QA_SCREENSHOT_DIR;
    if (dir) await page.screenshot({ path: `${dir}/share-invitation-file-${label.replaceAll(' ', '-')}-390.png`, fullPage: true });
  });
}

test('a file invitation 30 minutes from its deadlines never overstates them', async ({ page }) => {
  const soon = new Date(Math.floor((Date.now() + 30 * 60_000) / 1000) * 1000).toISOString();
  await open(page, { permissions: [], context: { ...context, subjectKind: 'file', acceptanceExpiresAt: soon, accessExpiresAt: soon } }, shareKey, [create, decrypt]);
  const box = page.getByLabel('Invitation');
  await expect(box).toContainText(`Approve within the next hour, by ${await shownDate(page, soon)}`);
  await expect(box).toContainText(`alex@example.test can open Project notes for less than an hour, until ${await shownDate(page, soon)}`);
  await expect(box).not.toContainText('1 hour');
});

// The page was opened after the deadlines passed (prepare is mocked; the server refuses such an approval).
const past = (ms: number) => new Date(Math.floor((Date.now() - ms) / 1000) * 1000).toISOString();

test('an expired file invitation says so for both dates', async ({ page }) => {
  const accepted = past(2 * 3600_000);
  const access = past(3600_000);
  await open(page, { permissions: [], context: { ...context, subjectKind: 'file', acceptanceExpiresAt: accepted, accessExpiresAt: access } }, shareKey, [create, decrypt]);
  const box = page.getByLabel('Invitation');
  await expect(box).toContainText(`The time to approve this ended on ${await shownDate(page, accepted)}.`);
  await expect(box).toContainText(`alex@example.test could open Project notes until ${await shownDate(page, access)}.`);
  await expect(box).not.toContainText('Approve within');
  await expect(box).not.toContainText('expired');
  const dir = process.env.QA_SCREENSHOT_DIR;
  if (dir) await page.screenshot({ path: `${dir}/share-invitation-file-expired-390.png`, fullPage: true });
});

test('a file invitation past acceptance but not access keeps the access line', async ({ page }) => {
  const accepted = past(3600_000);
  const access = new Date(Date.now() + 7 * DAY + 3600_000).toISOString();
  await open(page, { permissions: [], context: { ...context, subjectKind: 'file', acceptanceExpiresAt: accepted, accessExpiresAt: access } }, shareKey, [create, decrypt]);
  const box = page.getByLabel('Invitation');
  await expect(box).toContainText(`The time to approve this ended on ${await shownDate(page, accepted)}.`);
  await expect(box).toContainText(`alex@example.test can open Project notes for 7 days, until ${await shownDate(page, access)}`);
});

test('an expired session invitation says so and drops the continuation line', async ({ page }) => {
  const accepted = past(3600_000);
  await open(page, { permissions: [], context: { ...context, acceptanceExpiresAt: accepted, accessExpiresAt: accepted } }, shareKey, [create, decrypt]);
  const box = page.getByLabel('Invitation');
  await expect(box).toContainText(`This invitation expired on ${await shownDate(page, accepted)}.`);
  await expect(page.getByText(CONTINUATION)).toHaveCount(0);
  const dir = process.env.QA_SCREENSHOT_DIR;
  if (dir) await page.screenshot({ path: `${dir}/share-invitation-session-expired-390.png`, fullPage: true });
});

test('a request without an invitation shows no invitation summary', async ({ page }) => {
  const leaf = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default/share/${shareKeyId}`;
  await open(page, { permissions: [{ service: 'tinycloud.encryption', space: 'encryption', path: leaf, actions: [decrypt] }] }, leaf, [decrypt]);
  await expect(page.getByLabel('Invitation')).toHaveCount(0);
  await expect(page.getByText('Open this shared file')).toBeVisible();
  const dir = process.env.QA_SCREENSHOT_DIR;
  if (dir) await page.screenshot({ path: `${dir}/existing-share-approval-390.png`, fullPage: true });
});
