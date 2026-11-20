// TC-3569: a native consent whose prepare answers `kind: 'STEPUP'` is the step-up screen: a framed app of TinyCloud One
// asks for more than the Home sign-in grant holds. It runs on the sign-in screen's approve protocol; consent is
// all-or-nothing (no toggles), and a space the account does not host is told up front with nothing to Allow.
import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
const caps = 'tinycloud.capabilities/read';
const kvGet = 'tinycloud.kv/get';
const kvList = 'tinycloud.kv/list';
const kvPut = 'tinycloud.kv/put';
const sqlRead = 'tinycloud.sql/read';
const siwe = (resources: Record<string, Record<string, unknown[]>>) => [
  'openkey.so wants you to sign in with your Ethereum account:', address, '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-07T04:00:00.000Z',
  'Expiration Time: 2026-10-07T05:00:00.000Z', 'Resources:', `- ${makeRecapResource(resources)}`,
].join('\n');
const option = (service: string, space: string, path: string, abilities: string[]) => {
  const short = service.split('.')[1];
  const key = `${service}\0${spaceId(space)}\0${path}`;
  return { key, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
    actions: abilities.map(ability => ({ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required: true })) };
};

const stepUpSiwe = siwe({
  [`${spaceId('account')}/capabilities`]: { [caps]: [{}] },
  [`${spaceId('account')}/kv/applications/`]: { [kvGet]: [{}], [kvList]: [{}] },
  [`${spaceId('agents')}/sql/`]: { [sqlRead]: [{}] },
});
const permissionOptions = [
  option('tinycloud.capabilities', 'account', '', [caps]),
  option('tinycloud.kv', 'account', 'applications/', [kvGet, kvList]),
  option('tinycloud.sql', 'agents', '', [sqlRead]),
];
const selectedActionKeys = permissionOptions.flatMap(p => p.actions.map(a => a.key));
const spaces = [{ space: 'account', spaceId: spaceId('account') }, { space: 'agents', spaceId: spaceId('agents') }];
const stepUp = (appId = 'xyz.tinycloud.explorer') => ({
  requestId: 'native-1', userId: 'u', keyId: 'key-1', address, kind: 'STEPUP', stepUp: { grantId: 'grant-1', appId }, spaces, reactivation: false,
  client: { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' },
  redirectScheme: 'xyz.tinycloud.exo', sessionDid: 'did:key:z6Mk', tinycloudHost: 'https://tee.node.tinycloud.xyz', ttlSeconds: 3600,
  grantLifetimeSeconds: 2000000, hostPlan: null, permissionOptions, selectedActionKeys, sessionSiwe: stepUpSiwe,
});

const signInSpace = spaceId('applications');
const signInOptions = [option('tinycloud.capabilities', 'applications', '', [caps]),
  option('tinycloud.kv', 'applications', 'xyz.tinycloud.tinychat/threads/', [kvGet, kvPut])];
const signIn = () => ({ ...stepUp(), kind: undefined, stepUp: undefined, spaces: undefined, reactivation: undefined,
  hostPlan: { host: 'https://tee.node.tinycloud.xyz', spaceId: signInSpace, peerId: 'did:key:z6Mk', hostSiwe: 'host bytes' },
  permissionOptions: signInOptions, selectedActionKeys: signInOptions.flatMap(p => p.actions.map(a => a.key)),
  sessionSiwe: siwe({ [`${signInSpace}/capabilities`]: { [caps]: [{}] },
    [`${signInSpace}/kv/xyz.tinycloud.tinychat/threads/`]: { [kvGet]: [{}], [kvPut]: [{}] } }) });

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const sessionBody = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } };
const EXO_BRANDING = { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' };
const unhostedBody = { error: 'space_not_hosted', error_description: `Spaces not hosted on this node: ${spaceId('account')}` };
const PREWARN = /One of the spaces this app needs is not set up on your TinyCloud account yet, so it can’t be allowed yet\./;
const CONSENT_URL = '/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test';

interface Calls { prepares: number; approves: Record<string, any>[]; denies: number; providers: boolean[] }
/** Mocks the native consent API. `prepare` answers each prepare call (by index); `approve` each approval. */
async function setup(page: Page, prepare: (n: number) => { status?: number; body: unknown }, approve?: (n: number) => { status: number; body: unknown }) {
  const calls: Calls = { prepares: 0, approves: [], denies: 0, providers: [] };
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, sessionBody);
    if (path === '/api/oauth/tinycloud/clients/exo-native/branding') return json(route, EXO_BRANDING);
    if (path.endsWith('/prepare')) {
      const reply = prepare(calls.prepares++);
      return json(route, reply.body, reply.status ?? 200);
    }
    if (path.endsWith('/approve')) {
      calls.approves.push(route.request().postDataJSON());
      const reply = approve?.(calls.approves.length - 1) ?? { status: 200, body: { status: 'APPROVED', revision: 1 } };
      return json(route, reply.body, reply.status);
    }
    if (path.endsWith('/deny')) { calls.denies++; return json(route, { status: 'DENIED' }); }
    if (path === '/api/auth/oauth2/consent') {
      calls.providers.push(route.request().postDataJSON().accept);
      return json(route, { url: 'https://example.test/callback?code=code' });
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.route('https://example.test/**', route => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>app</p>' }));
  await page.goto(CONSENT_URL);
  return calls;
}
const allow = (page: Page) => page.getByRole('button', { name: 'Allow', exact: true });

test.describe('native step-up consent', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('names the app and what it adds, has no toggles, and approve echoes the revision and digest', async ({ page }) => {
    const calls = await setup(page, n => ({ body: { ...stepUp(), revision: n + 1, digest: `digest-${n + 1}` } }));
    await expect(page.getByRole('heading', { name: 'Give Explorer more access' })).toBeVisible();
    await expect(page.getByText('Explorer will be able to read more of your data than Exo can today.')).toBeVisible();
    await expect(page.getByText('This is added to what Exo already has access to.')).toBeVisible();
    await expect(page.getByText('Explorer stays allowed and renews with Exo until you remove it.')).toBeVisible();
    await expect(page.getByText('Signed in as')).toContainText('sam@example.test');
    // Every space and capability, in read-only words; the plumbing capabilities read is not listed.
    await expect(page.getByText(/^The account space$/)).toBeVisible();
    await expect(page.getByText(/^The agents space$/)).toBeVisible();
    await expect(page.getByText('kv/applications/', { exact: true })).toBeVisible();
    await expect(page.getByText('Read only: read, list')).toBeVisible();
    await expect(page.getByText('sql', { exact: true })).toBeVisible();
    await expect(page.getByText('Read only: read', { exact: true })).toBeVisible();
    await expect(page.getByText('capabilities', { exact: true })).toHaveCount(0);
    await expect(page.getByText(/renews automatically/)).toHaveCount(0);
    await expect(page.getByText(/First sign-in/)).toHaveCount(0);
    // All-or-nothing: nothing to switch off, not even inside Details.
    await page.locator('details.details > summary').click();
    await expect(page.getByRole('checkbox')).toHaveCount(0);
    await expect(page.getByText('xyz.tinycloud.explorer', { exact: true })).toBeVisible();
    await expect(page.getByText('xyz.tinycloud.exo://')).toBeVisible();
    await expect(page.getByRole('button', { name: "Don't allow", exact: true })).toBeVisible();

    await allow(page).click();
    await expect.poll(() => calls.approves.length).toBe(1);
    expect(calls.approves[0]).toEqual({ revision: 1, digest: 'digest-1', sessionSiwe: stepUpSiwe });
    expect(calls.prepares).toBe(1);
    await expect.poll(() => calls.providers).toEqual([true]);
    await page.waitForURL('https://example.test/callback?code=code');
  });

  for (const [appId, name] of [['xyz.tinycloud.explorer', 'Explorer'], ['xyz.tinycloud.account', 'Account'], ['xyz.tinycloud.courier', 'Courier'],
    ['com.example.notes', 'com.example.notes']]) {
    test(`shows ${name} for app id ${appId}`, async ({ page }) => {
      await setup(page, () => ({ body: { ...stepUp(appId), revision: 1, digest: 'digest-1' } }));
      await expect(page.getByRole('heading', { name: `Give ${name} more access` })).toBeVisible();
      await expect(page.getByText(`${name} stays allowed and renews with Exo until you remove it.`)).toBeVisible();
    });
  }

  test('says what a step-up can change when it is not read only', async ({ page }) => {
    const writable = option('tinycloud.kv', 'account', 'notes/', [kvGet, kvPut]);
    await setup(page, () => ({ body: { ...stepUp(), revision: 1, digest: 'digest-1', permissionOptions: [writable],
      sessionSiwe: siwe({ [`${spaceId('account')}/kv/notes/`]: { [kvGet]: [{}], [kvPut]: [{}] } }) } }));
    await expect(page.getByText('Explorer will be able to use more of your data than Exo can today.')).toBeVisible();
    await expect(page.getByText('Can change data: read, put')).toBeVisible();
  });

  test('a reactivation says the app was removed and is being allowed again', async ({ page }) => {
    await setup(page, () => ({ body: { ...stepUp(), reactivation: true, revision: 1, digest: 'digest-1' } }));
    await expect(page.getByText('You removed Explorer before. Allowing it now turns it back on.')).toBeVisible();
    await expect(allow(page)).toBeEnabled();
  });

  test('a first-time step-up carries no reactivation copy', async ({ page }) => {
    await setup(page, () => ({ body: { ...stepUp(), revision: 1, digest: 'digest-1' } }));
    await expect(page.getByRole('heading', { name: 'Give Explorer more access' })).toBeVisible();
    await expect(page.getByText(/You removed/)).toHaveCount(0);
  });

  test('Don’t allow denies the request and tells the provider', async ({ page }) => {
    const calls = await setup(page, () => ({ body: { ...stepUp(), revision: 1, digest: 'digest-1' } }));
    await page.getByRole('button', { name: "Don't allow", exact: true }).click();
    await expect.poll(() => calls.providers).toEqual([false]);
    expect(calls.denies).toBe(1);
    expect(calls.approves).toHaveLength(0);
  });

  test('a prepare that answers space_not_hosted shows the pre-warn, nothing to Allow, and never approves', async ({ page }) => {
    const calls = await setup(page, () => ({ status: 409, body: unhostedBody }));
    await expect(page.getByRole('heading', { name: 'This app can’t be allowed yet' })).toBeVisible();
    await expect(page.getByRole('alert')).toHaveText(PREWARN);
    await expect(page.getByRole('alert')).not.toContainText('Spaces not hosted on this node');
    await expect(allow(page)).toHaveCount(0);
    await expect(page.getByRole('button', { name: "Don't allow" })).toHaveCount(0);
    expect(calls.approves).toHaveLength(0);
    // The way back ends the request instead of leaving it pending.
    await page.getByRole('button', { name: 'Back to the app', exact: true }).click();
    await expect.poll(() => calls.providers).toEqual([false]);
    expect(calls.denies).toBe(1);
    expect(calls.approves).toHaveLength(0);
  });

  test('an approve the node refuses for an unhosted space ends on the same pre-warn with nothing to Allow', async ({ page }) => {
    const calls = await setup(page, () => ({ body: { ...stepUp(), revision: 1, digest: 'digest-1' } }), () => ({ status: 409, body: unhostedBody }));
    await allow(page).click();
    await expect(page.getByRole('alert')).toHaveText(PREWARN);
    await expect(allow(page)).toHaveCount(0);
    expect(calls.approves).toHaveLength(1);
    expect(calls.prepares).toBe(1);
  });

  test('another prepare failure stays a generic error, not the pre-warn', async ({ page }) => {
    await setup(page, () => ({ status: 409, body: { error: 'preparation_superseded' } }));
    await expect(page.getByRole('alert')).toHaveText('preparation_superseded');
    await expect(page.getByText(PREWARN)).toHaveCount(0);
    await expect(allow(page)).toHaveCount(0);
  });

  test('a prepare with no kind is a sign-in and renders the sign-in screen', async ({ page }) => {
    await setup(page, n => ({ body: { ...signIn(), revision: n + 1, digest: `digest-${n + 1}` } }));
    await expect(page.getByRole('heading', { name: 'Exo wants access' })).toBeVisible();
    await expect(page.getByText(/renews automatically while you use Exo\./)).toBeVisible();
    await expect(page.getByText(/First sign-in/)).toBeVisible();
    await expect(page.getByText(/stays allowed/)).toHaveCount(0);
    await expect(allow(page)).toBeEnabled();
  });

  test('kind SIGNIN is a sign-in too', async ({ page }) => {
    await setup(page, () => ({ body: { ...signIn(), kind: 'SIGNIN', revision: 1, digest: 'digest-1' } }));
    await expect(page.getByRole('heading', { name: 'Exo wants access' })).toBeVisible();
    await expect(page.getByText(/renews automatically/)).toBeVisible();
  });

  test('the step-up screen is never inferred from stepUp or spaces: a preview without a kind stays a sign-in', async ({ page }) => {
    await setup(page, () => ({ body: { ...signIn(), stepUp: { grantId: 'grant-1', appId: 'xyz.tinycloud.explorer' }, spaces, revision: 1, digest: 'digest-1' } }));
    await expect(page.getByRole('heading', { name: 'Exo wants access' })).toBeVisible();
    await expect(page.getByText(/renews automatically/)).toBeVisible();
    await expect(page.getByText(/stays allowed/)).toHaveCount(0);
  });

  test('an unknown kind is an error with nothing to Allow', async ({ page }) => {
    const calls = await setup(page, () => ({ body: { ...stepUp(), kind: 'FUTURE', revision: 1, digest: 'digest-1' } }));
    await expect(page.getByRole('alert')).toContainText('This request needs a newer version of the app to approve.');
    await expect(allow(page)).toHaveCount(0);
    expect(calls.approves).toHaveLength(0);
  });

  test('a STEPUP that does not name its app and spaces is an error with nothing to Allow', async ({ page }) => {
    await setup(page, () => ({ body: { ...stepUp(), stepUp: undefined, spaces: undefined, revision: 1, digest: 'digest-1' } }));
    await expect(page.getByRole('alert')).toContainText('This request needs a newer version of the app to approve.');
    await expect(allow(page)).toHaveCount(0);
  });

  test('a stale step-up revision prepares again without asking for optional actions', async ({ page }) => {
    const bodies: unknown[] = [];
    page.on('request', request => { if (request.url().endsWith('/prepare')) bodies.push(request.postDataJSON()); });
    const calls = await setup(page, n => ({ body: { ...stepUp(), revision: n + 1, digest: `digest-${n + 1}` } }),
      n => (n === 0 ? { status: 409, body: { error: 'preparation_superseded' } } : { status: 200, body: { status: 'APPROVED', revision: 2 } }));
    await allow(page).click();
    await expect.poll(() => calls.prepares).toBe(2);
    expect(bodies).toEqual([{}, {}]);
    await expect(allow(page)).toBeEnabled();
    await allow(page).click();
    await expect.poll(() => calls.approves.length).toBe(2);
    expect(calls.approves[1]).toMatchObject({ revision: 2, digest: 'digest-2' });
  });
});

// The passkey path is the sign-in one: Allow answers the revision's challenge and sends the assertion with the approval.
test('Allow on a step-up answers the passkey challenge and sends the assertion with the approval', async ({ page }) => {
  const credentialId = randomBytes(16);
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
  const passkey = { required: true, challengeToken: 'token-1', options: {
    challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
    allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
  } };
  const calls = await setup(page, () => ({ body: { ...stepUp(), revision: 1, digest: 'digest-1', passkey } }));
  await expect(allow(page)).toBeEnabled();
  await allow(page).click();
  await expect.poll(() => calls.approves.length).toBe(1);
  expect(calls.approves[0]).toMatchObject({
    revision: 1, digest: 'digest-1', sessionSiwe: stepUpSiwe,
    passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });
  await page.waitForURL('https://example.test/callback?code=code');
});
