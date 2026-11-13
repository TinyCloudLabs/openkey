// TC-2933: the renewal checkbox on the approval-request review page (/a/[id]). Every API call is answered by
// `page.route`; no API server runs. The box's default follows the request's signed purpose, the approve body
// carries the owner's choice, and an external wallet signs the lease as a second step. Set SHOT_DIR to save
// screenshots of each state at 390 and 1280 wide.
import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const fragment = `#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const path = `/a/${id}`;
const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const owner = `did:pkh:eip155:1:${address}`;
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const DAY = 86_400;
const KV_GET = 'tinycloud.kv/get';
const DECRYPT = 'tinycloud.encryption/decrypt';
const decryptResource = `urn:tinycloud:encryption:${owner}:default/apps/xyz.tinycloud.courier/`;
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

type Options = {
  renewal?: boolean;
  purpose?: 'task' | 'standing';
  sensitive?: boolean;
  keyType?: 'MANAGED' | 'EXTERNAL';
};

function prepared(sensitive: boolean) {
  const att: Record<string, Record<string, unknown[]>> = { [`${space}/kv/notes/`]: { [KV_GET]: [{}] } };
  if (sensitive) att[decryptResource] = { [DECRYPT]: [{}] };
  const siwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-11-13T00:00:00.000Z', 'Expiration Time: 2026-12-13T00:00:00.000Z',
    'Resources:', `- ${makeRecapResource(att)}`,
  ].join('\n');
  const optionKey = `tinycloud.kv\0${space}\0notes/`;
  const permissions = [{ key: optionKey, service: 'kv', path: 'notes/', label: 'kv', resourcePath: 'kv/notes/',
    actions: [{ key: `${optionKey}\0${KV_GET}`, action: 'get', ability: KV_GET, required: false }] }];
  return {
    prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: owner, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

const RESULT = { hostActivated: true, delegationHeader: { Authorization: 'x' }, delegationCid: 'bafy-delegation' };

async function serve(page: Page, options: Options = {}) {
  const calls: Array<{ path: string; body: unknown }> = [];
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    calls.push({ path: url.pathname, body: request.postDataJSON?.() ?? null });
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    }
    if (url.pathname === '/api/keys') {
      return json(route, 200, { keys: [{ id: 'key_0', address, publicKey: '0x', keyIndex: 0, label: null, keyType: options.keyType ?? 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }] });
    }
    if (url.pathname === `/api/approval-requests/${id}/load`) {
      const approvalRequest = {
        targetDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
        nodeOrigin: 'https://node.tinycloud.xyz', permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] }],
        grantLifetimeSeconds: 30 * DAY, reason: 'Courier keeps your agent connected',
        ...(options.purpose ? { purpose: options.purpose } : {}),
        ...(options.renewal === false ? {} : { renewal: { version: 1, leaseLifetimeSeconds: 365 * DAY } }),
      };
      return json(route, 200, { requestId: id, expiresAt: new Date(Date.now() + 3600_000).toISOString(), approved: false, denied: false, request: approvalRequest });
    }
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared(options.sensitive ?? false));
    if (url.pathname === '/api/delegate' && request.method() === 'POST') return json(route, 200, RESULT);
    if (url.pathname === '/api/delegate/complete') return json(route, 200, { ...RESULT, renewalSignature: { message: 'renewal lease message' } });
    if (url.pathname === `/api/approval-requests/${id}/renewal-signature`) return json(route, 200, RESULT);
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  return calls;
}

const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });
const box = (page: Page) => page.getByRole('checkbox');
const line = (page: Page) => page.getByTestId('approval-expiry-line');
const approvals = (calls: Array<{ path: string; body: unknown }>) => calls.filter((call) => call.path === '/api/delegate');

async function open(page: Page, options: Options = {}) {
  const calls = await serve(page, options);
  await page.goto(path + fragment);
  await expect(approve(page)).toBeEnabled();
  return calls;
}

test('ongoing access starts ticked, and approving sends the 90-day lease', async ({ page }) => {
  const calls = await open(page, { purpose: 'standing' });
  await expect(box(page)).toBeChecked();
  await expect(line(page)).toHaveText('This permission renews automatically for up to 90 days');
  await expect(page.getByText('(Change)')).toHaveCount(0);
  await approve(page).click();
  await expect.poll(() => approvals(calls).length).toBe(1);
  expect(approvals(calls)[0]!.body).toMatchObject({ renewal: { choice: 'leased', leaseLifetimeSeconds: 90 * DAY } });
});

test('unticked, it says when it expires, and approving sends a finite choice', async ({ page }) => {
  const calls = await open(page, { purpose: 'standing' });
  await box(page).uncheck();
  await expect(line(page)).toHaveText('This permission expires in 30 days');
  await approve(page).click();
  await expect.poll(() => approvals(calls).length).toBe(1);
  expect(approvals(calls)[0]!.body).toMatchObject({ renewal: { choice: 'finite' } });
});

test('a task, or a request without a purpose, starts unticked', async ({ page }) => {
  await open(page, { purpose: 'task' });
  await expect(box(page)).not.toBeChecked();
  await page.goto('about:blank');
  await open(page);
  await expect(box(page)).not.toBeChecked();
});

test('a request that did not ask for renewal shows no box and sends no choice', async ({ page }) => {
  const calls = await open(page, { renewal: false, purpose: 'standing' });
  await expect(box(page)).toHaveCount(0);
  await expect(line(page)).toHaveText('This permission expires in 30 days');
  await approve(page).click();
  await expect.poll(() => approvals(calls).length).toBe(1);
  expect(approvals(calls)[0]!.body).not.toHaveProperty('renewal');
});

test('the lease is changed under the fold', async ({ page }) => {
  const calls = await open(page, { purpose: 'standing' });
  await page.getByText('How long it lasts').click();
  await page.getByRole('button', { name: '1 year' }).click();
  await expect(line(page)).toHaveText('This permission renews automatically for up to 1 year');
  await approve(page).click();
  await expect.poll(() => approvals(calls).length).toBe(1);
  expect(approvals(calls)[0]!.body).toMatchObject({ renewal: { choice: 'leased', leaseLifetimeSeconds: 365 * DAY } });
});

test('ongoing access to decrypt starts unticked, and ticking asks first', async ({ page }) => {
  await open(page, { purpose: 'standing', sensitive: true });
  await expect(box(page)).not.toBeChecked();
  // The box stays unticked until the owner confirms, so this is a click, not `check()`.
  await box(page).click();
  await expect(page.getByRole('alertdialog', { name: 'Renew sensitive access?' })).toBeVisible();
  await page.getByRole('button', { name: "Don't renew" }).click();
  await expect(box(page)).not.toBeChecked();
  await box(page).click();
  await page.getByRole('button', { name: 'Turn on renewal' }).click();
  await expect(box(page)).toBeChecked();
});

async function wallet(page: Page, options: { declineSecond?: boolean } = {}) {
  await page.addInitScript(({ address, declineSecond }) => {
    const signed: string[] = [];
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => { release = resolve; });
    Object.assign(window, { qaSigned: signed, qaReleaseSecond: () => release(), ethereum: {
      on() {}, removeListener() {},
      async request({ method, params }: { method: string; params?: string[] }) {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [address];
        if (method === 'eth_chainId') return '0x1';
        if (method === 'personal_sign') {
          signed.push(params?.[0] ?? '');
          if (signed.length === 2) {
            await held;
            if (declineSecond) throw { code: 4001, message: 'User declined' };
          }
          return `qa-signature-${signed.length}`;
        }
        return null;
      },
    } });
  }, { address, declineSecond: options.declineSecond ?? false });
}

test('an external wallet signs the lease as a second step, then the approval is saved', async ({ page }) => {
  await wallet(page);
  const calls = await open(page, { purpose: 'standing', keyType: 'EXTERNAL' });
  await approve(page).click();
  await expect(page.getByText('Sign once more to turn on renewal')).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { qaSigned: string[] }).qaSigned)).toEqual([expect.any(String), 'renewal lease message']);
  await page.evaluate(() => (window as unknown as { qaReleaseSecond: () => void }).qaReleaseSecond());
  await expect.poll(() => calls.filter((call) => call.path === `/api/approval-requests/${id}/renewal-signature`).length).toBe(1);
  expect(calls.find((call) => call.path === '/api/delegate/complete')!.body).toMatchObject({ renewal: { choice: 'leased', leaseLifetimeSeconds: 90 * DAY } });
  expect(calls.find((call) => call.path === `/api/approval-requests/${id}/renewal-signature`)!.body).toEqual({ signature: 'qa-signature-2' });
});

test('declining the second signature approves nothing', async ({ page }) => {
  await wallet(page, { declineSecond: true });
  const calls = await open(page, { purpose: 'standing', keyType: 'EXTERNAL' });
  await approve(page).click();
  await expect(page.getByText('Sign once more to turn on renewal')).toBeVisible();
  await page.evaluate(() => (window as unknown as { qaReleaseSecond: () => void }).qaReleaseSecond());
  await expect(page.getByText("Renewal wasn't set up, so nothing was approved. Try again.")).toBeVisible();
  expect(calls.filter((call) => call.path === `/api/approval-requests/${id}/renewal-signature`)).toEqual([]);
});

for (const [name, viewport] of [['390', { width: 390, height: 844 }], ['1280', { width: 1280, height: 900 }]] as const) {
  test(`screenshots at ${name}: ticked, unticked, fold open, sensitive warning, wallet second signature`, async ({ page }) => {
    const shots = process.env.SHOT_DIR;
    const shot = async (label: string) => { if (shots) await page.screenshot({ path: `${shots}/renewal-${label}-${name}.png` }); };
    await page.setViewportSize(viewport);
    await open(page, { purpose: 'standing' });
    await line(page).scrollIntoViewIfNeeded();
    await shot('1-ticked');
    await box(page).uncheck();
    await shot('2-unticked');
    await box(page).check();
    await page.getByText('How long it lasts').click();
    await page.getByRole('button', { name: '1 year' }).scrollIntoViewIfNeeded();
    await shot('3-fold-open');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);

    await page.goto('about:blank');
    await open(page, { purpose: 'standing', sensitive: true });
    await box(page).click();
    await page.getByRole('alertdialog').scrollIntoViewIfNeeded();
    await shot('4-sensitive-warning');

    await page.goto('about:blank');
    await wallet(page);
    await open(page, { purpose: 'standing', keyType: 'EXTERNAL' });
    await approve(page).click();
    await page.getByText('Sign once more to turn on renewal').scrollIntoViewIfNeeded();
    await shot('5-wallet-second-signature');
    await page.evaluate(() => (window as unknown as { qaReleaseSecond: () => void }).qaReleaseSecond());
  });
}
