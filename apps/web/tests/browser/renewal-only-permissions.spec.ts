import { test, expect, type Page } from '@playwright/test';
import { makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { HOST, ORIGIN } from './e2e-port';
import { TERMS_ACCEPTED } from './terms-fixtures';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const secrets = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default/secrets/`;
const first = `${secrets}first`;
const second = `${secrets}second`;
const read = 'tinycloud.capabilities/read';
const decrypt = 'tinycloud.encryption/decrypt';
const ordinary = `tinycloud.capabilities\0${space}\0\0${read}`;
const actionId = (resource: string) => `tinycloud.encryption\0encryption\0${resource}\0${decrypt}`;
const leaseLifetimeSeconds = 90 * 86_400;

type Message = { type: string; success?: boolean; signedMessage?: string; height?: number; layoutId?: number };
type HostWindow = Window & { widget: Window; received: Message[] };
type Preview = { selectedActionIds: string[]; signedMessage: string; renewal?: { choice: string; sensitiveConfirmed?: boolean } };

async function open(page: Page, options: { iframe?: boolean; prefix?: boolean; unavailable?: boolean; exactBytes?: boolean } = {}) {
  const previews: Preview[] = [];
  const signs: Array<{ previewApprovalToken: string; selectedActionIds: string[] }> = [];
  const now = Date.now();
  const keyResources = options.prefix ? [secrets] : [first, second];
  const recap = (resources: string[], expiry?: string) => siweWithResources([makeRecapResource({
    [`${space}/capabilities`]: { [read]: [{}] },
    ...Object.fromEntries(resources.map((resource) => [resource, { [decrypt]: [{}] }])),
  })], {
    domain: HOST, address, uri: ORIGIN, issuedAt: new Date(now).toISOString(),
    expirationTime: expiry ?? new Date(now + 3_600_000).toISOString(),
  });
  const permissions = (ids: string[]) => ids.map((id) => {
    const [service, space, path, ability] = id.split('\0');
    return { service, space, path, actions: [ability] };
  });

  const context = page.context();
  await context.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await context.route('**/api/auth/get-session**', (route) => route.fulfill({ json: {
    session: { id: 'test-session' }, user: { id: 'test-user' },
  } }));
  await context.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await context.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected',
    keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await context.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({ json: {
    authorizationContextToken: 'context',
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    ...(options.unavailable ? {} : { renewal: { leaseLifetimeSeconds } }),
  } }));
  await context.route('**/api/delegate/authorize-sign-preview', (route) => {
    const { selectedActionIds, renewal, expirationTime } = route.request().postDataJSON();
    const signedMessage = recap(keyResources.filter((resource) => selectedActionIds.includes(actionId(resource))), expirationTime);
    previews.push({ selectedActionIds, signedMessage, renewal });
    return route.fulfill({ json: {
      previewApprovalToken: `preview-${previews.length}`,
      previewApprovalExpiresAt: new Date(Date.now() + 300_000).toISOString(),
      selectedActionKeys: selectedActionIds, permissions: permissions(selectedActionIds),
      signedMessage, passkey: { required: false },
    } });
  });
  await context.route('**/api/delegate/authorize-sign', (route) => {
    const body = route.request().postDataJSON();
    signs.push(body);
    const preview = previews[Number(body.previewApprovalToken.slice('preview-'.length)) - 1]!;
    expect(body.selectedActionIds).toEqual(preview.selectedActionIds);
    return route.fulfill({ json: { address, signature: '0x11', signedMessage: preview.signedMessage,
      selectedActionKeys: preview.selectedActionIds, permissions: permissions(preview.selectedActionIds),
    } });
  });

  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', (event) => {
      if (event.origin !== location.origin || event.source !== host.widget) return;
      host.received.push(event.data);
      const iframe = document.querySelector<HTMLIFrameElement>('#sign');
      if (event.data.type !== 'openkey:resize' || !iframe) return;
      const height = Math.min(Number(event.data.height), Math.floor(innerHeight * 0.85));
      iframe.style.height = `${height}px`;
      host.widget.postMessage({ type: 'openkey:layout-applied', requestId: 'renewal-only',
        protocolVersion: 2, height, layoutId: event.data.layoutId }, location.origin);
    });
  });

  let popup: Page | undefined;
  if (options.iframe) {
    await page.evaluate(() => {
      const iframe = document.createElement('iframe');
      iframe.id = 'sign';
      iframe.style.width = '700px';
      iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=renewal-only&protocolVersion=2&keyId=selected-key`;
      document.body.append(iframe);
      (window as unknown as HostWindow).widget = iframe.contentWindow!;
    });
  } else {
    const opened = page.waitForEvent('popup');
    await page.evaluate(() => {
      (window as unknown as HostWindow).widget = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`)!;
    });
    popup = await opened;
  }
  const messages = () => page.evaluate(() => (window as unknown as HostWindow).received ?? []);
  await expect.poll(async () => (await messages()).some((message) => message.type === 'openkey:ready')).toBe(true);
  await page.evaluate((request) => (window as unknown as HostWindow).widget.postMessage(request, location.origin), {
    type: 'openkey:sign:request', requestId: 'renewal-only', protocolVersion: options.iframe ? 2 : 1,
    authorizationProtocolVersion: options.exactBytes ? undefined : 1, keyId: 'selected-key', jwk: { kty: 'EC' },
    message: recap(keyResources), expiryChangeable: true,
    renewal: { version: 1, leaseLifetimeSeconds, purpose: 'standing' }, renewalOnlyResources: keyResources,
  });

  const view = popup ?? page.frameLocator('#sign');
  const approve = view.getByRole('button', { name: 'Approve', exact: true });
  const box = view.locator('input.renewal-box');
  const renewalRows = view.getByRole('region', { name: 'Only with renewal' });
  if (!options.exactBytes) await expect(approve).toBeEnabled();
  async function turnOn() {
    await box.click();
    await expect(view.getByRole('alertdialog', { name: 'Renew sensitive access?' })).toBeVisible();
    await view.getByRole('button', { name: 'Turn on renewal' }).click();
    await expect(box).toBeChecked();
    await expect(approve).toBeEnabled();
  }
  async function signedMessage() {
    await approve.click();
    const response = async () => (await messages()).find((message) => message.type === 'openkey:sign:response' && message.success);
    await expect.poll(async () => (await response())?.signedMessage).toBeTruthy();
    expect(signs).toHaveLength(1);
    return (await response())!.signedMessage;
  }

  return { view, approve, box, renewalRows, previews, turnOn, signedMessage, ordinaryMessage: recap([]) };
}

for (const iframe of [false, true]) {
  test(`${iframe ? 'iframe' : 'popup'} seals exact keys only when renewal is on`, async ({ page }) => {
    const h = await open(page, { iframe });
    await expect(h.box).not.toBeChecked();
    await expect(h.renewalRows).toContainText(`${HOST} gets these only if renewal is on.`);
    await expect(h.renewalRows).toContainText('first');
    expect(h.previews).toHaveLength(1);
    expect(h.previews[0]).toMatchObject({ selectedActionIds: [ordinary], renewal: { choice: 'finite' } });

    await h.turnOn();
    expect(h.previews).toHaveLength(2);
    expect(h.previews[1]).toMatchObject({
      selectedActionIds: [ordinary, actionId(first), actionId(second)],
      renewal: { choice: 'leased', sensitiveConfirmed: true },
    });
    await expect(h.renewalRows).toContainText(`${HOST} gets these only if renewal is on.`);

    await h.box.uncheck();
    await expect(h.renewalRows).toContainText(`Renewal is off, so ${HOST} doesn't get these.`);
    await expect(h.approve).toBeEnabled();
    expect(h.previews).toHaveLength(3);
    expect(h.previews[2]).toMatchObject({ selectedActionIds: [ordinary], renewal: { choice: 'finite' } });
    expect(await h.signedMessage()).toBe(h.previews[2]!.signedMessage);
    expect(h.previews[2]!.signedMessage.split('\n').at(-1)).toBe(h.ordinaryMessage.split('\n').at(-1));
  });
}

test('the owner can remove an exact key across renewal toggles', async ({ page }) => {
  const h = await open(page);
  await h.turnOn();
  await h.view.getByText('Advanced details', { exact: true }).click();
  await h.view.getByRole('button', { name: 'Edit', exact: true }).click();
  const firstGrant = h.view.getByRole('listitem').filter({
    has: h.view.getByLabel(`Exact resource: ${first}`, { exact: true }),
  });
  await firstGrant.getByRole('checkbox', { name: 'decrypt' }).uncheck();
  await expect(h.approve).toBeEnabled();
  expect(h.previews.at(-1)?.selectedActionIds).toEqual([ordinary, actionId(second)]);

  await h.box.uncheck();
  await expect(h.approve).toBeEnabled();
  await h.turnOn();
  expect(h.previews).toHaveLength(5);
  expect(h.previews.at(-1)?.selectedActionIds).toEqual([ordinary, actionId(second)]);
  await expect(firstGrant.getByRole('checkbox', { name: 'decrypt' })).not.toBeChecked();
});

test('a prefix stays an ordinary permission', async ({ page }) => {
  const warnings: string[] = [];
  page.context().on('console', (message) => {
    if (message.type() === 'warning') warnings.push(message.text());
  });
  const h = await open(page, { prefix: true });
  expect(warnings).toContain('[widget-transport] dropping malformed renewal-only resources');
  await expect(h.box).not.toBeChecked();
  await expect(h.renewalRows).toHaveCount(0);
  expect(h.previews.at(-1)?.selectedActionIds).toEqual([ordinary, actionId(secrets)]);
});

test('unavailable renewal excludes exact keys from the signed request', async ({ page }) => {
  const h = await open(page, { unavailable: true });
  await expect(h.box).toHaveCount(0);
  await expect(h.renewalRows).toContainText(`Renewal isn't available for this sign-in, so ${HOST} doesn't get these.`);
  expect(h.previews).toHaveLength(1);
  expect(h.previews[0]).toMatchObject({ selectedActionIds: [ordinary], signedMessage: h.ordinaryMessage });
  expect(h.previews[0]!.renewal).toBeUndefined();
  expect(await h.signedMessage()).toBe(h.ordinaryMessage);
});

test('exact-byte signing cannot approve renewal-only keys', async ({ page }) => {
  const h = await open(page, { iframe: true, exactBytes: true });
  await expect(h.view.getByText(
    `OpenKey can't show what this sign-in allows, so it can't be approved. Ask ${HOST} to try again.`,
    { exact: true },
  )).toBeVisible();
  await expect(h.approve).toBeDisabled();
  await expect(h.view.getByRole('button', { name: 'Cancel', exact: true })).toBeEnabled();
  expect(h.previews).toHaveLength(0);
});
