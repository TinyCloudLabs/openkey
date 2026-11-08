import { test, expect, type Page, type Route } from '@playwright/test';
import { HOST } from './e2e-port';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);

type Body = Record<string, unknown>;
type HostWindow = Window & { received: Body[]; signWindow: Window };
type Preview = { route: Route; ids: string[]; context: string; token: string; bytes: string };

// Hold each preview independently so the browser, rather than a stub adapter,
// exercises the route's generation, expiry and click guards.
async function openSigning(page: Page, surface: 'popup' | 'iframe', options: {
  external?: boolean; mismatch?: boolean; previewTtl?: number; contextTtl?: number;
} = {}) {
  const previews: Preview[] = [];
  const signs: Body[] = [];
  let prepares = 0;
  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().route('**/api/keys/**', route => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
    label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.context().route('**/api/auth/get-session**', route => route.fulfill({ json: {
    session: { id: 'test-session' }, user: { id: 'test-user' },
  } }));
  let signingPage = page;
  const now = () => signingPage.evaluate(() => Date.now());
  await page.context().route('**/api/delegate/authorize-sign-prepare', async route => {
    prepares++;
    const time = await now();
    await route.fulfill({ headers: { Date: new Date(time).toUTCString() }, json: {
      authorizationContextToken: `context-${prepares}`,
      expiresAt: new Date(time + (options.contextTtl ?? 300_000)).toISOString(),
    } });
  });
  await page.context().route('**/api/delegate/authorize-sign-preview', route => {
    const body = route.request().postDataJSON();
    expect(Array.isArray(body.selectedActionIds)).toBe(true);
    previews.push({ route, ids: body.selectedActionIds, context: body.authorizationContextToken,
      token: `preview-${previews.length + 1}`, bytes: `${siwe}\nPreview marker: ${previews.length + 1}` });
  });
  await page.context().route('**/api/delegate/authorize-sign', async route => {
    const body = route.request().postDataJSON();
    signs.push(body);
    const preview = previews.find(p => p.token === body.previewApprovalToken)!;
    expect(preview).toBeTruthy();
    expect(body.authorizationContextToken).toBe(preview.context);
    expect(body.selectedActionIds).toEqual(preview.ids);
    await route.fulfill({ json: {
      signature: `0x${'11'.repeat(65)}`, address,
      signedMessage: options.mismatch ? `${preview.bytes}\nchanged` : preview.bytes,
      selectedActionKeys: preview.ids, permissions: permissions(preview.ids),
    } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', event => {
      if (event.origin === location.origin && event.source === host.signWindow) host.received.push(event.data);
    });
  });
  if (surface === 'popup') {
    const popup = page.waitForEvent('popup');
    await page.evaluate(() => {
      (window as unknown as HostWindow).signWindow = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`)!;
    });
    signingPage = await popup;
  } else {
    await page.evaluate(() => {
      const iframe = document.createElement('iframe');
      iframe.id = 'sign';
      iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=background&protocolVersion=2&keyId=selected-key`;
      iframe.style.width = '700px';
      document.body.append(iframe);
      (window as unknown as HostWindow).signWindow = iframe.contentWindow!;
    });
  }
  await expect.poll(() => page.evaluate(() => (window as unknown as HostWindow).received.some(m => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate(({ message, external, version }) => {
    (window as unknown as HostWindow).signWindow.postMessage({
      type: 'openkey:sign:request', requestId: 'background', protocolVersion: version,
      authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message, externalSign: external,
    }, location.origin);
  }, { message: siwe, external: options.external ?? false, version: surface === 'iframe' ? 2 : 1 });
  const view = surface === 'popup' ? signingPage : page.frameLocator('#sign');
  const approve = view.getByRole('button', { name: 'Approve', exact: true });
  await expect.poll(() => previews.length).toBe(1);
  async function release(index: number) {
    const preview = previews[index]!;
    const time = await now();
    await preview.route.fulfill({ headers: { Date: new Date(time).toUTCString() }, json: {
      authorizationContextToken: preview.context, previewApprovalToken: preview.token,
      previewApprovalExpiresAt: new Date(time + (options.previewTtl ?? 60_000)).toISOString(),
      signedMessage: preview.bytes, selectedActionKeys: preview.ids, permissions: permissions(preview.ids),
    } });
  }
  async function ack() {
    if (surface === 'popup') return;
    await page.evaluate(() => {
      const host = window as unknown as HostWindow;
      const resize = host.received.filter(m => m.type === 'openkey:resize').at(-1);
      if (!resize) return;
      const height = Math.min(Number(resize.height), Math.floor(innerHeight * 0.85));
      document.querySelector<HTMLIFrameElement>('#sign')!.style.height = `${height}px`;
      host.signWindow.postMessage({ type: 'openkey:layout-applied', requestId: 'background',
        protocolVersion: 2, height, layoutId: resize.layoutId }, location.origin);
    });
  }
  async function ready() {
    await expect(async () => {
      await ack();
      await expect(approve).toBeEnabled({ timeout: 500 });
    }).toPass();
  }
  async function edit() {
    await view.getByText('Advanced details', { exact: true }).click();
    await view.getByRole('button', { name: 'Edit', exact: true }).click();
    return view.getByRole('checkbox').first();
  }
  const messages = () => page.evaluate(() => (window as unknown as HostWindow).received);
  return { view, approve, previews, signs, release, ack, ready, edit, messages, signingPage, prepares: () => prepares };
}

function permissions(ids: string[]) {
  return ids.map(id => {
    const [service, space, path, ability] = id.split('\0');
    return { service, space, path, actions: [ability] };
  });
}

for (const surface of ['popup', 'iframe'] as const) {
  test(`${surface}: background preview needs only one Approve to sign`, async ({ page }) => {
    const h = await openSigning(page, surface);
    await expect(h.approve).toBeDisabled();
    expect(h.signs).toHaveLength(0);
    await h.release(0);
    await h.ready();
    await h.approve.click();
    await expect.poll(() => h.signs.length).toBe(1);
    expect(h.signs[0]!.previewApprovalToken).toBe(h.previews[0]!.token);
    await expect.poll(async () => (await h.messages()).filter(m => m.type === 'openkey:sign:response' && m.success === true).length).toBe(1);
  });

  test(`${surface}: fetching blocks Approve while selection remains editable`, async ({ page }) => {
    const h = await openSigning(page, surface);
    await h.ack();
    await expect(h.approve).toBeDisabled();
    const checkbox = await h.edit();
    await expect(checkbox).toBeEnabled();
    await checkbox.uncheck();
    await expect.poll(() => h.previews.length).toBe(2);
    await expect(checkbox).toBeEnabled();
    await expect(h.approve).toBeDisabled();
    await h.release(1);
    await h.ready();
    await h.approve.click();
    await expect.poll(() => h.signs.length).toBe(1);
    expect(h.signs[0]!.previewApprovalToken).toBe(h.previews[1]!.token);
    await expect.poll(async () => (await h.messages()).filter(m => m.type === 'openkey:sign:response' && m.success === true).length).toBe(1);
  });

  test(`${surface}: late old preview cannot replace the current selection or raw details`, async ({ page }) => {
    const h = await openSigning(page, surface);
    const checkbox = await h.edit();
    await checkbox.uncheck();
    await expect.poll(() => h.previews.length).toBe(2);
    await h.release(1);
    await expect(h.view.locator('pre.raw-bytes')).toHaveText(h.previews[1]!.bytes);
    await h.release(0);
    // A layout frame lets the late response's continuation and effects settle.
    await h.signingPage.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(h.view.locator('pre.raw-bytes')).toHaveText(h.previews[1]!.bytes);
    await h.ready();
    await h.approve.click();
    await expect.poll(() => h.signs.length).toBe(1);
    expect(h.signs[0]!.previewApprovalToken).toBe(h.previews[1]!.token);
  });

  test(`${surface}: selection change racing approval never signs a different selection with an old token`, async ({ page }) => {
    const h = await openSigning(page, surface);
    await h.release(0);
    const checkbox = await h.edit();
    await h.ready();
    // Start the user edit first, then attempt the approval while its preview is held.
    await checkbox.uncheck();
    await h.approve.click({ force: true });
    await expect.poll(() => h.previews.length).toBe(2);
    expect(h.signs).toHaveLength(0);
    await h.release(1);
    await h.ready();
    await h.approve.click();
    await expect.poll(() => h.signs.length).toBe(1);
    expect(h.signs[0]!.selectedActionIds).toEqual(h.previews[1]!.ids);
    expect(h.signs[0]!.previewApprovalToken).toBe(h.previews[1]!.token);
  });

  for (const contextExpires of [false, true]) {
    test(`${surface}: expired preview refetches${contextExpires ? ' with a fresh context' : ' using the live context'} before approval`, async ({ page }) => {
      await page.clock.install();
      const h = await openSigning(page, surface, { previewTtl: 5000, contextTtl: contextExpires ? 5000 : 300_000 });
      await h.release(0);
      await h.ready();
      await h.signingPage.clock.runFor(6000);
      await expect.poll(() => h.previews.length).toBe(2);
      expect(h.prepares()).toBe(contextExpires ? 2 : 1);
      expect(h.previews[1]!.context === h.previews[0]!.context).toBe(!contextExpires);
      await h.ack();
      await expect(h.approve).toBeDisabled();
      expect(h.signs).toHaveLength(0);
      await h.release(1);
      await h.ready();
      await h.approve.click();
      await expect.poll(() => h.signs.length).toBe(1);
      expect(h.signs[0]!.previewApprovalToken).toBe(h.previews[1]!.token);
    });
  }

  test(`${surface}: a server signedMessage mismatch emits no successful sign response`, async ({ page }) => {
    const h = await openSigning(page, surface, { mismatch: true });
    await h.release(0);
    await h.ready();
    await h.approve.click();
    await expect.poll(() => h.signs.length).toBe(1);
    await expect(h.view.getByRole('alert')).toBeVisible();
    expect((await h.messages()).filter(m => m.type === 'openkey:sign:response' && m.success === true)).toEqual([]);
  });

  test(`${surface}: external approval hands off the current preview exactly once`, async ({ page }) => {
    const h = await openSigning(page, surface, { external: true });
    const checkbox = await h.edit();
    await checkbox.uncheck();
    await expect.poll(() => h.previews.length).toBe(2);
    await h.release(1);
    await h.ready();
    await h.approve.click();
    await expect.poll(async () => (await h.messages()).filter(m => m.type === 'openkey:externalSign:approve').length).toBe(1);
    const message = (await h.messages()).find(m => m.type === 'openkey:externalSign:approve');
    expect(message).toMatchObject({ requestId: 'background', protocolVersion: surface === 'iframe' ? 2 : 1,
      success: true, address, authorizationContextToken: h.previews[1]!.context,
      previewApprovalToken: h.previews[1]!.token, signedMessage: h.previews[1]!.bytes,
      selectedActionIds: h.previews[1]!.ids });
    expect(h.signs).toHaveLength(0);
  });
}

test('v2 background preview and raw details need a current layout ack before the single approval', async ({ page }) => {
  const h = await openSigning(page, 'iframe');
  // openSigning observed the preview request without any layout acknowledgement.
  await h.ack();
  await expect(h.approve).toBeDisabled();
  await h.release(0);
  await h.view.getByText('Advanced details', { exact: true }).click();
  await expect(h.view.locator('pre.raw-bytes')).toHaveText(h.previews[0]!.bytes);
  await expect(h.view.locator('pre.raw-bytes')).toBeVisible();
  await expect(h.approve).toBeDisabled();
  expect(h.signs).toHaveLength(0);
  await h.ready();
  await h.approve.click();
  await expect.poll(() => h.signs.length).toBe(1);
});

test('ordinary v2 SIWE ReCap signs exact bytes without entering authorization preview', async ({ page }) => {
  let prepares = 0;
  let signs = 0;
  let signedExactly = false;
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => {
    if (route.request().url().endsWith('/sign')) {
      signs++;
      signedExactly = route.request().postDataJSON()?.message === siwe;
      return route.fulfill({ json: { signature: '0x00', address } });
    }
    return route.fulfill({ json: { key: {
      id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
      label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
    } } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => {
    prepares++;
    return route.fulfill({ json: { authorizationContextToken: 'fixture' } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign-v2';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=phase-plain&protocolVersion=2&keyId=selected-key`;
    (window as unknown as Window & { received: Array<{ type: string; height?: number; layoutId?: number }> }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow && event.origin === location.origin) {
        (window as unknown as Window & { received: unknown[] }).received.push(event.data);
      }
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate((message) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'phase-plain', protocolVersion: 2, keyId: 'selected-key', message },
      location.origin,
    );
  }, siwe);
  const frame = page.frameLocator('#sign-v2');
  const approve = frame.getByRole('button', { name: 'Approve', exact: true });
  await frame.getByText('Advanced details', { exact: true }).click();
  await expect(frame.getByRole('button', { name: 'Edit', exact: true })).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:resize'))).toBe(true);
  const resize = await page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; height: number; layoutId: number }> }).received.filter(m => m.type === 'openkey:resize').at(-1)!);
  await page.evaluate(({ height, layoutId }) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2');
    const appliedHeight = Math.min(height, Math.floor(window.innerHeight * 0.85));
    if (iframe) iframe.style.height = `${appliedHeight}px`;
    iframe?.contentWindow?.postMessage({ type: 'openkey:layout-applied', requestId: 'phase-plain', protocolVersion: 2, height: appliedHeight, layoutId }, location.origin);
  }, resize);
  await expect(approve).toBeEnabled();
  await approve.click();
  await expect.poll(() => signs).toBe(1);
  expect(signedExactly).toBe(true);
  await expect.poll(() => page.evaluate(() =>
    (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:sign:response'),
  )).toBe(true);
  const exactMetadata = await page.evaluate(() => {
    const messages = (window as unknown as Window & { received: Array<{ type: string; selectedActionKeys?: string[]; permissions?: Array<{ actions: string[] }> }> }).received;
    const response = messages.find(m => m.type === 'openkey:sign:response');
    return response?.selectedActionKeys?.some(key => key.endsWith('tinycloud.kv/put')) &&
      response?.permissions?.some(grant => grant.actions.includes('tinycloud.kv/put'));
  });
  expect(exactMetadata).toBe(true);
  expect(prepares).toBe(0);
});
