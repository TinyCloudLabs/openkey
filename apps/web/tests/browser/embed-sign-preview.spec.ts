import { test, expect } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, 'localhost:5779');
const previewBytes = `${siwe}\nPreview marker: exact server bytes`;

test('v2 final preview bytes are visible before approval and require a new layout ack', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
    label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({ json: { authorizationContextToken: 'context-token' } }));
  await page.route('**/api/delegate/authorize-sign-preview', async (route) => {
    const body: unknown = route.request().postDataJSON();
    if (!body || typeof body !== 'object' || !('selectedActionIds' in body) || !Array.isArray(body.selectedActionIds)) {
      throw new Error('Preview request did not include the selected actions');
    }
    const selectedActionKeys = body.selectedActionIds.filter((id): id is string => typeof id === 'string');
    const permissions = selectedActionKeys.map((id) => {
      const [service, space, path, ability] = id.split('\0');
      return { service, space, path, actions: [ability] };
    });
    await route.fulfill({ json: { signedMessage: previewBytes, previewApprovalToken: 'preview-token', selectedActionKeys, permissions } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign-v2';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=phase-1&protocolVersion=2&keyId=selected-key`;
    (window as unknown as Window & { received: Array<{ type: string; height?: number; layoutId?: number; requestId?: string }> }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow && event.origin === location.origin) {
        (window as unknown as Window & { received: Array<{ type: string }> }).received.push(event.data);
      }
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; requestId?: string }> }).received.some(m => m.type === 'openkey:ready' && m.requestId === 'phase-1'))).toBe(true);
  await page.evaluate((message) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: 2, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message },
      location.origin,
    );
  }, siwe);
  const frame = page.frameLocator('#sign-v2');
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:resize'))).toBe(true);
  async function applyLatestLayout() {
    const resize = await page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; height: number; layoutId: number }> }).received.filter(m => m.type === 'openkey:resize').at(-1)!);
    await page.evaluate(({ height, layoutId }) => {
      const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2');
      const appliedHeight = Math.min(height, Math.floor(window.innerHeight * 0.85));
      if (iframe) iframe.style.height = `${appliedHeight}px`;
      iframe?.contentWindow?.postMessage({ type: 'openkey:layout-applied', requestId: 'phase-1', protocolVersion: 2, height: appliedHeight, layoutId }, location.origin);
    }, resize);
  }
  await applyLatestLayout();
  const approve = frame.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  await approve.click();
  await expect(frame.getByRole('button', { name: 'Approve exact bytes' })).toBeDisabled();
  await frame.getByText('Advanced details', { exact: true }).click();
  await expect(frame.locator('pre.raw-bytes')).toContainText('Preview marker: exact server bytes');
  await expect(frame.locator('pre.raw-bytes')).toBeVisible();
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.filter(m => m.type === 'openkey:resize').length)).toBeGreaterThan(1);
  await applyLatestLayout();
  await expect(frame.getByRole('button', { name: 'Approve exact bytes' })).toBeEnabled();
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
