// QA-only fixtures and mocked APIs; typed-data owner choice never reaches a live account.
import { test, expect, type Page } from '@playwright/test';
import { HOST } from './e2e-port';

const key = (id: string, keyIndex: number, isPrimary = false, keyType = 'MANAGED') => ({
  id, keyIndex, isPrimary, keyType, label: `Key ${keyIndex}`,
  address: `0x${String(keyIndex + 1).repeat(40)}`, publicKey: '0x', createdAt: '2026-01-01T00:00:00Z',
});
const primary = key('qa-primary', 2, true);
const other = key('qa-other', 4);
const archived = { ...key('qa-archived', 0), archivedAt: '2026-11-01T00:00:00Z' };
const external = key('qa-external', 5, false, 'EXTERNAL');
const archivedMessage = 'This key was archived. Reconnect to choose a key.';
type Response = { type: string; success?: boolean; error?: { code: string; message: string } };
type Recording = Window & { received?: Response[] };
const reconnectHint = `Go back to ${HOST} and connect again to choose a key.`;

async function expectBackToApp(page: Page, frame: ReturnType<Page['frameLocator']>, message: string) {
  await expect(frame.getByText(reconnectHint, { exact: true })).toBeVisible();
  await frame.getByRole('button', { name: 'Back to app', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as Recording).received?.filter(
    message => message.type === 'openkey:signTypedData:response' || message.type === 'openkey:close',
  ))).toEqual([
    { type: 'openkey:signTypedData:response', success: false, error: { code: 'NO_KEY', message: `${message} ${reconnectHint}` } },
    { type: 'openkey:close' },
  ]);
}

async function setup(
  page: Page, surface: string, keys: unknown[], keyId?: string,
  options: { readGate?: Promise<void>; detailKey?: unknown } = {},
) {
  const signed: string[] = [];
  let listRequests = 0;
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'qa-session'));
  await page.route('**/api/auth/get-session**', route => route.fulfill({
    json: { session: { id: 'qa-session', userId: 'qa-user' }, user: { id: 'qa-user' } },
  }));
  await page.route('**/api/keys', async route => {
    listRequests++;
    await options.readGate;
    return route.fulfill({ json: { keys } });
  });
  await page.route('**/api/keys/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === 'POST' && path.endsWith('/sign-typed-data')) {
      signed.push(path.split('/')[3]!);
      return route.fulfill({ json: { signature: '0x1234', address: other.address } });
    }
    await options.readGate;
    return route.fulfill({ json: { key: options.detailKey ?? archived } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(({ surface, keyId }) => {
    const iframe = document.createElement('iframe');
    iframe.id = 'typed-data';
    iframe.style.width = '600px';
    iframe.style.height = '900px';
    iframe.src = `/widget/${surface}?origin=${encodeURIComponent(location.origin)}`;
    (window as Recording).received = [];
    window.addEventListener('message', event => {
      if (event.source !== iframe.contentWindow || event.origin !== location.origin) return;
      (window as Recording).received?.push(event.data);
      if (event.data?.type === 'openkey:ready') {
        iframe.contentWindow?.postMessage({ type: 'openkey:signTypedData:request', data: {
          ...(keyId ? { keyId } : {}), domain: { name: 'QA' },
          types: { Note: [{ name: 'text', type: 'string' }] }, primaryType: 'Note',
          message: { text: 'QA owner choice' },
        } }, location.origin);
      }
    });
    document.body.append(iframe);
  }, { surface, keyId });
  return { frame: page.frameLocator('#typed-data'), signed, listRequests: () => listRequests };
}

for (const surface of ['sign-typed-data', 'embed/sign-typed-data']) {
  test(`${surface}: owner chooses another active managed key and signs with it`, async ({ page }) => {
    const { frame, signed } = await setup(page, surface, [archived, primary, other, external]);
    await expect(frame.getByRole('button', { name: /Key 2/ })).toContainText('Primary');
    await expect(frame.getByRole('button', { name: /Key 4/ })).toHaveCount(0);
    expect(signed).toEqual([]);
    await frame.getByRole('button', { name: 'Use a different key' }).click();
    await expect(frame.getByRole('button', { name: /Key 0|Key 5/ })).toHaveCount(0);
    await frame.getByRole('button', { name: /Key 4/ }).click();
    await expect(frame.getByText('Key 4', { exact: true })).toBeVisible();
    expect(signed).toEqual([]);
    await frame.getByRole('button', { name: 'Sign Data', exact: true }).click();
    await expect.poll(() => signed).toEqual([other.id]);
  });

  test(`${surface}: sole nonzero active primary reaches review automatically`, async ({ page }) => {
    const { frame, signed } = await setup(page, surface, [archived, primary, external]);
    await expect(frame.getByText('Key 2', { exact: true })).toBeVisible();
    await expect(frame.getByRole('button', { name: 'Use a different key' })).toHaveCount(0);
    expect(signed).toEqual([]);
    await frame.getByRole('button', { name: 'Sign Data', exact: true }).click();
    await expect.poll(() => signed).toEqual([primary.id]);
  });

  test(`${surface}: no usable managed keys offers a return to the app`, async ({ page }) => {
    const { frame, signed } = await setup(page, surface, [archived, external]);
    await expect(frame.getByText('No active managed keys are available to sign this data.')).toBeVisible();
    await expect(frame.getByRole('button', { name: 'Sign Data', exact: true })).toHaveCount(0);
    await expectBackToApp(page, frame, 'No active managed keys are available to sign this data.');
    expect(signed).toEqual([]);
  });

  test(`${surface}: archived explicit pin refuses without falling back to available keys`, async ({ page }) => {
    const { frame, signed, listRequests } = await setup(page, surface, [primary, other], archived.id);
    await expect(frame.getByText(archivedMessage, { exact: true })).toBeVisible();
    await expect(frame.getByRole('button', { name: /Key 2|Key 4|Sign Data/ })).toHaveCount(0);
    await expectBackToApp(page, frame, archivedMessage);
    expect(listRequests()).toBe(0);
    expect(signed).toEqual([]);
  });
}

const sessionChangedMessage = 'Signing session changed. Reconnect to choose a key.';

async function swapEmbeddedToken(page: Page) {
  await page.locator('#typed-data').evaluate(element => {
    (element as HTMLIFrameElement).contentWindow!.sessionStorage.setItem('openkey_session_token', 'qa-session-b');
  });
}

async function expectSessionRefusal(page: Page, context: Awaited<ReturnType<typeof setup>>) {
  await expect(context.frame.getByText(sessionChangedMessage, { exact: true })).toBeVisible();
  await expect(context.frame.getByRole('button', { name: /Key 2|Key 4|Sign Data/ })).toHaveCount(0);
  expect(context.signed).toEqual([]);
  await expectBackToApp(page, context.frame, sessionChangedMessage);
  expect(context.signed).toEqual([]);
}

for (const read of ['list', 'detail']) {
  test(`embed session binding: token swap during pending ${read} refuses stale metadata`, async ({ page }) => {
    let release!: () => void;
    const readGate = new Promise<void>(resolve => { release = resolve; });
    const pendingRead = page.waitForRequest(request => request.method() === 'GET' &&
      new URL(request.url()).pathname === (read === 'list' ? '/api/keys' : `/api/keys/${primary.id}`));
    const context = await setup(page, 'embed/sign-typed-data', [primary, other],
      read === 'detail' ? primary.id : undefined, { readGate, detailKey: primary });
    const request = await pendingRead;
    expect(request.headers()['authorization']).toBe('Bearer qa-session');
    await swapEmbeddedToken(page);
    release();
    await expectSessionRefusal(page, context);
  });
}

for (const step of ['selection', 'sign']) {
  test(`embed session binding: token swap before ${step} never submits a stale key`, async ({ page }) => {
    const context = await setup(page, 'embed/sign-typed-data', step === 'selection' ? [primary, other] : [primary]);
    if (step === 'selection') {
      await expect(context.frame.getByRole('button', { name: /Key 2/ })).toBeVisible();
      await swapEmbeddedToken(page);
      await context.frame.getByRole('button', { name: /Key 2/ }).click();
    } else {
      await expect(context.frame.getByRole('button', { name: 'Sign Data', exact: true })).toBeVisible();
      await swapEmbeddedToken(page);
      await context.frame.getByRole('button', { name: 'Sign Data', exact: true }).click();
    }
    await expectSessionRefusal(page, context);
  });
}

for (const surface of ['sign-typed-data', 'embed/sign-typed-data']) {
  for (const step of ['picker', 'review']) {
    test(`${surface}: ordinary Cancel in ${step} keeps USER_CANCELLED`, async ({ page }) => {
      const { frame, signed } = await setup(page, surface, step === 'picker' ? [primary, other] : [primary]);
      if (step === 'picker') await expect(frame.getByRole('button', { name: /Key 2/ })).toBeVisible();
      else await expect(frame.getByRole('button', { name: 'Sign Data', exact: true })).toBeVisible();
      await frame.getByRole('button', { name: 'Cancel', exact: true }).click();
      await expect.poll(() => page.evaluate(() => (window as Recording).received?.find(
        message => message.type === 'openkey:signTypedData:response',
      ))).toMatchObject({ success: false, error: { code: 'USER_CANCELLED', message: 'User cancelled' } });
      expect(signed).toEqual([]);
    });
  }
}
