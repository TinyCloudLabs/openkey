// TC-2281: the signing preview is prepared in the background for the loaded key's account. When another account takes
// over and the owner reads the key again (Try again), the preview must be prepared afresh for that account. The server
// binds an authorization context to the account it was issued to and refuses it for any other (`user_mismatch`), so a
// context or preview kept from the first account would fail the owner's first attempt.
import { test, expect, type Page } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';
import { HOST } from './e2e-port';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);

type Body = Record<string, unknown>;
type HostWindow = Window & { received: Body[]; signWindow: Window };

interface Server {
  /** The account the server sees signed in now. */
  account: 'a' | 'b';
  prepares: number;
  /** Every context the routes sent to preview or sign, with the account that was signed in at the time. */
  used: Array<{ context: string; account: 'a' | 'b' }>;
  signs: Body[];
}

const permissions = (ids: string[]) => ids.map((id) => {
  const [service, space, path, ability] = id.split('\0');
  return { service, space, path, actions: [ability] };
});

async function mockServer(page: Page): Promise<Server> {
  const server: Server = { account: 'a', prepares: 0, used: [], signs: [] };
  const issuedTo = new Map<string, 'a' | 'b'>();
  const refuseMismatch = { status: 400, json: { error: 'Authorization context bound to a different user', code: 'user_mismatch' } };
  await page.context().route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.context().route('**/api/auth/get-session**', (route) => route.fulfill({ json: {
    session: { id: `session-${server.account}` }, user: { id: `user-${server.account}` },
  } }));
  await page.context().route('**/api/delegate/authorize-sign-prepare', (route) => {
    server.prepares++;
    const context = `context-${server.prepares}`;
    issuedTo.set(context, server.account);
    return route.fulfill({ json: { authorizationContextToken: context, expiresAt: new Date(Date.now() + 300_000).toISOString() } });
  });
  await page.context().route('**/api/delegate/authorize-sign-preview', (route) => {
    const body = route.request().postDataJSON();
    const context = String(body.authorizationContextToken);
    server.used.push({ context, account: server.account });
    if (issuedTo.get(context) !== server.account) return route.fulfill(refuseMismatch);
    const ids = body.selectedActionIds as string[];
    return route.fulfill({ json: {
      authorizationContextToken: context, previewApprovalToken: `preview-${context}`,
      previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      signedMessage: siwe, selectedActionKeys: ids, permissions: permissions(ids),
    } });
  });
  await page.context().route('**/api/delegate/authorize-sign', (route) => {
    const body = route.request().postDataJSON();
    const context = String(body.authorizationContextToken);
    server.signs.push(body);
    server.used.push({ context, account: server.account });
    if (issuedTo.get(context) !== server.account) return route.fulfill(refuseMismatch);
    const ids = body.selectedActionIds as string[];
    return route.fulfill({ json: {
      signature: `0x${'11'.repeat(65)}`, address, signedMessage: siwe, selectedActionKeys: ids, permissions: permissions(ids),
    } });
  });
  return server;
}

/** The parent page: records what the signing window posts and sends it the versioned SIWE ReCap request on ready. */
async function openHost(page: Page) {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'session-a'));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', (event) => {
      if (event.origin === location.origin && event.source === host.signWindow) host.received.push(event.data);
    });
  });
}

async function sendRequest(page: Page, protocolVersion: number) {
  await expect.poll(() => page.evaluate(() => (window as unknown as HostWindow).received.some((m) => m.type === 'openkey:ready')), { timeout: 45_000 }).toBe(true);
  await page.evaluate(([message, version]) => {
    (window as unknown as HostWindow).signWindow.postMessage({
      type: 'openkey:sign:request', requestId: 'switch', protocolVersion: version,
      authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message,
    }, location.origin);
  }, [siwe, protocolVersion] as const);
}

async function expectSignedOnceWithAccountB(page: Page, server: Server) {
  const responses = () => page.evaluate(() =>
    (window as unknown as HostWindow).received.filter((m) => m.type === 'openkey:sign:response'));
  await expect.poll(responses).toEqual([expect.objectContaining({ success: true })]);
  expect(server.signs).toHaveLength(1);
  // Everything sent after the switch carried a context issued to account b: nothing was refused as another account's.
  expect(server.used.filter((use) => use.account === 'b').map((use) => use.context)).toEqual(['context-2', 'context-2']);
  expect(server.prepares).toBe(2);
}

test('popup: after another account takes over, Try again prepares the preview for that account and Approve signs on the first try', async ({ page }) => {
  const server = await mockServer(page);
  await openHost(page);
  const opened = page.waitForEvent('popup');
  await page.evaluate(() => {
    (window as unknown as HostWindow).signWindow = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`)!;
  });
  const popup = await opened;
  await sendRequest(page, 1);
  const approve = popup.locator('button.approve');
  await expect(approve).toBeEnabled({ timeout: 45_000 });
  expect(server.used).toEqual([{ context: 'context-1', account: 'a' }]);

  // Another account signs in elsewhere (better-auth's cross-tab message); the popup drops the key and offers Try again.
  server.account = 'b';
  await page.evaluate(() => localStorage.setItem('better-auth.message', JSON.stringify({ event: 'session', data: { trigger: 'signin' }, timestamp: Date.now() })));
  await popup.getByTestId('signing-key-retry').click({ timeout: 30_000 });

  await expect(approve).toBeEnabled({ timeout: 30_000 });
  await approve.click();
  await expectSignedOnceWithAccountB(page, server);
});

test('iframe: after the frame session changes, Try again prepares the preview for that account and Approve signs on the first try', async ({ page }) => {
  const server = await mockServer(page);
  await openHost(page);
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'sign';
    frame.style.cssText = 'border:none;width:420px;height:760px;display:block';
    frame.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=switch&keyId=selected-key&protocolVersion=1`;
    document.body.append(frame);
    (window as unknown as HostWindow).signWindow = frame.contentWindow!;
  });
  await sendRequest(page, 1);
  const frame = page.frameLocator('#sign');
  const approve = frame.locator('button.approve');
  await expect(approve).toBeEnabled({ timeout: 45_000 });
  expect(server.used).toEqual([{ context: 'context-1', account: 'a' }]);

  // The frame's session becomes another account's (its storage is shared with this same-origin parent). Approve checks
  // the key against the session, drops it and offers Try again; nothing is signed.
  server.account = 'b';
  await page.evaluate(() => sessionStorage.setItem('openkey_session_token', 'session-b'));
  await approve.click();
  await frame.getByTestId('signing-key-retry').click({ timeout: 30_000 });
  expect(server.signs).toHaveLength(0);

  await expect(approve).toBeEnabled({ timeout: 30_000 });
  await approve.click();
  await expectSignedOnceWithAccountB(page, server);
});
