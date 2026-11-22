import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { ORIGIN } from './e2e-port';

// TC-3893 (N1 popup-only): browser specs for the registry-change popup consent screen
// (`/widget/registry-change`), including the separate encryption-node callout, identity
// warnings (warn-only), passkey approval, stale re-prepare, refused URL handling, F3
// mode-only diff, F6 422 copy, undo/restore, cancel, framing headers, and removal of
// `/widget/embed/registry-change`.

const ADDRESS = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const SUBJECT = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE_DEFAULT = `tinycloud:pkh:eip155:1:${ADDRESS.toLowerCase()}:default`;
const SPACE_NOTES = `tinycloud:pkh:eip155:1:${ADDRESS.toLowerCase()}:notes`;
const NODE_A = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const NODE_B = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const RECORD_HASH = 'a'.repeat(64);
const credentialId = randomBytes(16);

type Msg = Record<string, unknown>;
type HostWindow = Window & { received: Msg[]; rcWindow: Window };

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

function makePasskeyOffer(token: string) {
  return {
    required: true as const,
    challengeToken: token,
    options: {
      challenge: randomBytes(32).toString('base64url'),
      rpId: 'localhost',
      userVerification: 'required',
      timeout: 60000,
      allowCredentials: [
        { id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] },
      ],
    },
  };
}

function makePrepareResponse(opts: {
  encryptionChanged?: boolean;
  identity?: Array<{ url: string; did: string | null; status: 'ok' | 'mismatch' | 'unreachable' }>;
  token?: string;
} = {}) {
  const encryptionChanged = opts.encryptionChanged ?? true;
  return {
    changeId: 'change-ticket-1',
    requestingOrigin: ORIGIN,
    before: {
      version: 2,
      subject: SUBJECT,
      nodes: [{ did: NODE_A, url: 'https://node-a.example' }],
      spaces: [
        { space: SPACE_DEFAULT, nodes: [{ did: NODE_A, mode: 'read-write' }] },
        { space: SPACE_NOTES, nodes: [{ did: NODE_A, mode: 'read-write' }] },
      ],
      encryptionNode: NODE_A,
      updated_at: '2026-11-22T15:00:00.000Z',
      sequence: 4,
    },
    after: {
      version: 2,
      subject: SUBJECT,
      nodes: [
        { did: NODE_A, url: 'https://node-a.example' },
        { did: NODE_B, url: 'https://node-b.example:8443' },
      ],
      spaces: [
        { space: SPACE_DEFAULT, nodes: [{ did: NODE_B, mode: 'read-write' }] },
        { space: SPACE_NOTES, nodes: [{ did: NODE_A, mode: 'read-write' }] },
      ],
      encryptionNode: encryptionChanged ? NODE_B : NODE_A,
      updated_at: '2026-11-22T16:00:00.000Z',
      sequence: 5,
    },
    recordHash: RECORD_HASH,
    identity: opts.identity ?? [{ url: 'https://node-b.example:8443', did: NODE_B, status: 'ok' }],
    encryptionChanged,
    passkey: makePasskeyOffer(opts.token ?? 'tok-1'),
  };
}

async function attachVirtualAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
    },
  });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: credentialId.toString('base64'),
      isResidentCredential: true,
      rpId: 'localhost',
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
      userHandle: Buffer.from('u').toString('base64'),
      signCount: 0,
    },
  });
}

async function openRegistryChangePopup(
  page: Page,
  requestPayload: Record<string, unknown> = {
    nodes: [{ url: 'https://node-b.example:8443' }],
    encryptionNode: 'https://node-b.example:8443',
  },
) {
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', (event) => {
      if (event.origin === location.origin && event.source === host.rcWindow) {
        host.received.push(event.data);
      }
    });
  });

  const popupPromise = page.waitForEvent('popup');
  await page.evaluate(() => {
    (window as unknown as HostWindow).rcWindow = window.open(
      `/widget/registry-change?origin=${encodeURIComponent(location.origin)}`,
    )!;
  });
  const widgetPage = await popupPromise;

  await attachVirtualAuthenticator(widgetPage);
  const received = () => page.evaluate(() => (window as unknown as HostWindow).received);
  await expect.poll(async () => (await received()).some((m) => m.type === 'openkey:ready')).toBe(true);

  await page.evaluate((req) => {
    (window as unknown as HostWindow).rcWindow.postMessage(
      {
        type: 'openkey:registry-change:request',
        requestId: 'rc-req-1',
        protocolVersion: 1,
        // Spoofed origin in payload must be ignored in favour of MessageEvent.origin.
        requestingOrigin: 'https://spoofed-app.example',
        request: req,
      },
      location.origin,
    );
  }, requestPayload);

  return { view: widgetPage, widgetPage, received };
}

test('popup: shows diff, encryption callout, identity warnings, and approves with passkey', async ({ page }) => {
  const prepareHeaders: Array<Record<string, string>> = [];
  const prepareBodies: unknown[] = [];
  const publishBodies: Array<Record<string, unknown>> = [];

  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().route('**/api/registry-change/**', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === '/api/registry-change/prepare') {
      prepareHeaders.push(req.headers());
      prepareBodies.push(req.postDataJSON());
      return json(
        route,
        makePrepareResponse({
          encryptionChanged: true,
          identity: [
            { url: 'https://node-b.example:8443', did: NODE_B, status: 'unreachable' },
          ],
        }),
      );
    }
    if (path === '/api/registry-change/publish') {
      publishBodies.push(req.postDataJSON() as Record<string, unknown>);
      return json(route, { sequence: 5, recordHash: RECORD_HASH });
    }
    return json(route, {});
  });

  const { view, received } = await openRegistryChangePopup(page);

  await expect(view.getByRole('heading', { name: 'Move where your data lives?' })).toBeVisible();
  // Verified origin comes from event.origin (ORIGIN), never the spoofed payload origin.
  await expect(view.getByTestId('registry-change-origin')).toContainText(`${ORIGIN} wants to change where your data lives.`);
  await expect(view.getByTestId('registry-change-origin')).not.toContainText('spoofed-app.example');

  // Before/after table shows canonical host + non-default port and No change for untouched space.
  const table = view.getByTestId('registry-change-diff-table');
  await expect(table).toContainText('default');
  await expect(table).toContainText('node-a.example');
  await expect(table).toContainText('node-b.example:8443');
  await expect(table).toContainText('notes');
  await expect(table).toContainText('No change');

  // Encryption change callout is rendered separately in its own colour with Monica's exact copy.
  const encCallout = view.getByTestId('registry-change-encryption-callout');
  await expect(encCallout).toBeVisible();
  await expect(encCallout).toContainText(
    'New secrets and keys will be held at node-b.example:8443. Whoever runs it can open secrets you save after this.',
  );

  // Identity warning is shown, and Approve stays enabled (warn-only, not a block).
  const warnings = view.getByTestId('registry-change-identity-warnings');
  await expect(warnings).toContainText("Couldn't reach node-b.example:8443 to confirm what it is.");
  await expect(warnings).toContainText('You can approve anyway, but check this host with whoever asked you to move.');

  // Verify prepare sent verified origin in header, NOT in body, and NEVER sent an Authorization header (F4).
  expect(prepareHeaders[0]?.['x-openkey-requesting-origin']).toBe(ORIGIN);
  expect(prepareHeaders[0]?.authorization).toBeUndefined();
  expect('requestingOrigin' in (prepareBodies[0] as Record<string, unknown>)).toBe(false);

  const approveBtn = view.getByRole('button', { name: 'Approve with passkey' });
  await expect(approveBtn).toBeEnabled();
  await approveBtn.click();

  // Publish received changeId + real WebAuthn passkeyAssertion.
  await expect.poll(() => publishBodies.length).toBe(1);
  expect(publishBodies[0]?.changeId).toBe('change-ticket-1');
  expect((publishBodies[0]?.passkeyAssertion as { challengeToken?: string })?.challengeToken).toBe('tok-1');

  await expect.poll(async () =>
    (await received()).find((m) => m.type === 'openkey:registry-change:response'),
  ).toEqual({
    type: 'openkey:registry-change:response',
    requestId: 'rc-req-1',
    protocolVersion: 1,
    success: true,
    status: 'published',
    sequence: 5,
    recordHash: RECORD_HASH,
  });
});

test('popup: omits encryption callout when encryptionChanged is false and handles stale 409 re-prepare', async ({ page }) => {
  let prepareCalls = 0;
  let publishCalls = 0;

  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().route('**/api/registry-change/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/registry-change/prepare') {
      prepareCalls += 1;
      return json(route, makePrepareResponse({ encryptionChanged: false, token: `tok-${prepareCalls}` }));
    }
    if (path === '/api/registry-change/publish') {
      publishCalls += 1;
      if (publishCalls === 1) {
        return json(route, { error: 'registry_change_stale' }, 409);
      }
      return json(route, { sequence: 6, recordHash: RECORD_HASH });
    }
    return json(route, {});
  });

  const { view, received } = await openRegistryChangePopup(page);

  await expect(view.getByTestId('registry-change-review')).toBeVisible();
  await expect(view.getByTestId('registry-change-encryption-callout')).toHaveCount(0);

  // First approve gets 409 stale -> shows stale screen with Review again button.
  await view.getByRole('button', { name: 'Approve with passkey' }).click();
  await expect(view.getByTestId('registry-change-stale')).toBeVisible();
  await expect(view.getByTestId('registry-change-stale')).toContainText('This changed while you were looking');

  // Clicking Review again re-calls /prepare and returns to review.
  await view.getByRole('button', { name: 'Review again' }).click();
  await expect.poll(() => prepareCalls).toBe(2);
  await expect(view.getByTestId('registry-change-review')).toBeVisible();

  // Cancel resolves cancelled.
  await view.getByRole('button', { name: 'Cancel' }).click();
  await expect.poll(async () =>
    (await received()).find((m) => m.type === 'openkey:registry-change:response'),
  ).toEqual({
    type: 'openkey:registry-change:response',
    requestId: 'rc-req-1',
    protocolVersion: 1,
    success: true,
    status: 'cancelled',
  });
});

test('popup: refused invalid node URL shows Monica refusal copy and no Approve button', async ({ page }) => {
  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().route('**/api/registry-change/prepare', (route) =>
    json(route, { error: 'registry_change_invalid_node' }, 400),
  );

  const { view } = await openRegistryChangePopup(page, {
    nodes: [{ url: 'not-a-url' }],
  });

  await expect(view.getByTestId('registry-change-error')).toContainText(
    "This request lists a node address OpenKey can't read, so nothing was signed.",
  );
  await expect(view.getByRole('button', { name: 'Approve with passkey' })).toHaveCount(0);
});

test('popup: undo/restore variant calls /undo/prepare, renders restore title + removed space, and approves with passkey', async ({ page }) => {
  const undoBodies: Array<Record<string, unknown>> = [];
  const publishBodies: Array<Record<string, unknown>> = [];

  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().route('**/api/registry-change/**', async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === '/api/registry-change/undo/prepare') {
      undoBodies.push(req.postDataJSON() as Record<string, unknown>);
      return json(route, {
        ...makePrepareResponse({ encryptionChanged: true, token: 'tok-undo-1' }),
        before: {
          version: 2,
          subject: SUBJECT,
          nodes: [{ did: NODE_B, url: 'https://node-b.example:8443' }],
          spaces: [
            { space: SPACE_DEFAULT, nodes: [{ did: NODE_B, mode: 'read-write' }] },
            { space: SPACE_NOTES, nodes: [{ did: NODE_B, mode: 'read-write' }] },
          ],
          encryptionNode: NODE_B,
          updated_at: '2026-11-22T16:00:00.000Z',
          sequence: 6,
        },
        after: {
          version: 2,
          subject: SUBJECT,
          nodes: [{ did: NODE_A, url: 'https://node-a.example' }],
          spaces: [
            { space: SPACE_DEFAULT, nodes: [{ did: NODE_A, mode: 'read-write' }] },
          ],
          encryptionNode: NODE_A,
          updated_at: '2026-11-22T16:30:00.000Z',
          sequence: 7,
        },
        undoKind: 'restore',
        restoredBeforeDate: '2026-11-20T10:00:00.000Z',
      });
    }
    if (path === '/api/registry-change/publish') {
      publishBodies.push(req.postDataJSON() as Record<string, unknown>);
      return json(route, { sequence: 7, recordHash: RECORD_HASH });
    }
    return json(route, {});
  });

  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', (event) => {
      if (event.origin === location.origin && event.source === host.rcWindow) host.received.push(event.data);
    });
  });

  const popupPromise = page.waitForEvent('popup');
  await page.evaluate(() => {
    (window as unknown as HostWindow).rcWindow = window.open(
      `/widget/registry-change?origin=${encodeURIComponent(location.origin)}`,
    )!;
  });
  const view = await popupPromise;
  await attachVirtualAuthenticator(view);
  const received = () => page.evaluate(() => (window as unknown as HostWindow).received);
  await expect.poll(async () => (await received()).some((m) => m.type === 'openkey:ready')).toBe(true);

  await page.evaluate(() => {
    (window as unknown as HostWindow).rcWindow.postMessage(
      { type: 'openkey:registry-undo:request', requestId: 'rc-undo-1', protocolVersion: 1, historyId: 'hist-old-1' },
      location.origin,
    );
  });

  await expect(view.getByRole('heading', { name: 'Restore an earlier version?' })).toBeVisible();
  // Non-One localhost origin uses `{origin}` form, never "TinyCloud One", with locale date (F8).
  const expectedLocaleDate = await page.evaluate(() => new Date('2026-11-20T10:00:00.000Z').toLocaleDateString());
  await expect(view.getByTestId('registry-change-origin')).toContainText(
    `${ORIGIN} wants to put back where your data lived before ${expectedLocaleDate}.`,
  );
  await expect(view.getByTestId('registry-change-diff-table')).toContainText('Not set');
  expect(undoBodies).toEqual([{ historyId: 'hist-old-1' }]);

  await view.getByRole('button', { name: 'Approve with passkey' }).click();
  await expect.poll(() => publishBodies.length).toBe(1);
  await expect.poll(async () =>
    (await received()).find((m) => m.type === 'openkey:registry-change:response'),
  ).toEqual({
    type: 'openkey:registry-change:response',
    requestId: 'rc-undo-1',
    protocolVersion: 1,
    success: true,
    status: 'published',
    sequence: 7,
    recordHash: RECORD_HASH,
  });
});

test('popup: F3 mode-only diff renders changed row', async ({ page }) => {
  await page.context().route('**/api/registry-change/prepare', (route) =>
    json(route, {
      ...makePrepareResponse({ encryptionChanged: false }),
      before: {
        version: 2,
        subject: SUBJECT,
        nodes: [{ did: NODE_A, url: 'https://node-a.example' }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ did: NODE_A, mode: 'read-only' }] }],
        encryptionNode: NODE_A,
        updated_at: '2026-11-22T15:00:00.000Z',
        sequence: 4,
      },
      after: {
        version: 2,
        subject: SUBJECT,
        nodes: [{ did: NODE_A, url: 'https://node-a.example' }],
        spaces: [{ space: SPACE_DEFAULT, nodes: [{ did: NODE_A, mode: 'read-write' }] }],
        encryptionNode: NODE_A,
        updated_at: '2026-11-22T16:00:00.000Z',
        sequence: 5,
      },
      identity: [{ url: 'https://node-a.example', did: NODE_A, status: 'ok' }],
    }),
  );

  const { view } = await openRegistryChangePopup(page, {
    nodes: [{ url: 'https://node-a.example' }],
    spaces: [{ space: SPACE_DEFAULT, nodes: [{ url: 'https://node-a.example', mode: 'read-write' }] }],
  });
  await expect(view.getByTestId('registry-change-mode-only-row')).toContainText(
    'default: node-a.example, read-only → read and write',
  );
});

test('popup: F6 422 registry_change_node_did_required shows Monica popup copy with no Approve button', async ({ page }) => {
  await page.context().route('**/api/registry-change/prepare', (route) =>
    json(route, { error: 'registry_change_node_did_required', host: 'node-b.example:8443' }, 422),
  );

  const { view } = await openRegistryChangePopup(page, {
    nodes: [{ url: 'https://node-b.example:8443' }],
  });
  await expect(view.getByTestId('registry-change-error')).toContainText(
    "Couldn't reach node-b.example:8443 to confirm which host it is, so nothing was changed. The app that asked needs to fix this; you can close this window.",
  );
  await expect(view.getByRole('button', { name: 'Approve with passkey' })).toHaveCount(0);
});

test('N1 framing & route removal: /widget/registry-change sends frame-ancestors none + DENY; /widget/embed/registry-change is 404', async ({ request }) => {
  const popupRes = await request.get('/widget/registry-change');
  expect(popupRes.status()).toBe(200);
  expect(popupRes.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
  expect(popupRes.headers()['x-frame-options']).toBe('DENY');
  expect(popupRes.headers()['referrer-policy']).toBe('no-referrer');

  const embedRes = await request.get('/widget/embed/registry-change');
  expect(embedRes.status()).toBe(404);
});
