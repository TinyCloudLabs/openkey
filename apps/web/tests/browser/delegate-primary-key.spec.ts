// TC-703: `/delegate` labels the primary key and keeps other keys behind "Use a
// different key". With several keys and no owner named, the user picks the
// signing key; nothing is preselected. Every API call is answered by
// `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const CAPS_READ = 'tinycloud.capabilities/read';
const KV_GET = 'tinycloud.kv/get';
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const key = (id: string, keyIndex: number, address: string, isPrimary: boolean, keyType = 'MANAGED') =>
  ({ id, address, publicKey: '0x', keyIndex, label: `Key ${keyIndex}`, keyType, isPrimary, createdAt: new Date().toISOString() });

const primary = key('key_0', 0, '0xd559ccd9eb87c530a9a349262669386de93cf412', true);
const second = key('key_1', 1, '0x2222222222222222222222222222222222222222', false);
const external = key('key_2', 2, '0x3333333333333333333333333333333333333333', false, 'EXTERNAL');
const threeKeys = [primary, second, external];

/** A `/api/delegate/prepare` response for the key that will sign. */
function preparedFor(address: string) {
  const space = `tinycloud:pkh:eip155:1:${address}:default`;
  const siwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
    'Resources:',
    `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] }, [`${space}/kv/notes/`]: { [KV_GET]: [{}] } })}`,
  ].join('\n');
  const option = (service: string, short: string, path: string, ability: string, required: boolean) => {
    const optionKey = `${service}\0${space}\0${path}`;
    return { key: optionKey, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
      actions: [{ key: `${optionKey}\0${ability}`, action: ability.split('/')[1], ability, required }] };
  };
  const permissions = [option('tinycloud.capabilities', 'capabilities', '', CAPS_READ, true), option('tinycloud.kv', 'kv', 'notes/', KV_GET, false)];
  return {
    prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

/** Mocks the API; returns the key IDs `/api/delegate/prepare` was asked to prepare, in order. */
async function mock(page: Page, keys: unknown[], delegation: Record<string, unknown> = {}) {
  const prepared: string[] = [];
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys });
    if (url.pathname === '/api/delegate/prepare') {
      const { keyId } = route.request().postDataJSON() as { keyId: string };
      prepared.push(keyId);
      const signer = (keys as Array<{ id: string; address: string }>).find((k) => k.id === keyId)!;
      return json(route, 200, preparedFor(signer.address));
    }
    if (url.pathname === '/api/delegate') {
      return json(route, 200, { delegationHeader: { Authorization: 'Bearer x' }, delegationCid: 'bafy', spaceId: 'tinycloud:pkh:eip155:1:0xd559ccd9eb87c530a9a349262669386de93cf412:default', hostActivated: true, permissions: [], ...delegation });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  return prepared;
}

const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const noOwner = `/delegate?did=did:key:z6Mk&jwk=${jwk}`;
const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });
const keyButton = (page: Page, name: string) => page.getByRole('button', { name, exact: true });

test.describe('TC-703 primary key picker', () => {
  test('with no owner named and several keys, the user picks; a non-primary key can sign', async ({ page }) => {
    const prepared = await mock(page, threeKeys);
    await page.goto(noOwner);

    // The picker shows; no key is prepared until the user chooses one.
    await expect(page.getByText('Sign in with your primary key')).toBeVisible();
    await expect(keyButton(page, 'Key 0')).toContainText('Primary');
    await expect(approve(page)).toHaveCount(0);
    expect(prepared).toEqual([]);
    await expect(keyButton(page, 'Key 1')).toHaveCount(0);
    await expect(keyButton(page, 'Key 2')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);

    await page.getByRole('button', { name: 'Use a different key' }).click();
    await expect(keyButton(page, 'Key 1')).toBeVisible();
    await expect(keyButton(page, 'Key 2')).toContainText('(External)');
    await expect(keyButton(page, 'Key 1')).not.toContainText('Primary');
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);

    await keyButton(page, 'Key 1').click();
    await expect(approve(page)).toBeEnabled();
    await expect(page.getByLabel('Signing key')).toContainText('Key 1');
    expect(prepared).toEqual(['key_1']);

    // Back returns to the picker without auto-advancing.
    await page.getByTestId('signing-dismiss').click();
    await expect(page.getByText('Sign in with your primary key')).toBeVisible();
    expect(prepared).toEqual(['key_1']);
  });

  test('a named owner still wins, with the primary key labelled in the list', async ({ page }) => {
    const prepared = await mock(page, threeKeys);
    const space = `tinycloud:pkh:eip155:1:${second.address}:default`;
    const request = [
      { service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] },
      { service: 'tinycloud.capabilities', space, path: '', actions: [CAPS_READ] },
    ];
    await page.goto(`${noOwner}&permissions=${encodeBase64UrlJson({ permissions: request })}`);
    await expect(approve(page)).toBeEnabled();
    expect(prepared).toEqual(['key_1']);

    await page.getByTestId('signing-dismiss').click();
    await expect(page.getByText('Select a key to authorize:')).toBeVisible();
    await expect(keyButton(page, 'Key 1')).toContainText('Requested');
    await expect(keyButton(page, 'Key 0')).toContainText('Primary');
    // The named-owner path keeps its own override; no primary-key gate.
    await expect(keyButton(page, 'Key 0')).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Use a different key' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);
  });

  test('without a primary key, every key is listed and none is preselected', async ({ page }) => {
    const prepared = await mock(page, [{ ...primary, isPrimary: false }, second, external]);
    await page.goto(noOwner);
    await expect(page.getByText('Select a key to authorize:')).toBeVisible();
    for (const name of ['Key 0', 'Key 1', 'Key 2']) await expect(keyButton(page, name)).toBeEnabled();
    await expect(page.getByText('Primary', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Use a different key' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Link External Wallet' })).toBeVisible();
    expect(prepared).toEqual([]);
  });

  test('the paste code carries the primary flag from the API unchanged', async ({ page }) => {
    await mock(page, threeKeys, { primary: true });
    await page.goto(noOwner);
    await keyButton(page, 'Key 0').click();
    await approve(page).click();
    const code = await page.locator('textarea').inputValue();
    const payload = JSON.parse(Buffer.from(code, 'base64').toString('utf8')) as Record<string, unknown>;
    expect(payload.primary).toBe(true);
  });

  test('the CLI callback receives the primary flag and full readiness metadata from the API unchanged', async ({ page }) => {
    const requestedSpaces = ['tinycloud:pkh:eip155:1:0xd559ccd9eb87c530a9a349262669386de93cf412:default'];
    const fullJwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', kid: 'delegate-key', alg: 'EdDSA', ext: true, key_ops: ['verify'] };
    await mock(page, threeKeys, { primary: false, requestedSpaces, jwk: fullJwk });
    let delivered: Record<string, unknown> | null = null;
    await page.route('http://127.0.0.1:47123/callback', (route) => {
      if (route.request().method() === 'POST') delivered = route.request().postDataJSON() as Record<string, unknown>;
      return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' }, body: '{"success":true}' });
    });
    await page.goto(`${noOwner}&callback=${encodeURIComponent('http://127.0.0.1:47123/callback')}`);
    await keyButton(page, 'Key 0').click();
    await approve(page).click();
    await expect.poll(() => delivered).not.toBeNull();
    expect(delivered!.primary).toBe(false);
    expect(delivered!.requestedSpaces).toEqual(requestedSpaces);
    expect(delivered!.jwk).toEqual(fullJwk);
  });

  test('archiving key zero leaves the sole nonzero primary as the signer', async ({ page }) => {
    const active = { ...second, keyIndex: 7, isPrimary: true };
    const prepared = await mock(page, [{ ...primary, archivedAt: '2026-11-01T00:00:00Z' }, active]);
    await page.goto(noOwner);
    await expect(approve(page)).toBeEnabled();
    expect(prepared).toEqual([active.id]);
    await expect(keyButton(page, 'Key 0')).toHaveCount(0);
  });

  test('an archived requested owner is not replaced by the active primary', async ({ page }) => {
    const prepared = await mock(page, [{ ...primary, archivedAt: '2026-11-01T00:00:00Z' }, { ...second, isPrimary: true }]);
    const space = `tinycloud:pkh:eip155:1:${primary.address}:default`;
    const permissions = [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] }];
    await page.goto(`${noOwner}&permissions=${encodeBase64UrlJson({ permissions })}`);
    await expect(keyButton(page, 'Key 1')).toBeDisabled();
    await expect(approve(page)).toHaveCount(0);
    expect(prepared).toEqual([]);
  });
});

test.describe('ordinary-link requester claims', () => {
  for (const request of [
    {
      title: 'a pasted registered callback does not verify the named MCP requester',
      domain: 'mcp.tinycloud.xyz',
      requesterOrigin: 'https://mcp.tinycloud.xyz',
      callback: 'https://mcp.tinycloud.xyz/connect/callback',
    },
    {
      title: 'a link that names a requester origin still names it, as an unverified claim',
      domain: 'listen.example',
      requesterOrigin: 'https://listen.example',
      callback: null,
    },
    {
      title: 'omitting requesterOrigin does not verify the default CLI requester',
      domain: 'cli.tinycloud.xyz',
      requesterOrigin: null,
      callback: null,
    },
  ]) {
    test(request.title, async ({ page }) => {
      await page.setViewportSize({ width: 390, height: 844 });
      await page.clock.setFixedTime(new Date('2026-10-15T00:00:00Z'));
      await mock(page, [primary]);
      const prepared = preparedFor(primary.address);
      prepared.prepared.siwe = prepared.prepared.siwe.replace('cli.tinycloud.xyz', request.domain);
      await page.route('**/api/delegate/prepare', route => json(route, 200, prepared));
      const params = new URLSearchParams();
      if (request.requesterOrigin) params.set('requesterOrigin', request.requesterOrigin);
      if (request.callback) params.set('callback', request.callback);
      await page.goto(`${noOwner}&${params}`);

      // A link-chosen authority is not a verified first-party app name,
      // even when the link also names a registered callback endpoint.
      const warning = page.getByRole('alert').filter({ has: page.getByRole('heading') });
      await expect(warning).toBeVisible();
      if (request.requesterOrigin) {
        await expect(page.locator('.requester-line .requester-name')).toHaveText(request.domain);
        await expect(warning).toContainText(request.domain);
      } else {
        // The link named no host, so none is claimed; the default signing
        // domain is not something the link said.
        await expect(page.locator('.requester-line')).toHaveText('From a link');
        await expect(warning).toContainText('Anyone can make a link like this.');
        await expect(warning).not.toContainText(request.domain);
      }
      // Advanced details never presents the claimed host as a verified requester.
      await expect(page.locator('.identity .label').first()).toHaveText(request.requesterOrigin ? 'Named in the link (not verified)' : 'Default signing domain');
      await expect(page.getByText('Review the access this request is asking for.')).toBeVisible();
      await expect(approve(page)).toBeEnabled();
    });
  }
});

test('a server-loaded signed request keeps its attribution without the ordinary-link warning', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.clock.setFixedTime(new Date('2026-10-15T00:00:00Z'));
  await mock(page, [primary]);
  const id = 'abcdefghijklmnopqrstuvwxyz';
  const space = `tinycloud:pkh:eip155:1:${primary.address}:default`;
  await page.route(`**/api/approval-requests/${id}/load`, route => json(route, 200, {
    request: {
      targetDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      nodeOrigin: 'https://node.tinycloud.xyz',
      permissions: [
        { service: 'tinycloud.capabilities', space, path: '', actions: [CAPS_READ] },
        { service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] },
      ],
      grantLifetimeSeconds: 3600,
    },
  }));
  const prepared = preparedFor(primary.address);
  prepared.prepared.siwe = prepared.prepared.siwe
    .replace('2026-10-03T00:00:00.000Z', '2026-10-15T00:00:00.000Z')
    .replace('2026-11-03T01:00:00.000Z', '2026-10-15T01:00:00.000Z');
  await page.route('**/api/delegate/prepare', route => json(route, 200, prepared));
  await page.goto(`/a/${id}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`);
  // A signed request carries no requester details of its own here, so the
  // line is neutral; the signing default is not a name.
  await expect(page.locator('.requester-line')).toHaveText('An approval link is asking');
  await expect(page.locator('.requester-line')).not.toContainText('TinyCloud');
  await expect(page.getByRole('alert').filter({ has: page.getByRole('heading') })).toHaveCount(0);
  await expect(approve(page)).toBeEnabled();
});

// TC-2526 follow-up: an ordinary link may name where the approval goes, as
// OpenKey itself enforces it. It never names the requester, and the warning
// stays in the same box.
test.describe('ordinary-link receiver line', () => {
  async function openOrdinary(page: Page, params: Record<string, string>) {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.clock.setFixedTime(new Date('2026-10-15T00:00:00Z'));
    await mock(page, [primary]);
    await page.goto(`${noOwner}&${new URLSearchParams(params)}`);
  }
  const warning = (page: Page) => page.getByRole('alert').filter({ has: page.getByRole('heading', { name: "OpenKey can't confirm who sent this request" }) });
  const receiverLine = (page: Page) => page.getByTestId('receiver-line');

  test('a registered MCP callback names the service as the destination, inside the warning', async ({ page }) => {
    await openOrdinary(page, { callback: 'https://mcp.tinycloud.xyz/connect/callback?state=t.n.sig' });
    await expect(warning(page)).toBeVisible();
    await expect(warning(page)).toContainText("This request may come from someone else's TinyCloud MCP session.");
    await expect(warning(page)).toContainText('Approve only if you started this request yourself.');
    await expect(warning(page).getByTestId('receiver-line')).toHaveText('Your approval will be delivered to the TinyCloud MCP service.');
    await expect(page.getByText(/is requesting|verified/i)).toHaveCount(0);
    await expect(approve(page)).toBeEnabled();
  });

  test('a loopback callback is an app on this device, with no brand', async ({ page }) => {
    await openOrdinary(page, { callback: 'http://127.0.0.1:47123/callback' });
    await expect(warning(page).getByTestId('receiver-line')).toHaveText('Your approval will be delivered to an app on this device (127.0.0.1:47123).');
    await expect(warning(page)).not.toContainText('TinyCloud');
    await expect(page.locator('.requester-line')).not.toContainText(/TinyCloud (MCP|CLI)/);
  });

  test('the service label never comes from a link parameter', async ({ page }) => {
    await openOrdinary(page, {
      callback: 'http://127.0.0.1:47123/callback',
      requesterOrigin: 'https://mcp.tinycloud.xyz',
      service: 'TinyCloud MCP',
      receiver: 'TinyCloud MCP',
      label: 'TinyCloud MCP',
    });
    await expect(receiverLine(page)).toHaveText('Your approval will be delivered to an app on this device (127.0.0.1:47123).');
    await expect(receiverLine(page)).not.toContainText('TinyCloud MCP');
    await expect(warning(page)).not.toContainText("someone else's TinyCloud MCP session");
  });

  test('a look-alike of a registered callback is refused and gets no receiver line', async ({ page }) => {
    await openOrdinary(page, { callback: 'https://mcp.tinycloud.xyz/connect/callback/extra' });
    await expect(page.getByRole('alert').filter({ hasText: 'not a registered TinyCloud app' })).toBeVisible();
    await expect(receiverLine(page)).toHaveCount(0);
  });

  test('with no callback there is no receiver line', async ({ page }) => {
    await openOrdinary(page, {});
    await expect(warning(page)).toBeVisible();
    await expect(receiverLine(page)).toHaveCount(0);
  });
});

test.describe('ordinary-link completion sentence', () => {
  for (const request of [
    {
      title: 'an approval delivered to the hosted MCP sends the owner back to ChatGPT or their MCP client',
      domain: 'mcp.tinycloud.xyz',
      requesterOrigin: 'https://mcp.tinycloud.xyz',
      callback: 'https://mcp.tinycloud.xyz/chatgpt/connect/callback?state=t.n.sig',
      sentence: 'You can close this window and return to ChatGPT or your MCP client.',
    },
    {
      title: 'a link that names a host sends the owner back to the app or site that sent them, never to the named host',
      domain: 'evil.example',
      requesterOrigin: 'https://evil.example',
      callback: 'http://127.0.0.1:47123/callback',
      sentence: 'You can close this window and return to the app or site that sent you.',
    },
    {
      title: 'a link that names no host sends the owner back to the app or site that sent them, not to a CLI or the default signing domain',
      domain: 'cli.tinycloud.xyz',
      requesterOrigin: null,
      callback: 'http://127.0.0.1:47123/callback',
      sentence: 'You can close this window and return to the app or site that sent you.',
    },
  ]) {
    test(request.title, async ({ page }) => {
      await mock(page, [primary]);
      const prepared = preparedFor(primary.address);
      prepared.prepared.siwe = prepared.prepared.siwe.replace('cli.tinycloud.xyz', request.domain);
      await page.route('**/api/delegate/prepare', route => json(route, 200, prepared));
      let delivered = false;
      await page.route(`${request.callback.split('?')[0]}**`, (route) => {
        if (route.request().method() === 'POST') delivered = true;
        return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' }, body: '{"success":true}' });
      });
      const params = new URLSearchParams({ callback: request.callback });
      if (request.requesterOrigin) params.set('requesterOrigin', request.requesterOrigin);
      await page.goto(`${noOwner}&${params}`);
      await approve(page).click();
      await expect.poll(() => delivered).toBe(true);
      await expect(page.getByRole('heading', { name: 'Authenticated' })).toBeVisible();
      await expect(page.getByText(request.sentence, { exact: true })).toBeVisible();
      // A host the link named is never shown as the closing instruction.
      if (request.requesterOrigin && request.domain !== 'mcp.tinycloud.xyz') {
        await expect(page.getByRole('heading', { name: 'Authenticated' }).locator('..')).not.toContainText(request.domain);
      }
    });
  }
});

test.describe('Close button on the Authenticated page', () => {
  const callback = 'http://127.0.0.1:47123/callback';
  async function openAuthenticated(page: Page) {
    await mock(page, [primary]);
    await page.route('**/api/delegate/prepare', route => json(route, 200, preparedFor(primary.address)));
    let delivered = false;
    await page.route(`${callback}**`, (route) => {
      if (route.request().method() === 'POST') delivered = true;
      return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' }, body: '{"success":true}' });
    });
    await page.goto(`${noOwner}&${new URLSearchParams({ callback })}`);
    await approve(page).click();
    await expect.poll(() => delivered).toBe(true);
    await expect(page.getByRole('heading', { name: 'Authenticated' })).toBeVisible();
  }

  test('the browser closes the window: Close calls window.close and the page stays as it is', async ({ page }) => {
    await page.addInitScript(() => {
      let closed = false;
      Reflect.set(window, '__closeCalls', 0);
      window.close = () => { Reflect.set(window, '__closeCalls', Number(Reflect.get(window, '__closeCalls')) + 1); closed = true; };
      Object.defineProperty(window, 'closed', { get: () => closed });
    });
    await openAuthenticated(page);
    await page.getByRole('button', { name: 'Close', exact: true }).click();
    await expect.poll(() => page.evaluate(() => Number(Reflect.get(window, '__closeCalls')))).toBe(1);
    // The window is gone, so nothing else is shown or needed; outlast the 300 ms check.
    await page.waitForTimeout(600);
    await expect(page.getByText('Your browser kept this tab open.')).toHaveCount(0);
  });

  test('the browser refuses (a tab the owner opened): the button is replaced by a status line and focus moves to it', async ({ page }) => {
    await openAuthenticated(page);
    // A top-level tab the owner opened: the browser ignores window.close().
    await page.getByRole('button', { name: 'Close', exact: true }).click();
    const refusal = page.getByRole('status').filter({ hasText: 'Your browser kept this tab open. Close it from your browser.' });
    await expect(refusal).toBeVisible();
    await expect(refusal).toBeFocused();
    await expect(page.getByRole('alert')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Close', exact: true })).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Authenticated' })).toBeVisible();
  });
});
