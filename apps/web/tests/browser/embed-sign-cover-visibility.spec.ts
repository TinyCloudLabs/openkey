import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { HOST } from './e2e-port';
import { makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';

// A framed sign iframe honours the web flow's one-passkey cover only while the browser's intersection observer v2
// reports Approve in plain view. Both tests run the real Chromium observer against the real page: the harness parent
// frames /widget/embed/sign, the mocked preview waives the passkey with `flowCover: true` whenever the request names
// the flow, and a real WebAuthn ceremony (virtual authenticator) answers the offer the API makes without it.
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const recapSiwe = siweWithResources([makeRecapResource({
  [`tinycloud:pkh:eip155:1:${address}:default/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
})], { domain: HOST, uri: `http://${HOST}` });
const credentialId = randomBytes(16);
const key = { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' };
const FLOW_HEADER = 'x-openkey-passkey-flow';
const FLOW_SHAPE = /^w\.[A-Za-z0-9_-]{32}$/;

type Body = Record<string, unknown> & { passkeyAssertion?: { challengeToken: string; response: { id: string } } };
type Seen = { flow: string | undefined; body: Body };
type HostWindow = Window & { received: Array<Record<string, unknown>>; signWindow: Window };
type Probe = { isIntersecting: boolean; isVisible: boolean } | null;
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

function offer(token: string) {
  return { required: true, challengeToken: token, options: {
    challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
    allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
  } };
}

async function virtualAuthenticator(page: Page) {
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
}

/** The preview waives the passkey when the request names the flow and offers a challenge when it does not. */
async function mockApi(page: Page) {
  const previews: Seen[] = [];
  const signs: Seen[] = [];
  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const flow = request.headers()[FLOW_HEADER];
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'test-session' }, user: { id: 'u' } });
    if (path === '/api/keys/selected-key') return json(route, { key });
    if (path === '/api/delegate/authorize-sign-prepare') {
      return json(route, { authorizationContextToken: 'context', expiresAt: new Date(Date.now() + 300_000).toISOString() });
    }
    if (path === '/api/delegate/authorize-sign-preview') {
      const body = request.postDataJSON() as Body & { selectedActionIds: string[] };
      previews.push({ flow, body });
      return json(route, {
        authorizationContextToken: 'context', previewApprovalToken: `preview-${previews.length}`,
        previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        signedMessage: recapSiwe, selectedActionKeys: body.selectedActionIds,
        passkey: flow ? { required: false, flowCover: true } : offer(`token-${previews.length}`),
        permissions: body.selectedActionIds.map((id) => {
          const [service, space, path, ability] = id.split('\0');
          return { service, space, path, actions: [ability] };
        }),
      });
    }
    if (path === '/api/delegate/authorize-sign') {
      signs.push({ flow, body: request.postDataJSON() });
      return json(route, { signature: `0x${'11'.repeat(65)}`, address, signedMessage: recapSiwe, selectedActionKeys: [], permissions: [] });
    }
    return json(route, {});
  });
  return { previews, signs };
}

/** Frames the real iframe sign page as the SDK does and answers its layout protocol. */
async function openFramedSign(page: Page) {
  // Counts the page's own WebAuthn ceremonies, in every frame.
  await page.context().addInitScript(() => {
    const w = window as unknown as { __gets: number };
    w.__gets = 0;
    const credentials = navigator.credentials;
    const get = credentials.get.bind(credentials);
    credentials.get = (options) => { w.__gets += 1; return get(options); };
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    // Like the SDK modal, size the frame to every height the page reports and acknowledge the layout.
    window.addEventListener('message', (event) => {
      if (event.origin !== location.origin || event.source !== host.signWindow) return;
      host.received.push(event.data);
      if (event.data?.type !== 'openkey:resize') return;
      const height = Math.min(Number(event.data.height), Math.floor(innerHeight * 0.85));
      document.querySelector<HTMLIFrameElement>('#sign')!.style.height = `${height}px`;
      host.signWindow.postMessage({ type: 'openkey:layout-applied', requestId: 'r1',
        protocolVersion: 2, height, layoutId: event.data.layoutId }, location.origin);
    });
    const iframe = document.createElement('iframe');
    iframe.id = 'sign';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=r1&protocolVersion=2&keyId=selected-key`;
    iframe.style.width = '700px';
    document.body.append(iframe);
    host.signWindow = iframe.contentWindow!;
  });
  await virtualAuthenticator(page);
  const received = () => page.evaluate(() => (window as unknown as HostWindow).received);
  await expect.poll(async () => (await received()).some((m) => m.type === 'openkey:ready')).toBe(true);
  await page.evaluate((message) => {
    (window as unknown as HostWindow).signWindow.postMessage({
      type: 'openkey:sign:request', requestId: 'r1', protocolVersion: 2,
      authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message,
    }, location.origin);
  }, recapSiwe);
  const approve = page.frameLocator('#sign').locator('button.approve');
  // The iframe approves only once the host has applied the frame's height.
  await expect(approve).toBeEnabled({ timeout: 30_000 });
  const frame = () => page.frames().find((f) => f.url().includes('/widget/embed/sign'))!;
  // Watches Approve with the frame's own observer v2, the same report the page's gate reads.
  await frame().evaluate(() => {
    const w = window as unknown as { __probe: Probe };
    w.__probe = null;
    const button = document.querySelector('button.approve')!;
    const observer = new IntersectionObserver((entries) => {
      const entry = entries.at(-1) as IntersectionObserverEntry & { isVisible: boolean };
      w.__probe = { isIntersecting: entry.isIntersecting, isVisible: entry.isVisible };
    }, { threshold: 1.0, trackVisibility: true, delay: 100 } as IntersectionObserverInit);
    observer.observe(button);
  });
  const probe = () => frame().evaluate(() => (window as unknown as { __probe: Probe }).__probe);
  const ceremonies = () => frame().evaluate(() => (window as unknown as { __gets: number }).__gets);
  return { approve, probe, ceremonies };
}

for (const covered of [true, false]) {
  test(covered
    ? 'Approve covered by an element of the parent page: the tap asks for the passkey and the approval names no flow'
    : 'Approve in plain view for over 500 ms: the tap uses the cover, runs no passkey ceremony and names the flow', async ({ page }) => {
    const calls = await mockApi(page);
    const h = await openFramedSign(page);
    expect(calls.previews).toHaveLength(1);
    expect(calls.previews[0]!.flow).toMatch(FLOW_SHAPE);

    if (covered) {
      // The parent lays a see-through-to-clicks but painted element over Approve.
      await page.evaluate(() => {
        const frame = document.querySelector<HTMLIFrameElement>('#sign')!;
        const box = frame.contentDocument!.querySelector('button.approve')!.getBoundingClientRect();
        const frameBox = frame.getBoundingClientRect();
        const overlay = document.createElement('div');
        overlay.id = 'overlay';
        overlay.style.cssText = `position:fixed;z-index:2147483647;pointer-events:none;background:#c00;opacity:.6;`
          + `left:${frameBox.left + box.left - 4}px;top:${frameBox.top + box.top - 4}px;`
          + `width:${box.width + 8}px;height:${box.height + 8}px`;
        document.body.append(overlay);
      });
      await expect.poll(() => h.probe(), { timeout: 5_000 }).toMatchObject({ isVisible: false });
    } else {
      await expect.poll(() => h.probe(), { timeout: 5_000 }).toEqual({ isIntersecting: true, isVisible: true });
    }
    // Well past the 500 ms the cover needs.
    await page.waitForTimeout(900);
    expect(await h.probe()).toMatchObject({ isVisible: !covered });

    await h.approve.click();
    await expect.poll(() => calls.signs.length).toBe(1);
    expect(calls.signs).toHaveLength(1);
    const approval = calls.signs[0]!;
    if (covered) {
      // One tap: a fresh offer without the flow, then the ceremony, then the approval with its assertion and no flow.
      expect(calls.previews).toHaveLength(2);
      expect(calls.previews[1]!.flow).toBeUndefined();
      expect(await h.ceremonies()).toBe(1);
      expect(approval.flow).toBeUndefined();
      expect(approval.body.passkeyAssertion).toMatchObject({ challengeToken: 'token-2', response: { id: credentialId.toString('base64url') } });
      expect(approval.body.previewApprovalToken).toBe('preview-2');
    } else {
      expect(calls.previews).toHaveLength(1);
      expect(await h.ceremonies()).toBe(0);
      expect(approval.flow).toBe(calls.previews[0]!.flow);
      expect(approval.body).not.toHaveProperty('passkeyAssertion');
      expect(approval.body.previewApprovalToken).toBe('preview-1');
    }
  });
}
