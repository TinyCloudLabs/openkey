// Shared set-up for the approval frame, loader and sign-in card specs. Every API call is answered by
// `page.route`; no API server runs. The popup is a new page of the browser context, so its route is on the context.
import type { Page, Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

export const json = (route: Route, status: number, body: unknown) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

export const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const host = 'https://node.tinycloud.xyz';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const handoffId = 'B'.repeat(43);
const state = 'A'.repeat(43);
const cancelSecret = 'C'.repeat(43);
const fullKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/get`;
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'I further authorize these capabilities.', '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-16T17:00:00.000Z', 'Expiration Time: 2026-10-23T17:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}] } })}`,
].join('\n');
const key = { id: 'key-one', address, publicKey: '0x', keyIndex: 0, label: 'Key', keyType: 'MANAGED', isPrimary: true, createdAt: '2026-10-16T17:00:00.000Z' };
const rawResult = {
  protocolVersion: 1, address, signature: '0xsigned', signedMessage: siwe, selectedActionKeys: [fullKey],
  permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }],
};

export const ownerEmail = 'owner@example.test';
const signedInSession = () => ({
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  user: { id: 'u', email: ownerEmail, name: 'Owner' },
});

/** A legacy delegate link, as the CLI opens it. */
export const delegateLink = `/delegate?did=did:key:z6Mk&jwk=${encodeBase64UrlJson(jwk)}`;

/** The prepared CLI sign-in link: the request rides in the #fragment. */
export function preparedLink(): string {
  const input = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk, host, sessionDid: 'did:key:cli-session', keyId: key.id },
    delivery: { handoffId, state, cancelSecret },
  };
  return `/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`;
}

/** The prepared revoke link. */
export function revokeLink(): string {
  const request = {
    kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`,
    cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe', nonce: '0123456789abcdef0123456789abcdef',
    expiresAt: '2026-10-16T17:09:00.000Z',
  };
  const input = { transportVersion: 2, request, delivery: { handoffId, state, cancelSecret } };
  return `/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`;
}

export interface MockOptions {
  signedIn: boolean;
  providers?: string[];
  /** The session answer waits for this. */
  sessionHeld?: Promise<void>;
  /** The key list waits for this. */
  keysHeld?: Promise<void>;
  /** The approval link's (/a/…) load waits for this. */
  loadHeld?: Promise<void>;
  /** The legacy review's prepare call waits for this. */
  prepareHeld?: Promise<void>;
  /** How the approve call of a prepared request answers. */
  signReply?: { status: number; body: unknown };
  /** How the approve call of an approval link (/a/…) answers. */
  approveReply?: { status: number; body: unknown };
}

export interface MockState {
  signedIn: boolean;
  claims: number;
  revokeClaims: number;
  keyCalls: number;
  cancelCalls: number;
}

/** Answers the API for the delegate, prepared, revoke and device pages. */
export async function mockApi(page: Page, options: MockOptions): Promise<MockState> {
  await page.clock.setFixedTime(new Date('2026-10-16T17:00:00.000Z'));
  const mocked: MockState = { signedIn: options.signedIn, claims: 0, revokeClaims: 0, keyCalls: 0, cancelCalls: 0 };
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') {
      await options.sessionHeld;
      return json(route, 200, mocked.signedIn ? signedInSession() : null);
    }
    if (path === '/api/auth/sign-out') {
      mocked.signedIn = false;
      return json(route, 200, { success: true });
    }
    if (path === '/api/auth/providers') return json(route, 200, { providers: options.providers ?? ['google', 'apple'] });
    if (path === '/api/keys') {
      mocked.keyCalls += 1;
      await options.keysHeld;
      return json(route, 200, { keys: [key] });
    }
    if (path === '/api/organizations') return json(route, 200, { organizations: [] });
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') {
      mocked.claims += 1;
      return json(route, 201, { transportVersion: 2, ticket: handoffId, expiresAt: '2026-10-16T17:05:00.000Z' });
    }
    if (path === '/api/delegate/handoffs/cancel-claimed') {
      mocked.cancelCalls += 1;
      return json(route, 200, { cancelled: true });
    }
    if (path === '/api/delegate/owner-revocation/prepare') {
      mocked.revokeClaims += 1;
      return json(route, 500, { error: 'not part of this check' });
    }
    if (path === '/api/delegate/authorize-sign-prepare') {
      return json(route, 200, { authorizationContextToken: 'bound-context', allowedActionIds: [fullKey], initialSelectionActionIds: [fullKey], address });
    }
    if (path === '/api/delegate/authorize-sign-preview') return json(route, 200, { ...rawResult, previewApprovalToken: 'approved-preview' });
    if (path === '/api/delegate/authorize-sign') {
      const reply = options.signReply ?? { status: 200, body: { ...rawResult, deliveryState: state, selectedKeyId: key.id } };
      return json(route, reply.status, reply.body);
    }
    if (path === `/api/approval-requests/${approvalId}/load`) {
      await options.loadHeld;
      const request = {
        targetDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', targetPublicJwk: jwk, nodeOrigin: host,
        permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }],
        grantLifetimeSeconds: 7200, reason: 'Read notes for two hours',
      };
      return json(route, 200, { requestId: approvalId, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), approved: false, denied: false, request });
    }
    if (path === '/api/delegate/prepare') {
      await options.prepareHeld;
      return json(route, 200, legacyPrepared());
    }
    if (path === '/api/delegate' && route.request().method() === 'POST') {
      const reply = options.approveReply ?? { status: 200, body: { hostActivated: true, delegationHeader: { Authorization: 'x' }, delegationCid: 'bafy-delegation' } };
      return json(route, reply.status, reply.body);
    }
    return json(route, 404, { error: `unmocked ${path}` });
  });
  return mocked;
}

/**
 * The popup's own page, as /auth/social/callback answers it. `complete` and `error` tell the opener how it ended;
 * `stay` leaves the window open and quiet; `close` closes it without a word.
 */
export async function mockPopup(
  page: Page,
  mocked: MockState,
  outcome: { type: 'complete' } | { type: 'error'; message: string } | { type: 'stay' } | { type: 'close' },
) {
  await page.context().route('**/auth/social/callback**', (route) => {
    let script = '';
    if (outcome.type === 'complete') {
      mocked.signedIn = true;
      script = `window.opener.postMessage({ type: 'openkey:social:complete', sessionToken: 'popup-session' }, location.origin); window.close();`;
    } else if (outcome.type === 'error') {
      script = `window.opener.postMessage(${JSON.stringify({ type: 'openkey:social:error', message: outcome.message })}, location.origin); window.close();`;
    } else if (outcome.type === 'close') {
      script = 'window.close();';
    }
    return route.fulfill({ status: 200, contentType: 'text/html', body: `<!doctype html><title>popup</title><script>${script}</script>` });
  });
}

/** An approval link, as a person gets it in a message. */
const approvalId = 'abcdefghijklmnopqrstuvwxyz';
export const approvalLink = `/a/${approvalId}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;

/** What the legacy review calls prepare answers. */
function legacyPrepared() {
  const kvGet = 'tinycloud.kv/get';
  const legacySiwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
    'Resources:',
    `- ${makeRecapResource({ [`${space}/kv/notes/`]: { [kvGet]: [{}] } })}`,
  ].join('\n');
  const optionKey = `tinycloud.kv\0${space}\0notes/`;
  const permissions = [{
    key: optionKey, service: 'kv', path: 'notes/', label: 'kv', resourcePath: 'kv/notes/',
    actions: [{ key: `${optionKey}\0${kvGet}`, action: 'get', ability: kvGet, required: false }],
  }];
  return {
    prepared: { siwe: legacySiwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host, permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

export const DEVICE_LINK = '/device?user_code=ABCD-EFGH';

/** The device lookup the /device page makes. */
export async function mockDeviceLookup(page: Page) {
  await page.route('**/api/device-authorizations/lookup**', (route) => json(route, 200, {
    id: 'device-fixture', userCode: 'ABCDEFGH', sessionDid: 'did:key:z6MkFixture',
    publicJwk: jwk, relayPublicJwk: {},
    permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }],
    nodeOrigin: 'https://node.example.test', shareOrigin: 'https://share.example.test',
    delegationTtlSeconds: 604_800,
    transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(),
    delegationExpiresAt: new Date(Date.now() + 604_800_000).toISOString(),
  }));
}
