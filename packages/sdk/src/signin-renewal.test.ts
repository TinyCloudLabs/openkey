// TC-2872: `authorizeTinyCloud({ renewal })`, the app's ask for the renewal checkbox on OpenKey's sign-in window.
// The SDK forwards a well-formed ask to the widget, hands back the owner's choice and the signed lease, and on
// an external wallet has the wallet sign the lease after the grant; a declined lease fails the sign-in.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { afterEach, describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

const siwe = 'app wants you to sign in with your Ethereum account:\n0xfirst';
const ASK = { version: 1, leaseLifetimeSeconds: 90 * 86_400 } as const;
const receipt = {
  version: 1, approvedLeaseLifetimeSeconds: 90 * 86_400, approvedAt: '2026-11-17T00:00:00.000Z',
  receipt: { originalCid: 'bafy-grant', leaseCid: 'bafy-lease', leaseAuthorization: 'lease-cacao', leaseExpiresAt: '2027-02-15T00:00:00.000Z', leaseGeneration: 1,
    nodeIdentity: { nodeDid: 'did:key:node', renewerDid: 'did:key:renewer' } },
};
const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function openKeyWith(keyType: 'MANAGED' | 'EXTERNAL', widgetAnswer: Record<string, unknown>) {
  const openkey = Object.create(OpenKey.prototype) as OpenKey;
  const internals = openkey as unknown as Record<string, unknown>;
  internals.activeFlowCancellations = new Set();
  internals.lastAuth = { address: '0xfirst', keyId: 'key-first', keyType };
  internals.oauthHost = 'https://api.openkey.test';
  internals.fetchKnownKeysIfNeeded = async () => [];
  const widgetRequests: Array<Record<string, unknown>> = [];
  internals.openFlow = async (_action: string, request: Record<string, unknown>) => {
    widgetRequests.push(request);
    return widgetAnswer;
  };
  return { openkey, internals, widgetRequests };
}

const authorize = (openkey: OpenKey, extra: Record<string, unknown>) =>
  openkey.authorizeTinyCloud({ protocolVersion: 1, siwe, jwk: {}, ...extra } as Parameters<OpenKey['authorizeTinyCloud']>[0], { mode: 'iframe' });

const grant = { signature: '0xsig', address: '0xfirst', signedMessage: siwe, selectedActionKeys: [], permissions: [] };

describe('the renewal ask', () => {
  test('reaches the widget as a clean copy, only beside expiryChangeable: true', async () => {
    const { openkey, widgetRequests } = openKeyWith('MANAGED', grant);
    await authorize(openkey, { expiryChangeable: true, renewal: { ...ASK, purpose: 'standing', extra: 'dropped' } });
    expect(widgetRequests[0]!.renewal).toEqual({ ...ASK, purpose: 'standing' });
    await authorize(openkey, { expiryChangeable: true });
    expect(widgetRequests[1]).not.toHaveProperty('renewal');
  });

  test('a malformed ask, or one without expiryChangeable, fails in the app and opens nothing', async () => {
    const { openkey, widgetRequests } = openKeyWith('MANAGED', grant);
    for (const extra of [
      { renewal: ASK },
      { expiryChangeable: true, renewal: { version: 2, leaseLifetimeSeconds: 60 } },
      { expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 366 * 86_400 } },
      { expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 1.5 } },
      { expiryChangeable: true, renewal: { ...ASK, purpose: 'forever' } },
    ]) {
      await expect(authorize(openkey, extra)).rejects.toThrow(/renewal/);
    }
    expect(widgetRequests).toHaveLength(0);
  });
});

describe('the managed-key result', () => {
  test('carries the owner\'s choice and the signed lease from the widget', async () => {
    const leased = await authorize(openKeyWith('MANAGED', { ...grant, renewalChoice: 'leased', renewal: receipt }).openkey, { expiryChangeable: true, renewal: ASK });
    expect(leased).toMatchObject({ renewalChoice: 'leased', renewal: receipt });
    const finite = await authorize(openKeyWith('MANAGED', { ...grant, renewalChoice: 'finite' }).openkey, { expiryChangeable: true, renewal: ASK });
    expect(finite.renewalChoice).toBe('finite');
    expect(finite).not.toHaveProperty('renewal');
  });

  test('a leased choice with no lease is refused', async () => {
    await expect(authorize(openKeyWith('MANAGED', { ...grant, renewalChoice: 'leased' }).openkey, { expiryChangeable: true, renewal: ASK }))
      .rejects.toThrow(/no renewal lease/);
  });
});

describe('an external wallet', () => {
  const approval = { authorizationContextToken: 'ctx', previewApprovalToken: 'preview', signedMessage: siwe, selectedActionIds: [], address: '0xfirst' };

  function setUp(walletAnswers: { lease: () => Promise<string> }) {
    const { openkey, internals } = openKeyWith('EXTERNAL', approval);
    const walletCalls: unknown[][] = [];
    internals.findWalletProvider = async () => ({
      request: async ({ params }: { method: string; params: unknown[] }) => {
        walletCalls.push(params);
        return walletCalls.length === 1 ? '0xgrant-signature' : walletAnswers.lease();
      },
    });
    const posts: Array<{ url: string; body: Record<string, unknown> }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      posts.push({ url, body });
      if (url.endsWith('/api/delegate/authorize-sign')) {
        return Response.json({ ...grant, renewalChoice: 'leased', renewalSignature: { message: 'lease message', leaseLifetimeSeconds: ASK.leaseLifetimeSeconds, renewalToken: 'okr_token' } });
      }
      if (url.endsWith('/api/delegate/authorize-sign-renewal')) return Response.json({ renewalChoice: 'leased', renewal: receipt });
      throw new Error(`unexpected ${url}`);
    }) as typeof fetch;
    return { openkey, walletCalls, posts };
  }

  test('signs the lease after the grant, and OpenKey returns it with that signature', async () => {
    const { openkey, walletCalls, posts } = setUp({ lease: async () => '0xlease-signature' });
    const result = await authorize(openkey, { expiryChangeable: true, renewal: ASK });
    expect(result).toMatchObject({ signature: '0xsig', renewalChoice: 'leased', renewal: receipt });
    const hex = [...new TextEncoder().encode('lease message')].map((byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(walletCalls[1]).toEqual([`0x${hex}`, '0xfirst']);
    expect(posts[1]).toEqual({
      url: 'https://api.openkey.test/api/delegate/authorize-sign-renewal',
      body: { renewalToken: 'okr_token', signature: '0xlease-signature' },
    });
  });

  test('declining the lease signature fails the sign-in', async () => {
    const { openkey, posts } = setUp({ lease: async () => { throw new Error('User rejected the request.'); } });
    await expect(authorize(openkey, { expiryChangeable: true, renewal: ASK })).rejects.toThrow('User rejected the request.');
    expect(posts.map((post) => post.url)).toEqual(['https://api.openkey.test/api/delegate/authorize-sign']);
  });
});
