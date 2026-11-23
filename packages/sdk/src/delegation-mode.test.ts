// TC-3810 (step 4): OpenKey.authorizeTinyCloud forwards optional delegationMode
// to the widget on both managed and external-wallet flows without adding it when omitted.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

const siwe = 'app wants you to sign in with your Ethereum account:\n0xfirst';
const grant = { signature: '0xsig', address: '0xfirst', signedMessage: siwe, selectedActionKeys: [], permissions: [] };

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

describe('TC-3810 delegationMode forwarding', () => {
  test('managed authorizeTinyCloud forwards terminal, attenuable, and omits undefined', async () => {
    const { openkey, widgetRequests } = openKeyWith('MANAGED', grant);
    await openkey.authorizeTinyCloud({ protocolVersion: 1, siwe, jwk: {}, delegationMode: 'attenuable' }, { mode: 'iframe' });
    await openkey.authorizeTinyCloud({ protocolVersion: 1, siwe, jwk: {}, delegationMode: 'terminal' }, { mode: 'iframe' });
    await openkey.authorizeTinyCloud({ protocolVersion: 1, siwe, jwk: {} }, { mode: 'iframe' });
    expect(widgetRequests[0]!.delegationMode).toBe('attenuable');
    expect(widgetRequests[1]!.delegationMode).toBe('terminal');
    expect(widgetRequests[2]).not.toHaveProperty('delegationMode');
  });

  test('external authorizeTinyCloud forwards delegationMode to the externalSign widget request', async () => {
    const approval = { authorizationContextToken: 'ctx', previewApprovalToken: 'preview', signedMessage: siwe, selectedActionIds: [], address: '0xfirst' };
    const { openkey, internals, widgetRequests } = openKeyWith('EXTERNAL', approval);
    internals.findWalletProvider = async () => ({ request: async () => '0xwallet-sig' });
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ signature: '0xwallet-sig', address: '0xfirst', signedMessage: siwe, selectedActionKeys: [], permissions: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as unknown as typeof fetch;
    try {
      await openkey.authorizeTinyCloud({ protocolVersion: 1, siwe, jwk: {}, delegationMode: 'attenuable' }, { mode: 'iframe' });
      await openkey.authorizeTinyCloud({ protocolVersion: 1, siwe, jwk: {} }, { mode: 'iframe' });
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(widgetRequests[0]!.delegationMode).toBe('attenuable');
    expect(widgetRequests[1]).not.toHaveProperty('delegationMode');
  });
});
