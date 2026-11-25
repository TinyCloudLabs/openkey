// POST /api/delegate/prepare and POST /api/delegate (the approval route). The server BUILDS the SIWE from the
// `permissions` a link or app names, and `tinycloud.space/host` is an ability a permission may name: a message that
// hosts a space is the ability to create it. The same rule as POST /api/keys/:id/sign applies, from what the server
// holds about who is asking: an approval request, a device request or a loopback or paste link is OpenKey's own page;
// any other link, the token-less legacy request and a link that claims an origin are another site, which gets only
// the owner's non-primary spaces once the owner's primary space is hosted. Real delegate route, real WASM, a loopback
// node; the database, the TEE, the session and the approval-request store are stand-ins.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const owner = { id: 'user_owner', email: 'owner@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = {
  id: 'key_owner', userId: owner.id, address: account.address, keyType: 'MANAGED' as const,
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const HOST = 'tinycloud.space/host';

let row: { status: string } | null = null;
// What each read of the approval-request store does, in order; a read with nothing queued finds it still pending.
let approvalReads: Array<() => void> = [];
let signed: string[] = [];
const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: { findUnique: mock(async () => row) },
};

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', owner);
      c.set('session', { id: 'session_approve_hosts', userId: owner.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { address: wallet.address, signMessage: async (input: { message: string }) => { signed.push(input.message); return wallet.signMessage(input); } };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '../routes/approval-requests': () => ({
    admitApprovalDelegation: async () => {},
    checkApprovalDelegation: async () => { approvalReads.shift()?.(); },
    bindApprovalRenewal: async () => undefined,
    confirmBoundRenewal: () => {},
    releaseApprovalDelegation: async () => {},
    saveApprovalDelegation: async (_body: unknown, _userId: string, delegation: Record<string, unknown>) => delegation,
  }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;
let node: FakeTinyCloudNode;
const ENV = ['TINYCLOUD_BOOTSTRAP_HOST', 'TINYCLOUD_BOOTSTRAP_ON_SIGN'] as const;
const savedEnv = Object.fromEntries(ENV.map((name) => [name, process.env[name]]));

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import('../routes/delegate?approve-space-host' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import('../services/authorization-signing?approve-space-host' as string));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', owner);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: owner.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});
beforeEach(() => {
  node = startFakeTinyCloudNode();
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
  row = null;
  approvalReads = [];
  signed = [];
  resetContexts?.();
});
afterAll(() => {
  node?.stop();
  for (const name of ENV) {
    if (savedEnv[name] === undefined) delete process.env[name];
    else process.env[name] = savedEnv[name];
  }
});

type Reply = { status: number; body: { code?: string; delegationHeader?: { Authorization?: string }; prepared?: unknown; authorizationContext?: { token: string }; selectedActionKeys?: string[] } };
async function post(path: string, body: Record<string, unknown>): Promise<Reply> {
  const response = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: (await response.json()) as Reply['body'] };
}

/** A permission that asks to host `space`, spelled as `service` and `space` say. */
const hostPermission = (space: string, service = 'tinycloud.space') => ({ service, space, path: '', actions: [HOST] });
const kvPermission = (space: string) => ({ service: 'tinycloud.kv', space, path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] });

/** What the approval page sends to /prepare and then to /, for the extra fields `extra`. */
async function approve(permissions: unknown, extra: Record<string, unknown> = {}): Promise<{ prepared: Reply; approved?: Reply }> {
  const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions, ...extra });
  if (prepared.status !== 200) return { prepared };
  const approved = await post('/', {
    keyId: keyRecord.id, jwk, host: node.url, permissions, prepared: prepared.body.prepared,
    authorizationContextToken: prepared.body.authorizationContext!.token,
    selectedActionIds: prepared.body.selectedActionKeys, protocolVersion: 1, ...extra,
  });
  return { prepared, approved };
}

function expectRefused(reply: Reply | undefined) {
  expect(reply?.status).toBe(403);
  expect(reply?.body.code).toBe('host_signing_first_party_only');
  expect(reply?.body.delegationHeader).toBeUndefined();
  expect(signed).toEqual([]);
}

const ANOTHER_SITE = [
  { label: 'a link that says nothing about how it returns', extra: {} },
  { label: 'a link that returns to another site', extra: { linkDelivery: 'callback', linkCallback: 'https://app.example.test/cb' } },
  { label: 'a link that returns to a lookalike of loopback', extra: { linkDelivery: 'callback', linkCallback: 'http://127.0.0.1.evil.com:43111/cb' } },
  { label: 'a link that claims a TinyCloud app as its origin', extra: { requesterOrigin: 'https://home.tinycloud.xyz', requestOrigin: 'https://home.tinycloud.xyz' } },
] as const;

describe('a link that asks to host a space, from another site', () => {
  for (const { label, extra } of ANOTHER_SITE) {
    test(`${label} is refused for the primary space, hosted or not, in every spelling`, async () => {
      for (const hosted of [null, { status: 'complete' }]) {
        row = hosted;
        const spellings = [
          [hostPermission('default')],
          [hostPermission('default', 'space')],
          [hostPermission(spaceId('default'))],
          [hostPermission(spaceId('default'), 'space')],
          [kvPermission('default'), hostPermission('default')],
        ];
        for (const permissions of spellings) {
          resetContexts?.();
          const { prepared, approved } = await approve(permissions, extra);
          expectRefused(prepared);
          expect(approved).toBeUndefined();
        }
      }
    });
  }

  test('is refused for a non-primary space while the primary space is not known to be hosted', async () => {
    for (const unknown of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = unknown;
      expectRefused((await approve([hostPermission('public')])).prepared);
    }
  });

  test('is refused when the permissions mix the primary space with another', async () => {
    row = { status: 'complete' };
    expectRefused((await approve([hostPermission('public'), hostPermission('default')])).prepared);
  });

  test('is signed for a non-primary space once the primary space is hosted', async () => {
    row = { status: 'complete' };
    const { prepared, approved } = await approve([hostPermission('public')]);

    expect(prepared.status).toBe(200);
    expect(approved?.status).toBe(200);
    expect(approved?.body.delegationHeader?.Authorization).toBeTruthy();
    expect(signed.length).toBe(1);
  });

  test('the token-less request, which binds no context, is refused for the primary space and signs nothing', async () => {
    for (const hosted of [null, { status: 'complete' }]) {
      row = hosted;
      expectRefused(await post('/', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions: [hostPermission('default')] }));
    }
  });

  test('the token-less request is signed for a non-primary space once the primary space is hosted', async () => {
    row = { status: 'complete' };
    const approved = await post('/', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions: [hostPermission('public')] });

    expect(approved.status).toBe(200);
    expect(signed.length).toBe(1);
  });

  test('a context prepared for a plain permission cannot be approved with a host permission added', async () => {
    row = null;
    const prepared = await post('/prepare', { keyId: keyRecord.id, jwk, host: node.url, prefix: 'default', permissions: [kvPermission('default')] });
    expect(prepared.status).toBe(200);
    const approved = await post('/', {
      keyId: keyRecord.id, jwk, host: node.url, permissions: [kvPermission('default'), hostPermission('default')], prepared: prepared.body.prepared,
      authorizationContextToken: prepared.body.authorizationContext!.token, selectedActionIds: prepared.body.selectedActionKeys, protocolVersion: 1,
    });

    expect(approved.status).toBeGreaterThanOrEqual(400);
    expect(approved.body.delegationHeader).toBeUndefined();
    expect(signed).toEqual([]);
  });
});

describe('a link that asks to host a space, from OpenKey\'s own page', () => {
  const ALLOWED = [
    { label: 'a paste link', extra: { linkDelivery: 'paste' } },
    { label: 'a loopback callback link', extra: { linkDelivery: 'callback', linkCallback: 'http://127.0.0.1:43111/cb' } },
    { label: 'an approval request', extra: { approvalRequestId: 'request_owner' } },
  ] as const;
  for (const { label, extra } of ALLOWED) {
    test(`${label} is signed for the primary space whether or not the account is set up`, async () => {
      for (const hosted of [null, { status: 'complete' }]) {
        row = hosted;
        signed = [];
        resetContexts?.();
        const { approved } = await approve([hostPermission('default')], extra);

        expect(approved?.status).toBe(200);
        expect(approved?.body.delegationHeader?.Authorization).toBeTruthy();
        expect(signed.length).toBe(1);
      }
    });
  }

  test('an approval request that was denied after /prepare is refused at approval, before anything is signed', async () => {
    // /prepare reads the request, the check before signing reads it, then the read that decides the authority refuses it.
    approvalReads = [() => {}, () => {}, () => { throw new Error('Approval request is no longer pending'); }];
    const { prepared, approved } = await approve([hostPermission('default')], { approvalRequestId: 'request_owner' });

    expect(prepared.status).toBe(200);
    expectRefused(approved);
  });
});
