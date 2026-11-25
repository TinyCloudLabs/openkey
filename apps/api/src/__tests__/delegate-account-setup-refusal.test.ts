// The sign widget's prepare step refuses a site that is not TinyCloud's own a message that hosts the owner's primary
// space (`host_signing_first_party_only`). When the owner's account is not set up on TinyCloud hosting, the refusal
// says so (`accountSetup: 'required'`), so the widget can offer OpenKey's own account setup page; the code is the
// same either way.

import { afterAll, beforeAll, beforeEach, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_setup_refusal', email: 'setup@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const THIRD_PARTY = 'https://app.example.test';
const keyRecord = {
  id: 'key_setup_refusal', userId: user.id, address: account.address, keyType: 'MANAGED' as string,
  archivedAt: null, sealedBlob: 'key-blob' as string | null, sealingContext: null,
};

let row: { status: string } | null = null;
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
      c.set('user', user);
      c.set('session', { id: 'session_setup_refusal', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => privateKey),
  }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
const savedOnSign = process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
beforeAll(async () => {
  process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
  ({ delegateRouter: router } = await import('../routes/delegate?account-setup-refusal' as string));
});
afterAll(() => {
  if (savedOnSign === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  else process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = savedOnSign;
});
beforeEach(() => {
  row = null;
  keyRecord.keyType = 'MANAGED';
  keyRecord.sealedBlob = 'key-blob';
});

function defaultHostSiwe() {
  return generateHostSIWEMessage({
    address: account.address, chainId: 1, domain: new URL(THIRD_PARTY).host, issuedAt: new Date().toISOString(),
    spaceId: `tinycloud:pkh:eip155:1:${account.address}:default`, peerId: PEER,
  }).replace(/^(Issued At: .*)$/m, `$1\nExpiration Time: ${new Date(Date.now() + 3_600_000).toISOString()}`);
}

async function prepare(): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await router.request('/authorize-sign-prepare', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ keyId: keyRecord.id, siwe: defaultHostSiwe(), jwk, host: 'https://node.tinycloud.xyz', requestOrigin: THIRD_PARTY }),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

test('the host-signing refusal says setup is required only while the account is not set up', async () => {
  for (const state of [null, { status: 'failed' }, { status: 'in_progress' }]) {
    row = state;
    const reply = await prepare();
    expect(reply.status).toBe(403);
    expect(reply.body).toEqual({
      error: expect.any(String),
      code: 'host_signing_first_party_only',
      accountSetup: 'required',
    });
  }

  row = { status: 'complete' };
  const reply = await prepare();
  expect(reply.status).toBe(403);
  expect(reply.body.code).toBe('host_signing_first_party_only');
  expect(reply.body).not.toHaveProperty('accountSetup');
});
