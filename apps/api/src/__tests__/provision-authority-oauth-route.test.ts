// P4: the OAuth signer route (`POST /api/delegate/sign`, tinycloud:session clients). A client that is not first-party
// signs for an account that is already set up and never sets one up: when the account is not set up, the
// bootstrap skips and the signature is refused. The bootstrap is a stand-in here; its own authority rules are in
// provision-authority-bootstrap.test.ts.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  createDelegateSignerAuth,
} from '../middleware/delegate-signer-auth';
import { coordinationosUserNamespace } from '../services/coordinationos-session-policy';
import { mockModules, replaceModules } from './mock-module';

const configuredClientId = 'coordinationos-client';
const configuredOrigin = 'https://coordination.example';

const rawBearer = 'opaque_OpenKey_token_123';
const tokenHash = createHash('sha256').update(rawBearer).digest('base64url');
const tokenAudit = createHash('sha256').update(rawBearer).digest('hex');
const serverRequestIdPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const key = {
  id: 'key_1',
  userId: 'user_1',
  address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed',
  sealingContext: null,
};
const token = {
  id: 'oauth_token_1',
  token: tokenHash,
  clientId: configuredClientId,
  userId: 'user_1',
  scopes: ['openid', 'email', 'keys', 'tinycloud:session'],
  createdAt: new Date(),
  expiresAt: new Date(),
};
const client = {
  clientId: configuredClientId,
  disabled: false,
  type: 'web',
  public: false,
  tokenEndpointAuthMethod: 'client_secret_basic',
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid', 'email', 'keys', 'tinycloud:session'],
  tinycloudSessionPolicy: 'coordinationos-kv-v1' as string | null,
  tinycloudSessionOrigin: configuredOrigin as string | null,
};

let decisions: any[] = [];
let grants: any[] = [];
let signerCalls = 0;
let signerFailure = false;
let auditFailure = false;
let betterAuthSession = false;
let bootstrapMode: 'complete' | 'skipped' | 'failed' = 'complete';
let bootstrapCalls: any[] = [];
let executionOrder: string[] = [];
let autoSignEnabled = true;
let tinyCloudManageKeyEnabled = true;
let manageKeyAppEnabled = true;
let tinyCloudManageKeyMode = 'APP_MANAGED';
let manageKeySigningDecisions: any[] = [];
let transactionTail: Promise<void> = Promise.resolve();
let storedOauthTokens = new Map<string, any>();
let registeredOauthClients = new Map<string, any>();
let consentedClientIds = new Set<string>();
let resolvedOauthUser: { id: string; emailVerified: boolean; lockedAt?: Date | null } | null = {
  id: 'user_1',
  emailVerified: true,
};
let resolvedKey: any = { ...key };

const prisma: any = {
  // The terms gate of the signer auth: the account has accepted.
  termsAcceptance: { findFirst: mock(async () => ({ id: 'terms_1' })) },
  oauthAccessToken: {
    findUnique: mock(async ({ where }: any) => storedOauthTokens.get(where.token) ?? null),
  },
  oauthClient: {
    findUnique: mock(async ({ where }: any) => registeredOauthClients.get(where.clientId) ?? null),
  },
  user: {
    findUnique: mock(async ({ select }: any) => select?.autoSignEnabled
      ? { autoSignEnabled }
      : select?.tinyCloudManageKeyMode
        ? { tinyCloudManageKeyEnabled, tinyCloudManageKeyMode, tinyCloudManageKeyPolicyEpoch: BigInt(0) }
        : select?.tinyCloudManageKeyEnabled
          ? { tinyCloudManageKeyEnabled }
        : resolvedOauthUser),
  },
  oauthConsent: {
    findFirst: mock(async ({ where }: any) => consentedClientIds.has(where.clientId) ? { clientId: where.clientId } : null),
  },
  tinyCloudManageKeyAppPreference: {
    findUnique: mock(async () => ({ enabled: manageKeyAppEnabled, status: manageKeyAppEnabled ? 'ENABLED' : 'DISABLED' })),
  },
  ethereumKey: {
    findUnique: mock(async ({ where }: any) => where.id === key.id ? resolvedKey : null),
    findFirst: mock(async ({ where }: any) => {
      if (where.id && where.id !== key.id) return null;
      return key;
    }),
  },
  coordinationosSigningDecision: {
    create: mock(async ({ data }: any) => {
      if (auditFailure) throw new Error('audit unavailable');
      decisions.push(data);
      return data;
    }),
  },
  tinyCloudManageKeySigningDecision: {
    create: mock(async ({ data }: any) => { manageKeySigningDecisions.push(data); return data; }),
  },
  $queryRawUnsafe: mock(async () => []),
  coordinationosSessionGrant: {
    create: mock(async ({ data }: any) => {
      if (grants.some((grant) => grant.oauthAccessTokenId === data.oauthAccessTokenId
        || grant.nonceDigest === data.nonceDigest)) {
        throw Object.assign(new Error('unique'), { code: 'P2002' });
      }
      grants.push(data);
      return data;
    }),
    findUnique: mock(async ({ where }: any) => grants.find((grant) =>
      where.oauthAccessTokenId
        ? grant.oauthAccessTokenId === where.oauthAccessTokenId
        : grant.nonceDigest === where.nonceDigest
    ) ?? null),
  },
  $transaction: mock((callback: (tx: any) => Promise<unknown>) => {
    const run = transactionTail.then(async () => {
      const decisionLength = decisions.length;
      const grantLength = grants.length;
      const manageKeyDecisionLength = manageKeySigningDecisions.length;
      try {
        return await callback(prisma);
      } catch (error) {
        decisions.splice(decisionLength);
        grants.splice(grantLength);
        manageKeySigningDecisions.splice(manageKeyDecisionLength);
        throw error;
      }
    });
    transactionTail = run.then(() => undefined, () => undefined);
    return run;
  }),
};

const ensureTinyCloudBootstrapForApprovedSign = mock(async (input: any) => {
  bootstrapCalls.push(input);
  executionOrder.push(`bootstrap:${bootstrapMode}`);
  return bootstrapMode === 'failed'
    ? {
        status: 'failed' as const,
        errorCode: 'tinycloud_bootstrap_failed',
        errorMessage: 'bootstrap unavailable',
      }
    : { status: bootstrapMode };
});
// The route's non-sign endpoints retain their normal middleware. /sign is
// explicitly replaced below through the injectable auth seam under test.
replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c) => c.json({ error: 'Unauthorized' }, 401)),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrapForApprovedSign,
  }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: async () => new Uint8Array(32) }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (value: `0x${string}`) => {
      const wallet = privateKeyToAccount(value);
      return {
        ...wallet,
        signMessage: async (input: { message: string }) => {
          signerCalls += 1;
          executionOrder.push('sign');
          if (signerFailure) throw new Error('TEE signer unavailable');
          return wallet.signMessage(input);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let setSignerAuth: typeof import('../routes/delegate')['setDelegateSignerAuthMiddlewareForTests'];

function installSignerAuth() {
  setSignerAuth(createDelegateSignerAuth({
    database: prisma,
    resolveSession: async (c) => {
      if (!betterAuthSession) return false;
      c.set('user', { id: 'user_1', email: 'alice@example.test' });
      c.set('session', {
        id: 'session_1',
        userId: 'user_1',
        expiresAt: new Date(Date.now() + 60_000),
      });
      return true;
    },
  }));
}

beforeAll(async () => {
  ({
    delegateRouter: router,
    setDelegateSignerAuthMiddlewareForTests: setSignerAuth,
  } = await import('../routes/delegate?provision-authority-oauth-isolated' as string));
  installSignerAuth();
});

afterAll(() => {
  setSignerAuth();
});

beforeEach(() => {
  decisions = [];
  grants = [];
  signerCalls = 0;
  signerFailure = false;
  auditFailure = false;
  betterAuthSession = false;
  bootstrapMode = 'complete';
  bootstrapCalls = [];
  executionOrder = [];
  autoSignEnabled = true;
  tinyCloudManageKeyEnabled = true;
  tinyCloudManageKeyMode = 'APP_MANAGED';
  manageKeySigningDecisions = [];
  manageKeyAppEnabled = true;
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
  transactionTail = Promise.resolve();
  resolvedOauthUser = { id: 'user_1', emailVerified: true };
  resolvedKey = { ...key };
  token.clientId = configuredClientId;
  token.userId = 'user_1';
  token.scopes = ['openid', 'email', 'keys', 'tinycloud:session'];
  token.createdAt = new Date(Date.now() - 1_000);
  token.expiresAt = new Date(Date.now() + 299_000);
  client.clientId = configuredClientId;
  client.disabled = false;
  client.type = 'web';
  client.public = false;
  client.tokenEndpointAuthMethod = 'client_secret_basic';
  client.grantTypes = ['authorization_code'];
  client.responseTypes = ['code'];
  client.scopes = ['openid', 'email', 'keys', 'tinycloud:session'];
  client.tinycloudSessionPolicy = 'coordinationos-kv-v1';
  client.tinycloudSessionOrigin = configuredOrigin;
  storedOauthTokens = new Map([[tokenHash, token]]);
  registeredOauthClients = new Map([[configuredClientId, client]]);
  consentedClientIds = new Set([configuredClientId]);
  installSignerAuth();
});

function signingBody(options: {
  requestAddress?: string;
  requestChainId?: number;
  domain?: string;
  siweChainId?: number;
  issuedAt?: string;
  expirationTime?: string;
  spaceId?: string;
  abilities?: Record<string, Record<string, string[]>>;
  type?: string;
  purpose?: string;
} = {}) {
  const current = new Date();
  return {
    address: options.requestAddress ?? address,
    chainId: options.requestChainId ?? 1,
    message: prepareSession({
      address,
      chainId: options.siweChainId ?? 1,
      domain: options.domain ?? 'coordination.example',
      issuedAt: options.issuedAt ?? current.toISOString(),
      expirationTime: options.expirationTime
        ?? new Date(current.getTime() + 3_600_000).toISOString(),
      spaceId: options.spaceId ?? `tinycloud:pkh:eip155:1:${address}:applications`,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities: options.abilities ?? {
        kv: {
          [`coordinationos/integration/v1/${coordinationosUserNamespace(key.id)}/canary`]: [
            'tinycloud.kv/get',
            'tinycloud.kv/put',
          ],
        },
      },
    }).siwe,
    type: options.type ?? 'siwe',
    purpose: options.purpose ?? 'sign-in',
    keyId: key.id,
  };
}

function sign(
  body: unknown = signingBody(),
  authorization: string | null = `Bearer ${rawBearer}`,
  headers: Record<string, string> = {},
) {
  return router.request('/sign', {
    method: 'POST',
    headers: {
      ...(authorization === null ? {} : { authorization }),
      origin: configuredOrigin,
      'content-type': 'application/json',
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}


test('an account that is not set up is refused the signature, and the client is judged by its client id', async () => {
  bootstrapMode = 'skipped';
  const response = await sign();

  expect(response.status).toBe(500);
  expect(await response.json()).toMatchObject({ approved: false, code: 'signer_failed' });
  expect(signerCalls).toBe(0);
  expect(bootstrapCalls).toHaveLength(1);
  expect(bootstrapCalls[0].authority).toEqual({ kind: 'oauth-client', clientId: configuredClientId });
  expect(bootstrapCalls[0].acceptCompleteRow).toBe(true);
  expect(executionOrder).toEqual(['bootstrap:skipped']);
});

test('an account that is already set up is signed for, as before', async () => {
  bootstrapMode = 'complete';
  const response = await sign();

  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ approved: true });
  expect(signerCalls).toBe(1);
  expect(executionOrder).toEqual(['bootstrap:complete', 'sign']);
});

test('a failed bootstrap still refuses the signature', async () => {
  bootstrapMode = 'failed';
  const response = await sign();

  expect(response.status).toBe(500);
  expect(signerCalls).toBe(0);
});
