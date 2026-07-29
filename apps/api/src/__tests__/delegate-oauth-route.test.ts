import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { BOOTSTRAP_SESSION_REQUESTS, bootstrapSpaceId } from '@tinycloud/bootstrap';
import {
  createDelegateSignerAuth,
} from '../middleware/delegate-signer-auth';
import {
  COORDINATIONOS_DENIAL_STATUS,
} from '../services/coordinationos-signing-audit';
import { coordinationosUserNamespace } from '../services/coordinationos-session-policy';

const configuredClientId = 'coordinationos-client';
const configuredOrigin = 'https://coordination.example';
process.env.OPENKEY_COORDINATIONOS_OAUTH_CLIENT_ID = configuredClientId;
process.env.OPENKEY_COORDINATIONOS_ORIGIN = configuredOrigin;

const rawBearer = 'opaque_OpenKey_token_123';
const tokenHash = createHash('sha256').update(rawBearer).digest('base64url');
const tokenAudit = createHash('sha256').update(rawBearer).digest('hex');
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const key = {
  id: 'key_1',
  userId: 'user_1',
  address,
  keyType: 'MANAGED',
  keyPurpose: 'PERSONAL',
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
  mode: 'PERSONAL',
  type: 'web',
  public: false,
  tokenEndpointAuthMethod: 'client_secret_basic',
  grantTypes: ['authorization_code'],
  responseTypes: ['code'],
  scopes: ['openid', 'email', 'keys', 'tinycloud:session'],
};

let decisions: any[] = [];
let grants: any[] = [];
let signerCalls = 0;
let signerFailure = false;
let auditFailure = false;
let betterAuthSession = false;
let bootstrapMode: 'fresh' | 'cached' | 'failed' = 'fresh';
let bootstrapCalls: any[] = [];
let executionOrder: string[] = [];
let transactionTail: Promise<void> = Promise.resolve();
let resolvedOauthUser: { id: string; emailVerified: boolean } | null = {
  id: 'user_1',
  emailVerified: true,
};

const prisma: any = {
  oauthAccessToken: {
    findUnique: mock(async ({ where }: any) => where.token === tokenHash ? token : null),
  },
  oauthClient: {
    findUnique: mock(async () => client),
  },
  user: {
    findUnique: mock(async ({ select }: any) => select?.autoSignEnabled
      ? { autoSignEnabled: true }
      : resolvedOauthUser),
  },
  ethereumKey: {
    findUnique: mock(async ({ where }: any) => where.id === key.id ? key : null),
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
      try {
        return await callback(prisma);
      } catch (error) {
        decisions.splice(decisionLength);
        grants.splice(grantLength);
        throw error;
      }
    });
    transactionTail = run.then(() => undefined, () => undefined);
    return run;
  }),
};

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
const ensureTinyCloudBootstrapForApprovedSign = mock(async (input: any) => {
  bootstrapCalls.push(input);
  executionOrder.push(`bootstrap:${bootstrapMode}`);
  return bootstrapMode === 'failed'
    ? {
        status: 'failed' as const,
        errorCode: 'tinycloud_bootstrap_failed',
        errorMessage: 'bootstrap unavailable',
      }
    : { status: 'complete' as const };
});
mock.module('../services/tinycloud-bootstrap', () => ({
  ensureTinyCloudBootstrapForApprovedSign,
}));
const realTee = await import('../../../../packages/tee/src/index?coordinationos-route-test' as string);
mock.module('@openkey/tee', () => ({
  ...realTee,
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
}));
// The route's non-sign endpoints retain their normal middleware. /sign is
// explicitly replaced below through the injectable auth seam under test.
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c) => c.json({ error: 'Unauthorized' }, 401)),
}));

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
  } = await import('../routes/delegate?coordinationos-oauth-route-isolated' as string));
  installSignerAuth();
});

afterAll(() => {
  setSignerAuth();
  mock.restore();
});

beforeEach(() => {
  decisions = [];
  grants = [];
  signerCalls = 0;
  signerFailure = false;
  auditFailure = false;
  betterAuthSession = false;
  bootstrapMode = 'fresh';
  bootstrapCalls = [];
  executionOrder = [];
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
  transactionTail = Promise.resolve();
  resolvedOauthUser = { id: 'user_1', emailVerified: true };
  token.clientId = configuredClientId;
  token.userId = 'user_1';
  token.scopes = ['openid', 'email', 'keys', 'tinycloud:session'];
  token.createdAt = new Date(Date.now() - 1_000);
  token.expiresAt = new Date(Date.now() + 299_000);
  client.clientId = configuredClientId;
  client.disabled = false;
  client.mode = 'PERSONAL';
  client.type = 'web';
  client.public = false;
  client.tokenEndpointAuthMethod = 'client_secret_basic';
  client.grantTypes = ['authorization_code'];
  client.responseTypes = ['code'];
  client.scopes = ['openid', 'email', 'keys', 'tinycloud:session'];
  process.env.OPENKEY_COORDINATIONOS_OAUTH_CLIENT_ID = configuredClientId;
  process.env.OPENKEY_COORDINATIONOS_ORIGIN = configuredOrigin;
  installSignerAuth();
});

function signingBody() {
  const current = new Date();
  return {
    address,
    chainId: 1,
    message: prepareSession({
      address,
      chainId: 1,
      domain: 'coordination.example',
      issuedAt: current.toISOString(),
      expirationTime: new Date(current.getTime() + 3_600_000).toISOString(),
      spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities: {
        kv: {
          [`coordinationos/integration/v1/${coordinationosUserNamespace(key.id)}/canary`]: [
            'tinycloud.kv/get',
            'tinycloud.kv/put',
          ],
        },
      },
    }).siwe,
    type: 'siwe',
    purpose: 'sign-in',
    keyId: key.id,
  };
}

function bootstrapSigningBody() {
  const abilities: Record<string, Record<string, string[]>> = {};
  for (const resource of BOOTSTRAP_SESSION_REQUESTS.default.resources) {
    const service = resource.service.replace(/^tinycloud\./, '');
    abilities[service] ??= {};
    abilities[service]![resource.path] = [...resource.actions];
  }
  return {
    address,
    chainId: 1,
    message: prepareSession({
      address,
      chainId: 1,
      domain: 'cli.tinycloud.xyz',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
      spaceId: bootstrapSpaceId(address, 1, 'default'),
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities,
    }).siwe,
    type: 'siwe',
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

async function expectDenied(
  responsePromise: Response | Promise<Response>,
  status: number,
  code: string,
  expectedDecisions = 1,
  expectedSignerCalls = 0,
) {
  const response = await responsePromise;
  expect(response.status).toBe(status);
  expect(await response.json()).toMatchObject({
    approved: false,
    needsApproval: false,
    code,
  });
  expect(decisions).toHaveLength(expectedDecisions);
  if (expectedDecisions === 1) {
    expect(decisions[0]).toMatchObject({ decision: 'DENY', reasonCode: code });
  }
  expect(signerCalls).toBe(expectedSignerCalls);
  expect(JSON.stringify(decisions)).not.toContain(rawBearer);
  expect(JSON.stringify(decisions)).not.toContain('unknownOpaqueBearer123');
}

describe('CoordinationOS OAuth signer route', () => {
  test('raw bearer resolves by storage digest and audit stores only the hex digest', async () => {
    const response = await sign();
    expect(response.status).toBe(200);
    expect(signerCalls).toBe(1);
    expect(prisma.oauthAccessToken.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { token: tokenHash } }),
    );
    expect(token.token).not.toBe(rawBearer);
    expect(JSON.stringify(decisions)).not.toContain(rawBearer);
    expect(decisions[0].tokenDigest).toBe(tokenAudit);
    expect(decisions[0].evidence.tokenDigest).toBe(tokenAudit);
    expect(decisions[0]).toMatchObject({ decision: 'ALLOW', reasonCode: 'allow' });
  });

  test('untrusted request ID cannot persist the raw bearer in audit evidence', async () => {
    const response = await sign(signingBody(), `Bearer ${rawBearer}`, {
      'x-request-id': rawBearer,
    });

    expect(response.status).toBe(200);
    expect(decisions).toHaveLength(1);
    expect(decisions[0].requestId).toBeNull();
    expect(decisions[0].evidence.requestId).toBeNull();
    expect(decisions[0].tokenDigest).toBe(tokenAudit);
    expect(decisions[0].evidence.tokenDigest).toBe(tokenAudit);
    expect(decisions[0].tokenDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(decisions)).not.toContain(rawBearer);
  });

  test('fresh managed PERSONAL key bootstraps before exactly one signer call', async () => {
    bootstrapMode = 'fresh';
    const response = await sign();

    expect(response.status).toBe(200);
    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toMatchObject({
      prisma,
      userId: 'user_1',
      key: {
        id: key.id,
        address,
        keyType: 'MANAGED',
        keyPurpose: 'PERSONAL',
      },
      privateKey,
      format: 'personal_sign',
    });
    expect(bootstrapCalls[0].message).toContain(
      `tinycloud:pkh:eip155:1:${address}:account`,
    );
    expect(executionOrder).toEqual(['bootstrap:fresh', 'sign']);
    expect(signerCalls).toBe(1);
  });

  test('cached bootstrap remains idempotent and still signs exactly once', async () => {
    bootstrapMode = 'cached';
    const response = await sign();

    expect(response.status).toBe(200);
    expect(bootstrapCalls).toHaveLength(1);
    expect(executionOrder).toEqual(['bootstrap:cached', 'sign']);
    expect(signerCalls).toBe(1);
    expect(grants).toHaveLength(1);
  });

  test('bootstrap failure consumes grant, appends ERROR, and makes zero signing calls', async () => {
    bootstrapMode = 'failed';
    const response = await sign();

    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({
      approved: false,
      needsApproval: false,
      code: 'signer_failed',
    });
    expect(bootstrapCalls).toHaveLength(1);
    expect(executionOrder).toEqual(['bootstrap:failed']);
    expect(signerCalls).toBe(0);
    expect(grants).toHaveLength(1);
    expect(decisions.map((decision) => [decision.decision, decision.reasonCode])).toEqual([
      ['ALLOW', 'allow'],
      ['ERROR', 'signer_failed'],
    ]);

    bootstrapMode = 'fresh';
    const reuse = await sign();
    expect(reuse.status).toBe(409);
    expect(await reuse.json()).toMatchObject({
      code: 'token_consumed',
      needsApproval: false,
    });
    expect(bootstrapCalls).toHaveLength(1);
    expect(signerCalls).toBe(0);
  });

  test('one token signs once across sequential and concurrent reuse', async () => {
    expect((await sign()).status).toBe(200);
    await expectDenied(sign(), 409, 'token_consumed', 2, 1);
    expect(signerCalls).toBe(1);

    decisions = [];
    grants = [];
    signerCalls = 0;
    const responses = await Promise.all([sign(), sign()]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
    const denied = responses.find((response) => response.status === 409)!;
    expect(await denied.json()).toMatchObject({
      code: 'token_consumed',
      needsApproval: false,
    });
    expect(decisions.filter((decision) => decision.decision === 'ALLOW')).toHaveLength(1);
    expect(decisions.filter((decision) => decision.reasonCode === 'token_consumed')).toHaveLength(1);
    expect(signerCalls).toBe(1);
  });

  test.each([
    ['missing authorization', null, 'missing_authorization'],
    ['malformed authorization', 'Basic opaque', 'malformed_authorization'],
    ['multiple authorization', `Bearer ${rawBearer}, Bearer second`, 'multiple_authorization'],
    ['unknown bearer', 'Bearer unknownOpaqueBearer123', 'unknown_token'],
  ])('%s is audited before signing', async (_name, authorization, code) => {
    await expectDenied(sign(signingBody(), authorization), 401, code);
  });

  test.each([
    ['wrong client', () => { token.clientId = 'other-client'; }, 'wrong_client'],
    ['disabled client', () => { client.disabled = true; }, 'client_disabled'],
    ['missing token scope', () => {
      token.scopes = ['openid', 'email', 'keys'];
    }, 'missing_scope'],
    ['non-web client', () => { client.type = 'spa'; }, 'client_misconfigured'],
    ['non-personal client', () => { client.mode = 'TENANT_MANAGED'; }, 'client_misconfigured'],
    ['public client', () => { client.public = true; }, 'client_misconfigured'],
    ['wrong auth method', () => {
      client.tokenEndpointAuthMethod = 'none';
    }, 'client_misconfigured'],
    ['wrong grants', () => {
      client.grantTypes = ['authorization_code', 'refresh_token'];
    }, 'client_misconfigured'],
    ['wrong response types', () => {
      client.responseTypes = ['code', 'token'];
    }, 'client_misconfigured'],
    ['wrong client scopes', () => {
      client.scopes = ['openid', 'email', 'keys', 'tinycloud:session', 'offline_access'];
    }, 'client_misconfigured'],
    ['missing user', () => { resolvedOauthUser = null; }, 'user_not_found'],
    ['unverified user', () => {
      resolvedOauthUser = { id: 'user_1', emailVerified: false };
    }, 'email_not_verified'],
  ])('%s OAuth authentication policy denial is audited before signing', async (
    _name,
    mutate,
    code,
  ) => {
    mutate();
    await expectDenied(sign(), 403, code);
  });

  test('expired and over-300-second OAuth tokens are audited before signing', async () => {
    token.expiresAt = new Date(Date.now() - 1);
    await expectDenied(sign(), 401, 'token_expired');

    decisions = [];
    token.expiresAt = new Date(Date.now() + 60_000);
    token.createdAt = new Date(Date.now() - 300_001);
    await expectDenied(sign(), 401, 'token_too_old');
  });

  test('malformed JSON and every missing OAuth request field are audited without signing', async () => {
    await expectDenied(sign('{'), 400, 'malformed_json');
    for (const field of ['address', 'chainId', 'message', 'type', 'purpose', 'keyId']) {
      decisions = [];
      const body: any = signingBody();
      delete body[field];
      await expectDenied(sign(body), 400, 'missing_field');
    }
  });

  test('invalid non-multibase did:key URI is audited once and never signed', async () => {
    const body = signingBody();
    body.message = body.message.replace(
      /^URI: .*$/m,
      'URI: did:key:not_multibase#not_multibase',
    );
    await expectDenied(sign(body), 403, 'siwe_uri_mismatch');
  });

  test('signer failure consumes the grant and appends ERROR audit evidence', async () => {
    signerFailure = true;
    const response = await sign();
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({
      approved: false,
      needsApproval: false,
      code: 'signer_failed',
    });
    expect(signerCalls).toBe(1);
    expect(grants).toHaveLength(1);
    expect(decisions.map((decision) => [decision.decision, decision.reasonCode])).toEqual([
      ['ALLOW', 'allow'],
      ['ERROR', 'signer_failed'],
    ]);
    expect(JSON.stringify(decisions)).not.toContain(rawBearer);

    signerFailure = false;
    const reuse = await sign();
    expect(reuse.status).toBe(409);
    expect(await reuse.json()).toMatchObject({ code: 'token_consumed', needsApproval: false });
    expect(signerCalls).toBe(1);
  });

  test('audit-write failure closes the request without signing', async () => {
    auditFailure = true;
    const body = signingBody();
    body.purpose = 'other';
    const response = await sign(body);
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({
      approved: false,
      needsApproval: false,
      code: 'audit_write_failed',
    });
    expect(decisions).toHaveLength(0);
    expect(grants).toHaveLength(0);
    expect(signerCalls).toBe(0);
  });

  test('OAuth configuration off still allows a real Better Auth session through bootstrap policy', async () => {
    delete process.env.OPENKEY_COORDINATIONOS_OAUTH_CLIENT_ID;
    delete process.env.OPENKEY_COORDINATIONOS_ORIGIN;
    betterAuthSession = true;
    const response = await sign(bootstrapSigningBody(), 'Bearer better_auth_session_token');
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      approved: true,
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
    });
    expect(decisions).toHaveLength(0);
    expect(signerCalls).toBe(1);
  });

  test('the complete stable-code status map matches the contract', () => {
    expect(Object.entries(COORDINATIONOS_DENIAL_STATUS).filter(([, status]) => status === 400).map(([code]) => code))
      .toEqual(['malformed_json', 'missing_field', 'invalid_siwe', 'invalid_nonce']);
    expect(Object.keys(COORDINATIONOS_DENIAL_STATUS)).toHaveLength(40);
    expect(COORDINATIONOS_DENIAL_STATUS.token_consumed).toBe(409);
    expect(COORDINATIONOS_DENIAL_STATUS.signer_failed).toBe(500);
  });
});
