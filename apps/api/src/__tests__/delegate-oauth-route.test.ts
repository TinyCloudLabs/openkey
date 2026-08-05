import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
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
import {
  coordinationosCanaryPath,
  coordinationosInviteCodePath,
  coordinationosUserNamespace,
} from '../services/coordinationos-session-policy';

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
  tinycloudSessionPolicy: 'coordinationos-kv-v1' as string | null,
  tinycloudSessionOrigin: configuredOrigin as string | null,
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
let autoSignEnabled = true;
let transactionTail: Promise<void> = Promise.resolve();
let resolvedOauthUser: { id: string; emailVerified: boolean } | null = {
  id: 'user_1',
  emailVerified: true,
};
let resolvedKey: any = { ...key };

const prisma: any = {
  oauthAccessToken: {
    findUnique: mock(async ({ where }: any) => where.token === tokenHash ? token : null),
  },
  oauthClient: {
    findUnique: mock(async () => client),
  },
  user: {
    findUnique: mock(async ({ select }: any) => select?.autoSignEnabled
      ? { autoSignEnabled }
      : resolvedOauthUser),
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

afterEach(() => {
  for (const decision of decisions) {
    expect(decision.requestId).toMatch(serverRequestIdPattern);
    expect(decision.evidence.requestId).toBe(decision.requestId);
  }
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
  autoSignEnabled = true;
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
  client.mode = 'PERSONAL';
  client.type = 'web';
  client.public = false;
  client.tokenEndpointAuthMethod = 'client_secret_basic';
  client.grantTypes = ['authorization_code'];
  client.responseTypes = ['code'];
  client.scopes = ['openid', 'email', 'keys', 'tinycloud:session'];
  client.tinycloudSessionPolicy = 'coordinationos-kv-v1';
  client.tinycloudSessionOrigin = configuredOrigin;
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

function withRecapCaveat(
  body: ReturnType<typeof signingBody>,
  caveat: Record<string, unknown>,
) {
  const encoded = /- urn:recap:([A-Za-z0-9_-]+)/.exec(body.message)?.[1];
  if (!encoded) throw new Error('fixture does not contain a ReCap resource');
  const recap = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as {
    att: Record<string, Record<string, unknown[]>>;
  };
  for (const abilities of Object.values(recap.att)) {
    for (const ability of Object.keys(abilities)) {
      abilities[ability] = [{ caveats: [caveat] }];
    }
  }
  const mutated = Buffer.from(JSON.stringify(recap), 'utf8').toString('base64url');
  return {
    ...body,
    message: body.message.replace(`urn:recap:${encoded}`, `urn:recap:${mutated}`),
  };
}

function withSqlAndCanaryRecaps(
  body: ReturnType<typeof signingBody>,
  sqlFirst: boolean,
) {
  const canaryResource = /^- urn:recap:[A-Za-z0-9_-]+$/m.exec(body.message)?.[0];
  const current = new Date();
  const sqlMessage = prepareSession({
    address,
    chainId: 1,
    domain: 'coordination.example',
    issuedAt: current.toISOString(),
    expirationTime: new Date(current.getTime() + 3_600_000).toISOString(),
    spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: {
      sql: {
        '': ['tinycloud.sql/read', 'tinycloud.sql/write'],
      },
    },
  }).siwe;
  const sqlResource = /^- urn:recap:[A-Za-z0-9_-]+$/m.exec(sqlMessage)?.[0];
  if (!canaryResource || !sqlResource) throw new Error('fixture does not contain a ReCap resource');
  const resources = sqlFirst
    ? `${sqlResource}\n${canaryResource}`
    : `${canaryResource}\n${sqlResource}`;
  return {
    ...body,
    message: body.message.replace(canaryResource, resources),
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

test('tinycloud:manage-key silently signs a canonical TinyCloud SIWE/ReCap through the public signer route', async () => {
  token.scopes = ['openid', 'keys', 'tinycloud:manage-key'];
  client.scopes = ['openid', 'keys', 'tinycloud:manage-key'];
  const body = signingBody();
  // The route must not use either caller-controlled selector.
  body.address = '0x0000000000000000000000000000000000000000';
  body.keyId = 'attacker-selected-key';

  const response = await sign(body);
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    approved: true,
    signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
    canonicalIdentity: {
      version: 'v1',
      keyId: key.id,
      address,
      chainId: 1,
      did: `did:pkh:eip155:1:${address}`,
      spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
    },
  });
  expect(signerCalls).toBe(1);
  expect(decisions).toHaveLength(0);
});

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

function expectDigestOnlyDenialEvidence(body?: unknown) {
  expect(decisions).toHaveLength(1);
  expect(bootstrapCalls).toHaveLength(0);
  expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
  expect(signerCalls).toBe(0);

  const serialized = JSON.stringify(decisions);
  expect(serialized).not.toContain(rawBearer);
  expect(serialized).not.toContain(tokenHash);
  expect(serialized).not.toContain('alice@example.test');
  expect(serialized).not.toContain(key.sealedBlob);
  if (body && typeof body === 'object' && 'message' in body) {
    const message = (body as { message?: unknown }).message;
    if (typeof message === 'string') expect(serialized).not.toContain(message);
  }

  const evidence = decisions[0].evidence;
  for (const digest of [
    evidence.tokenDigest,
    evidence.siweDigest,
    evidence.capabilityDigest,
    evidence.nonceDigest,
  ]) {
    if (digest !== null) expect(digest).toMatch(/^[0-9a-f]{64}$/);
  }
}

async function expectRouteDenial(
  body: unknown,
  status: number,
  code: string,
  authorization: string | null = `Bearer ${rawBearer}`,
  headers: Record<string, string> = {},
) {
  await expectDenied(sign(body, authorization, headers), status, code);
  expectDigestOnlyDenialEvidence(body);
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

  test('signs an exact canary plus private invite-code session once', async () => {
    const response = await sign(signingBody({
      abilities: {
        kv: {
          [coordinationosCanaryPath(key.id)]: [
            'tinycloud.kv/get',
            'tinycloud.kv/put',
          ],
          [coordinationosInviteCodePath(key.id)]: [
            'tinycloud.kv/get',
            'tinycloud.kv/put',
          ],
        },
      },
    }));

    expect(response.status).toBe(200);
    expect(signerCalls).toBe(1);
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({ decision: 'ALLOW', reasonCode: 'allow' });
    expect(grants).toHaveLength(1);
  });

  test('untrusted request ID cannot persist the raw bearer in audit evidence', async () => {
    const response = await sign(signingBody(), `Bearer ${rawBearer}`, {
      'x-request-id': rawBearer,
    });

    expect(response.status).toBe(200);
    expect(decisions).toHaveLength(1);
    expect(decisions[0].requestId).toMatch(serverRequestIdPattern);
    expect(decisions[0].requestId).not.toBe(rawBearer);
    expect(decisions[0].evidence.requestId).toBe(decisions[0].requestId);
    expect(decisions[0].tokenDigest).toBe(tokenAudit);
    expect(decisions[0].evidence.tokenDigest).toBe(tokenAudit);
    expect(decisions[0].tokenDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(decisions)).not.toContain(rawBearer);
  });

  test('fresh managed PERSONAL key bootstraps before exactly one signer call', async () => {
    bootstrapMode = 'fresh';
    autoSignEnabled = false;
    const response = await sign();

    expect(response.status).toBe(200);
    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toMatchObject({
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
    expect(await bootstrapCalls[0].prisma.user.findUnique()).toEqual({ autoSignEnabled: true });
    expect(bootstrapCalls[0].prisma.tinyCloudBootstrapState).toBe(
      prisma.tinyCloudBootstrapState,
    );
    expect(bootstrapCalls[0].message).toContain(
      `tinycloud:pkh:eip155:1:${address}:account`,
    );
    expect(executionOrder).toEqual(['bootstrap:fresh', 'sign']);
    expect(signerCalls).toBe(1);
  });

  test('cached bootstrap remains idempotent and still signs exactly once', async () => {
    bootstrapMode = 'cached';
    autoSignEnabled = false;
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
    expect(decisions[0].requestId).toMatch(serverRequestIdPattern);
    expect(decisions[1].requestId).toBe(decisions[0].requestId);
    expect(decisions[0].evidence.requestId).toBe(decisions[0].requestId);
    expect(decisions[1].evidence.requestId).toBe(decisions[0].requestId);

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
    const body = signingBody();
    await expectRouteDenial(body, 401, code, authorization);
  });

  test('an OAuth bearer never falls back to a first-party session', async () => {
    betterAuthSession = true;
    await expectRouteDenial(
      bootstrapSigningBody(),
      401,
      'unknown_token',
      'Bearer unknownOpaqueBearer123',
    );
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
    ['missing client session policy', () => {
      client.tinycloudSessionPolicy = null;
      client.tinycloudSessionOrigin = null;
    }, 'client_misconfigured'],
    ['unknown client session policy', () => {
      client.tinycloudSessionPolicy = 'unknown-policy';
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
    const body = signingBody();
    await expectRouteDenial(body, 403, code);
  });

  test('expired and over-300-second OAuth tokens are audited before signing', async () => {
    const expiredBody = signingBody();
    token.expiresAt = new Date(Date.now() - 1);
    await expectRouteDenial(expiredBody, 401, 'token_expired');

    decisions = [];
    token.expiresAt = new Date(Date.now() + 60_000);
    token.createdAt = new Date(Date.now() - 300_001);
    const oldBody = signingBody();
    await expectRouteDenial(oldBody, 401, 'token_too_old');
  });

  test('malformed JSON and every missing OAuth request field are audited without signing', async () => {
    await expectRouteDenial('{', 400, 'malformed_json');
    for (const field of ['address', 'chainId', 'message', 'type', 'purpose', 'keyId']) {
      decisions = [];
      const body: any = signingBody();
      delete body[field];
      await expectRouteDenial(body, 400, 'missing_field');
    }
  });

  test('OAuth transport and authentication denials are audited before signing', async () => {
    const cases: Array<{
      body: unknown;
      status: number;
      code: string;
      authorization?: string | null;
    }> = [
      { body: '{', status: 400, code: 'malformed_json' },
      ...['address', 'chainId', 'message', 'type', 'purpose', 'keyId'].map((field) => {
        const body: any = signingBody();
        delete body[field];
        return { body, status: 400, code: 'missing_field' };
      }),
      {
        body: signingBody(),
        status: 401,
        code: 'missing_authorization',
        authorization: null,
      },
      {
        body: signingBody(),
        status: 401,
        code: 'malformed_authorization',
        authorization: 'Basic opaque',
      },
      {
        body: signingBody(),
        status: 401,
        code: 'multiple_authorization',
        authorization: `Bearer ${rawBearer}, Bearer second`,
      },
      {
        body: signingBody(),
        status: 401,
        code: 'unknown_token',
        authorization: 'Bearer unknownOpaqueBearer123',
      },
    ];

    for (const testCase of cases) {
      decisions = [];
      grants = [];
      signerCalls = 0;
      bootstrapCalls = [];
      ensureTinyCloudBootstrapForApprovedSign.mockClear();
      await expectRouteDenial(
        testCase.body,
        testCase.status,
        testCase.code,
        testCase.authorization,
      );
    }
  });

  test('invalid non-multibase did:key URI is audited once and never signed', async () => {
    const body = signingBody();
    body.message = body.message.replace(
      /^URI: .*$/m,
      'URI: did:key:not_multibase#not_multibase',
    );
    await expectRouteDenial(body, 403, 'siwe_uri_mismatch');
  });

  test('a real ReCap with caveats [{}] is denied before bootstrap or signing', async () => {
    const body = withRecapCaveat(signingBody(), {});
    await expectRouteDenial(
      body,
      403,
      'capability_escalation',
    );
    expect(bootstrapCalls).toHaveLength(0);
    expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
  });

  test.each([
    ['SQL ReCap first', true],
    ['canary ReCap first', false],
  ])('%s among multiple ReCap resources is audited once without bootstrap or signing', async (
    _name,
    sqlFirst,
  ) => {
    const body = withSqlAndCanaryRecaps(signingBody(), sqlFirst);
    await expectRouteDenial(
      body,
      403,
      'capability_escalation',
    );
    expect(decisions).toHaveLength(1);
    expect(decisions[0]).toMatchObject({
      decision: 'DENY',
      reasonCode: 'capability_escalation',
    });
    expect(bootstrapCalls).toHaveLength(0);
    expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
    expect(signerCalls).toBe(0);
  });

  test.each([
    ['missing key', () => { resolvedKey = null; }, 'key_not_found'],
    ['other-user key', () => { resolvedKey.userId = 'user_2'; }, 'wrong_user'],
    ['non-personal key', () => {
      resolvedKey.keyPurpose = 'MANAGED_ACCOUNT';
    }, 'wrong_key_purpose'],
    ['external key', () => { resolvedKey.keyType = 'EXTERNAL'; }, 'external_key_denied'],
    ['archived key', () => { resolvedKey.archivedAt = new Date(); }, 'key_archived'],
    ['address-mismatched key', () => {
      resolvedKey.address = '0x1111111111111111111111111111111111111111';
    }, 'key_address_mismatch'],
    ['unsealed key', () => { resolvedKey.sealedBlob = null; }, 'key_unavailable'],
  ])('%s route denial records digest-only evidence without bootstrap or signing', async (
    _name,
    mutate,
    code,
  ) => {
    mutate();
    const body = signingBody();
    await expectRouteDenial(body, 403, code);
  });

  test.each([
    ['missing origin', () => signingBody(), { origin: '' }, 403, 'missing_origin'],
    ['wrong origin', () => signingBody(), { origin: 'https://evil.example' }, 403, 'wrong_origin'],
    ['SIWE domain mismatch', () => signingBody({
      domain: 'evil.example',
    }), {}, 403, 'siwe_domain_mismatch'],
    ['wrong request chain', () => signingBody({
      requestChainId: 137,
    }), {}, 403, 'wrong_chain'],
    ['SIWE chain mismatch', () => signingBody({
      siweChainId: 137,
    }), {}, 403, 'chain_mismatch'],
    ['ReCap space chain mismatch', () => signingBody({
      spaceId: `tinycloud:pkh:eip155:137:${address}:applications`,
    }), {}, 403, 'chain_mismatch'],
    ['wrong signing type', () => signingBody({
      type: 'message',
    }), {}, 403, 'wrong_type'],
    ['wrong signing purpose', () => signingBody({
      purpose: 'bootstrap-session',
    }), {}, 403, 'wrong_purpose'],
    ['malformed SIWE', () => ({
      ...signingBody(),
      message: 'not siwe',
    }), {}, 400, 'invalid_siwe'],
    ['wrong canary capability', () => signingBody({
      abilities: {
        kv: {
          'coordinationos/integration/v1/wrong/canary': [
            'tinycloud.kv/get',
            'tinycloud.kv/put',
          ],
        },
      },
    }), {}, 403, 'wrong_capability'],
    ['capability escalation', () => signingBody({
      abilities: {
        kv: {
          [`coordinationos/integration/v1/${coordinationosUserNamespace(key.id)}/canary`]: [
            'tinycloud.kv/get',
            'tinycloud.kv/put',
            'tinycloud.kv/delete',
          ],
        },
      },
    }), {}, 403, 'capability_escalation'],
    ['invalid nonce', () => {
      const body = signingBody();
      body.message = body.message.replace(/^Nonce: .*$/m, 'Nonce: short');
      return body;
    }, {}, 400, 'invalid_nonce'],
    ['future issued-at', () => {
      const current = Date.now();
      return signingBody({
        issuedAt: new Date(current + 61_000).toISOString(),
        expirationTime: new Date(current + 3_600_000).toISOString(),
      });
    }, {}, 403, 'issued_at_invalid'],
    ['expired session', () => {
      const current = Date.now();
      return signingBody({
        issuedAt: new Date(current - 30_000).toISOString(),
        expirationTime: new Date(current - 1_000).toISOString(),
      });
    }, {}, 403, 'session_expired'],
    ['session TTL exceeded', () => {
      const current = Date.now();
      return signingBody({
        issuedAt: new Date(current).toISOString(),
        expirationTime: new Date(current + 3_601_000).toISOString(),
      });
    }, {}, 403, 'session_ttl_exceeded'],
  ])('%s policy dimension is denied at the route with one digest-only audit row', async (
    _name,
    makeBody,
    headers,
    status,
    code,
  ) => {
    const body = makeBody();
    await expectRouteDenial(body, status, code, `Bearer ${rawBearer}`, headers);
  });

  test.each([
    ['token reuse', 'token_consumed', (body: ReturnType<typeof signingBody>) => {
      grants.push({
        oauthAccessTokenId: token.id,
        nonceDigest: 'f'.repeat(64),
      });
    }],
    ['nonce replay', 'nonce_replayed', (body: ReturnType<typeof signingBody>) => {
      const nonce = /^Nonce: (.*)$/m.exec(body.message)?.[1];
      if (!nonce) throw new Error('fixture nonce missing');
      grants.push({
        oauthAccessTokenId: 'another_token',
        nonceDigest: createHash('sha256').update(nonce).digest('hex'),
      });
    }],
  ])('%s is denied at the route with one DENY row and no bootstrap or signer calls', async (
    _name,
    code,
    arrange,
  ) => {
    const body = signingBody();
    arrange(body);
    await expectRouteDenial(body, 409, code);
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
    expect(decisions[0].requestId).toMatch(serverRequestIdPattern);
    expect(decisions[1].requestId).toBe(decisions[0].requestId);
    expect(decisions[0].evidence.requestId).toBe(decisions[0].requestId);
    expect(decisions[1].evidence.requestId).toBe(decisions[0].requestId);
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

  test('an OAuth client policy does not affect a real Better Auth session bootstrap', async () => {
    betterAuthSession = true;
    const response = await sign(bootstrapSigningBody(), null);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      approved: true,
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
    });
    expect(decisions).toHaveLength(0);
    expect(signerCalls).toBe(1);
  });

  test('matching OAuth bearer is denied when its stored TinyCloud policy is unset', async () => {
    client.tinycloudSessionPolicy = null;
    client.tinycloudSessionOrigin = null;
    const body = signingBody();

    await expectRouteDenial(body, 403, 'client_misconfigured');
  });

  test('Better Auth session signing still honors disabled Auto-Sign', async () => {
    betterAuthSession = true;
    autoSignEnabled = false;
    const response = await sign(bootstrapSigningBody(), null);
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      approved: false,
      needsApproval: true,
      code: 'auto_sign_disabled',
    });
    expect(decisions).toHaveLength(0);
    expect(bootstrapCalls).toHaveLength(0);
    expect(signerCalls).toBe(0);
  });

  test('the complete stable-code status map matches the contract', () => {
    expect(COORDINATIONOS_DENIAL_STATUS).toEqual({
      malformed_json: 400,
      missing_field: 400,
      invalid_siwe: 400,
      invalid_nonce: 400,
      missing_authorization: 401,
      malformed_authorization: 401,
      multiple_authorization: 401,
      unknown_token: 401,
      token_expired: 401,
      token_too_old: 401,
      wrong_client: 403,
      client_disabled: 403,
      client_misconfigured: 403,
      missing_scope: 403,
      user_not_found: 403,
      email_not_verified: 403,
      key_not_found: 403,
      wrong_user: 403,
      wrong_key_purpose: 403,
      external_key_denied: 403,
      key_archived: 403,
      key_address_mismatch: 403,
      key_unavailable: 403,
      missing_origin: 403,
      wrong_origin: 403,
      siwe_domain_mismatch: 403,
      wrong_chain: 403,
      chain_mismatch: 403,
      wrong_type: 403,
      wrong_purpose: 403,
      siwe_uri_mismatch: 403,
      wrong_capability: 403,
      capability_escalation: 403,
      issued_at_invalid: 403,
      session_expired: 403,
      session_ttl_exceeded: 403,
      nonce_replayed: 409,
      token_consumed: 409,
      audit_write_failed: 500,
      signer_failed: 500,
    });
  });
});
