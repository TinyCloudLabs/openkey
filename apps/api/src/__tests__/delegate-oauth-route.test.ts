import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  COORDINATIONOS_DENIAL_STATUS,
} from '../services/coordinationos-signing-audit';
import { coordinationosUserNamespace } from '../services/coordinationos-session-policy';

process.env.OPENKEY_COORDINATIONOS_OAUTH_CLIENT_ID = 'coordinationos-client';
process.env.OPENKEY_COORDINATIONOS_ORIGIN = 'https://coordination.example';

const rawBearer = 'opaque_OpenKey_token_123';
const tokenHash = createHash('sha256').update(rawBearer).digest('base64url');
const tokenAudit = createHash('sha256').update(rawBearer).digest('hex');
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const now = new Date();
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
  clientId: 'coordinationos-client',
  userId: 'user_1',
  scopes: ['openid', 'email', 'keys', 'tinycloud:session'],
  createdAt: new Date(now.getTime() - 1_000),
  expiresAt: new Date(now.getTime() + 299_000),
};
const client = {
  clientId: 'coordinationos-client',
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

const prisma: any = {
  oauthAccessToken: {
    findUnique: mock(async ({ where }: any) => where.token === tokenHash ? token : null),
  },
  oauthClient: {
    findUnique: mock(async () => client),
  },
  user: {
    findUnique: mock(async () => ({ id: 'user_1', emailVerified: true })),
  },
  ethereumKey: {
    findUnique: mock(async ({ where }: any) => where.id === key.id ? key : null),
    findFirst: mock(async () => key),
  },
  coordinationosSigningDecision: {
    create: mock(async ({ data }: any) => {
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
  $transaction: mock(async (callback: (tx: any) => Promise<unknown>) => {
    const decisionLength = decisions.length;
    const grantLength = grants.length;
    try {
      return await callback(prisma);
    } catch (error) {
      decisions.splice(decisionLength);
      grants.splice(grantLength);
      throw error;
    }
  }),
};

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
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
        return wallet.signMessage(input);
      },
    };
  },
  generatePrivateKey: () => privateKey,
  getAddressFromPrivateKey: () => address,
}));
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c) => c.json({ error: 'Unauthorized' }, 401)),
}));

let router: typeof import('../routes/delegate')['delegateRouter'];

beforeAll(async () => {
  ({ delegateRouter: router } = await import('../routes/delegate?coordinationos-oauth-route-isolated' as string));
});

afterAll(() => {
  mock.restore();
});

beforeEach(() => {
  decisions = [];
  grants = [];
  signerCalls = 0;
  token.createdAt = new Date(Date.now() - 1_000);
  token.expiresAt = new Date(Date.now() + 299_000);
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

function sign(body: unknown = signingBody(), authorization = `Bearer ${rawBearer}`) {
  return router.request('/sign', {
    method: 'POST',
    headers: {
      authorization,
      origin: 'https://coordination.example',
      'content-type': 'application/json',
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
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
  });

  test('one token signs once across sequential and concurrent reuse', async () => {
    const first = await sign();
    const second = await sign();
    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({ code: 'token_consumed', needsApproval: false });
    expect(signerCalls).toBe(1);

    decisions = [];
    grants = [];
    signerCalls = 0;
    const responses = await Promise.all([sign(), sign()]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
    expect(signerCalls).toBe(1);
  });

  test('OAuth transport and authentication denials are audited before signing', async () => {
    const malformed = await sign('{');
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({ code: 'malformed_json', needsApproval: false });
    expect(decisions).toHaveLength(1);
    expect(signerCalls).toBe(0);

    decisions = [];
    const missing = await router.request('/sign', {
      method: 'POST',
      headers: { origin: 'https://coordination.example', 'content-type': 'application/json' },
      body: JSON.stringify(signingBody()),
    });
    expect(missing.status).toBe(401);
    expect(await missing.json()).toMatchObject({ code: 'missing_authorization' });
    expect(decisions).toHaveLength(1);
    expect(signerCalls).toBe(0);
  });

  test('each missing OAuth request field is audited without signing', async () => {
    for (const field of ['address', 'chainId', 'message', 'type', 'purpose', 'keyId']) {
      decisions = [];
      const body: any = signingBody();
      delete body[field];
      const response = await sign(body);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ code: 'missing_field' });
      expect(decisions).toHaveLength(1);
      expect(signerCalls).toBe(0);
    }
  });

  test('the complete stable-code status map matches the contract', () => {
    expect(Object.entries(COORDINATIONOS_DENIAL_STATUS).filter(([, status]) => status === 400).map(([code]) => code))
      .toEqual(['malformed_json', 'missing_field', 'invalid_siwe', 'invalid_nonce']);
    expect(Object.keys(COORDINATIONOS_DENIAL_STATUS)).toHaveLength(40);
    expect(COORDINATIONOS_DENIAL_STATUS.token_consumed).toBe(409);
    expect(COORDINATIONOS_DENIAL_STATUS.signer_failed).toBe(500);
  });
});
