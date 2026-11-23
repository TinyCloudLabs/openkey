// TC-3810 (passive OpenKey parser): route-level tests for /authorize-sign
// (narrowing, mode-drop/flip refusal) and the device-window /complete path.
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { verifyMessage } from 'ethers';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import * as signing from '../services/authorization-signing';
import * as realNarrowing from '../services/siwe-narrow';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from '../services/device-authorization';
import {
  DELEGATION_MODE_KEY,
  SIGNED_SUBSET_REFUSAL_CODE,
  parseStrictSiwe,
  type DelegationMode,
} from '../services/signed-subset';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
const managed = {
  id: 'managed_1',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

let narrowModeFault: 'drop' | 'flip' | null = null;

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => managed),
    findMany: mock(async () => [managed]),
    findUnique: mock(async () => managed),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

const narrow = realNarrowing.narrowSiwePreservingImmutable;
const unseal = mock(async () => privateKey);
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));
const activateSessionWithHost = mock(async () => ({ success: true }));
const deviceService = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
  verificationOrigin: 'https://openkey.so',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
});

function rewriteRecapMode(siwe: string, mode: DelegationMode | undefined): string {
  const line = siwe.split('\n').find((l) => l.startsWith('- urn:recap:'))!;
  const parsed = JSON.parse(Buffer.from(line.slice('- urn:recap:'.length), 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  const next: Record<string, unknown> = { att: parsed.att, prf: parsed.prf };
  if (mode !== undefined) next[DELEGATION_MODE_KEY] = mode;
  return siwe.replace(line, `- urn:recap:${Buffer.from(JSON.stringify(next), 'utf8').toString('base64url')}`);
}

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  '../routes/device-authorization': () => ({ deviceAuthorizationService: deviceService }),
});
await mockModules({
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrap: mock(async () => ({ status: 'complete' as const })),
  }),
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal,
    createWalletFromPrivateKey: () => ({
      signMessage: ({ message }: { message: string }) => signManagedMessage(message),
    }),
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
  '../services/siwe-narrow': () => ({
    narrowSiwePreservingImmutable: (input: Parameters<typeof narrow>[0]) => {
      const result = narrow(input);
      if (!result.ok || narrowModeFault === null) return result;
      if (narrowModeFault === 'drop') {
        return { ...result, siwe: rewriteRecapMode(result.siwe, undefined) };
      }
      return { ...result, siwe: rewriteRecapMode(result.siwe, 'attenuable') };
    },
  }),
});

let router: typeof delegateRouter;
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?delegation-mode-routes-isolated' as string
  ));
  setSignerAuth(
    createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
      c.set('delegateSignerOauthContext', null);
      c.set('delegateSignerAuthFailure', null);
      await next();
    }),
  );
});

beforeEach(() => {
  signing._resetAuthorizationContextStoreForTests();
  narrowModeFault = null;
  unseal.mockClear();
  signManagedMessage.mockClear();
  activateSessionWithHost.mockClear();
});

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

function makeSiwe(mode?: DelegationMode): string {
  const now = Date.now();
  const base = prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'openkey.so',
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + 3_600_000).toISOString(),
    spaceId: space,
    jwk,
    abilities: {
      kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      capabilities: { [space]: ['tinycloud.capabilities/read'] },
    } as unknown as Parameters<typeof prepareSession>[0]['abilities'],
  }).siwe as string;
  return mode === undefined ? base : rewriteRecapMode(base, mode);
}

describe('/authorize-sign routes with xyz.tinycloud.policy/delegationMode', () => {
  test('narrowing a terminal request through prepare -> preview -> sign preserves mode and signs', async () => {
    const siwe = makeSiwe('terminal');
    const prepared = await post('/authorize-sign-prepare', {
      keyId: managed.id,
      siwe,
      jwk,
      host,
      requestOrigin: 'https://openkey.so',
    });
    expect(prepared.status).toBe(200);
    const allowed = prepared.body.allowedActionIds as string[];
    const selected = allowed.filter((id) => !id.includes('kv/put'));
    expect(selected.length).toBe(allowed.length - 1);
    const contextToken = prepared.body.authorizationContextToken as string;

    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken: contextToken,
      selectedActionIds: selected,
    });
    expect(preview.status).toBe(200);
    const previewBytes = preview.body.signedMessage as string;
    const previewParsed = parseStrictSiwe(previewBytes);
    expect(previewParsed.ok).toBe(true);
    if (!previewParsed.ok) return;
    expect(previewParsed.siwe.recap?.delegationMode).toBe('terminal');

    const signed = await post('/authorize-sign', {
      authorizationContextToken: contextToken,
      previewApprovalToken: preview.body.previewApprovalToken,
      selectedActionIds: selected,
      protocolVersion: 1,
    });
    expect(signed.status).toBe(200);
    expect(signed.body.signedMessage).toBe(previewBytes);
    const signedParsed = parseStrictSiwe(signed.body.signedMessage as string);
    expect(signedParsed.ok).toBe(true);
    if (!signedParsed.ok) return;
    expect(signedParsed.siwe.recap?.delegationMode).toBe('terminal');
    expect(
      verifyMessage(signed.body.signedMessage as string, signed.body.signature as string).toLowerCase(),
    ).toBe(account.address.toLowerCase());
    expect(signManagedMessage).toHaveBeenCalledTimes(1);
  });

  for (const fault of ['drop', 'flip'] as const) {
    test(`refuses with delegation_mode when narrowing ${fault}s the mode at preview and at sign`, async () => {
      const siwe = makeSiwe('terminal');
      const prepared = await post('/authorize-sign-prepare', {
        keyId: managed.id,
        siwe,
        jwk,
        host,
        requestOrigin: 'https://openkey.so',
      });
      expect(prepared.status).toBe(200);
      const allowed = prepared.body.allowedActionIds as string[];
      const selected = allowed.filter((id) => !id.includes('kv/put'));
      const contextToken = prepared.body.authorizationContextToken as string;

      // Preview refuses if regenerated bytes drop or flip the mode.
      narrowModeFault = fault;
      const refusedPreview = await post('/authorize-sign-preview', {
        authorizationContextToken: contextToken,
        selectedActionIds: selected,
      });
      expect(refusedPreview.status).toBe(400);
      expect(refusedPreview.body).toMatchObject({
        code: SIGNED_SUBSET_REFUSAL_CODE,
        reason: 'delegation_mode',
      });

      // With a clean preview, /authorize-sign still refuses before signing if its
      // regenerated candidate drops or flips the mode.
      narrowModeFault = null;
      const preview = await post('/authorize-sign-preview', {
        authorizationContextToken: contextToken,
        selectedActionIds: selected,
      });
      expect(preview.status).toBe(200);

      narrowModeFault = fault;
      const refusedSign = await post('/authorize-sign', {
        authorizationContextToken: contextToken,
        previewApprovalToken: preview.body.previewApprovalToken,
        selectedActionIds: selected,
        protocolVersion: 1,
      });
      expect(refusedSign.status).toBe(400);
      expect(refusedSign.body).toMatchObject({
        code: SIGNED_SUBSET_REFUSAL_CODE,
        reason: 'delegation_mode',
      });
      expect(unseal).not.toHaveBeenCalled();
      expect(signManagedMessage).not.toHaveBeenCalled();
    });
  }
});

describe('device-window /complete route checks delegationMode against the device reference', () => {
  const devicePermissions = [
    { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
  ];

  async function startDeviceTransaction(): Promise<string> {
    const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
    const started = await deviceService.start(
      {
        deviceSecretHash: digest(`secret-${Math.random()}`),
        codeChallenge: digest(`verifier-${Math.random()}`),
        sessionDid: sessionDidForPublicJwk(jwk),
        publicJwk: jwk,
        relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
          format: 'jwk',
        }) as Record<string, unknown>,
        permissions: devicePermissions,
        nodeOrigin: host,
        shareOrigin: 'https://share.tinycloud.xyz',
        delegationTtlSeconds: 60,
      },
      `198.51.100.${Math.floor(Math.random() * 250)}`,
    );
    return started.transactionId;
  }

  test('refuses /complete with delegation_mode when a signed device SIWE drops or flips the device terminal mode', async () => {
    const transactionId = await startDeviceTransaction();
    const prepared = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      deviceTransactionId: transactionId,
      permissions: devicePermissions,
    });
    expect(prepared.status).toBe(200);

    const preparedPayload = prepared.body.prepared as Record<string, unknown> & { siwe: string };
    for (const tamperedMode of [undefined, 'attenuable'] as const) {
      const tamperedSiwe = rewriteRecapMode(preparedPayload.siwe, tamperedMode);
      const signature = await account.signMessage({ message: tamperedSiwe });

      const refused = await post('/complete', {
        prepared: { ...preparedPayload, siwe: tamperedSiwe },
        signature,
        host,
        jwk,
        deviceTransactionId: transactionId,
      });
      expect(refused.status).toBe(400);
      expect(refused.body).toMatchObject({
        code: SIGNED_SUBSET_REFUSAL_CODE,
        reason: 'delegation_mode',
      });
    }
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    // Unmodified device SIWE (terminal) still completes normally.
    const validSignature = await account.signMessage({ message: preparedPayload.siwe });
    const accepted = await post('/complete', {
      prepared: preparedPayload,
      signature: validSignature,
      host,
      jwk,
      deviceTransactionId: transactionId,
    });
    expect(accepted.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });
});
