// TC-3810 (step 4 — OpenKey activation): route-level and service tests covering
// matrix §6 rows that apply to OpenKey:
//   - honor declarations ("terminal" | "attenuable"; unknown -> "terminal"; conflict refused);
//   - approve -> signed value;
//   - narrowing preserves mode (terminal and attenuable);
//   - changed or dropped mode is refused (authorize-sign, /complete, /a/, device);
//   - third-party flows mint terminal (/a/, device, auth request --grant, renewal lease);
//   - undeclared stays attenuable (legacy absent) and emits origin-only log line.
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { verifyMessage } from 'ethers';
import { privateKeyToAccount } from 'viem/accounts';
import { completeSessionSetup, prepareSession } from '@tinycloud/node-sdk-wasm';
import * as signing from '../services/authorization-signing';
import {
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
  strictSessionDid,
} from '../services/device-authorization';
import {
  ApprovalResultService,
  type ApprovalRequestRecord,
  type ApprovalRequestStore,
} from '../services/approval-results';
import { admitLease, prepareRenewalStage, signLease } from '../services/renewal-lease';
import {
  DELEGATION_MODE_KEY,
  SIGNED_SUBSET_REFUSAL_CODE,
  normalizeDeclaredDelegationMode,
  parseStrictSiwe,
  withRecapDelegationMode,
  type DelegationMode,
} from '../services/signed-subset';
import { logUndeclaredDelegationModeSignIn } from '../log';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_step4', email: 'step4-canary@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
const managed = {
  id: 'managed_step4',
  userId: user.id,
  address: account.address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => managed),
    findMany: mock(async () => [managed]),
    findUnique: mock(async () => managed),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

const unseal = mock(async () => privateKey);
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));
const activateSessionWithHost = mock(async () => ({ success: true }));

const deviceService = new DeviceAuthorizationService(new MemoryDeviceAuthorizationStore(), {
  verificationOrigin: 'https://openkey.so',
  encryptionSecret: 'test-device-authorization-secret-is-long-enough',
});

// In-memory store for /a/ approval requests so /api/delegate/prepare, / and /complete run end-to-end.
const approvalRecords = new Map<string, ApprovalRequestRecord>();
const approvalStore: ApprovalRequestStore = {
  async register(record) {
    approvalRecords.set(record.id, record);
    return record;
  },
  async findById(id) {
    return approvalRecords.get(id) ?? null;
  },
  async findByResultRef(ref) {
    return [...approvalRecords.values()].find((r) => r.resultRef === ref) ?? null;
  },
  async admit(id, now) {
    const rec = approvalRecords.get(id);
    if (!rec || rec.resultRef || rec.deniedAt || rec.expiresAt <= now) return null;
    rec.approvingAt = now;
    return now;
  },
  async release(id, marker) {
    const rec = approvalRecords.get(id);
    if (rec && rec.approvingAt?.getTime() === marker.getTime()) rec.approvingAt = null;
  },
  async approve(id, result) {
    const rec = approvalRecords.get(id);
    if (!rec || rec.resultRef) return false;
    Object.assign(rec, result, { approvingAt: null });
    return true;
  },
  async saveRenewal() {
    return true;
  },
  async acknowledge() {
    return null;
  },
  async deny() {
    return false;
  },
};
const approvalService = new ApprovalResultService(approvalStore, {
  apiOrigin: 'https://api.openkey.test',
  retentionSeconds: 600,
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
      c.set('session', { id: 'session_step4', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
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
});
await mockModules({
  '../routes/approval-requests': () => ({
    approvalResultService: () => approvalService,
    checkApprovalDelegation: async (body: { approvalRequestId?: unknown; jwk: unknown; host: unknown; permissions?: unknown }, input: { expiryMs?: number; signedSiwe?: string }) => {
      if (body.approvalRequestId === undefined) return;
      await approvalService.assertDelegationWindow(body.approvalRequestId, { ...body, permissions: body.permissions, ...input });
    },
    admitApprovalDelegation: async (body: { approvalRequestId?: unknown }) => {
      if (body.approvalRequestId === undefined) return;
      await approvalService.admit(String(body.approvalRequestId));
    },
    releaseApprovalDelegation: async () => undefined,
    bindApprovalRenewal: async () => undefined,
    checkApprovalLeaseGrant: () => undefined,
    confirmBoundRenewal: () => undefined,
    saveApprovalDelegation: async (body: { approvalRequestId?: unknown; jwk: unknown; host: unknown; permissions?: unknown }, userId: string, delegation: Record<string, unknown>) => {
      if (body.approvalRequestId === undefined) return delegation;
      const approvalCode = await approvalService.approve(String(body.approvalRequestId), userId, { ...body, permissions: body.permissions }, delegation);
      return { ...delegation, approvalCode };
    },
  }),
});

let router: typeof delegateRouter;
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?delegation-mode-step4-isolated' as string
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
  approvalRecords.clear();
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

function makeSiwe(mode?: DelegationMode, domain = 'outside.example.com'): string {
  const now = Date.now();
  const base = prepareSession({
    address: account.address,
    chainId: 1,
    domain,
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + 3_600_000).toISOString(),
    spaceId: space,
    jwk,
    abilities: {
      kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      capabilities: { [space]: ['tinycloud.capabilities/read'] },
    } as unknown as Parameters<typeof prepareSession>[0]['abilities'],
  }).siwe as string;
  return mode === undefined ? base : withRecapDelegationMode(base, mode);
}

async function captureStdout<T>(fn: () => Promise<T> | T): Promise<{ result: T; lines: Record<string, unknown>[] }> {
  const chunks: string[] = [];
  const orig = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  try {
    const result = await fn();
    const lines = chunks
      .join('')
      .split('\n')
      .filter((line) => line.startsWith('{'))
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    return { result, lines };
  } finally {
    process.stdout.write = orig;
  }
}

describe('TC-3810 step 4: honor declarations & preserve through narrowing', () => {
  test('normalizeDeclaredDelegationMode keeps undefined undeclared, accepts exact attenuable, and forces unknown to terminal', () => {
    expect(normalizeDeclaredDelegationMode(undefined)).toBeUndefined();
    expect(normalizeDeclaredDelegationMode('attenuable')).toBe('attenuable');
    expect(normalizeDeclaredDelegationMode('terminal')).toBe('terminal');
    for (const unknown of ['Attenuable', 'ATTENUABLE', '', 'delegate', null, 1, true, {}]) {
      expect(normalizeDeclaredDelegationMode(unknown)).toBe('terminal');
    }
  });

  for (const mode of ['attenuable', 'terminal'] as const) {
    test(`/authorize-sign honors ${mode} declared via request body (stamping into SIWE) and preserves it through narrowing`, async () => {
      const siwe = makeSiwe(undefined, 'outside.example.com');
      const { result: prepared, lines } = await captureStdout(() =>
        post('/authorize-sign-prepare', {
          keyId: managed.id,
          siwe,
          jwk,
          host,
          requestOrigin: 'https://outside.example.com',
          delegationMode: mode,
        }),
      );
      expect(prepared.status).toBe(200);
      expect(prepared.body.delegationMode).toBe(mode);
      // Declared requests must NOT emit undeclared_delegation_mode_signin.
      expect(lines.filter((l) => l.event === 'undeclared_delegation_mode_signin')).toHaveLength(0);

      const allowed = prepared.body.allowedActionIds as string[];
      const narrowed = allowed.filter((id) => !id.includes('kv/put'));
      const contextToken = prepared.body.authorizationContextToken as string;

      const preview = await post('/authorize-sign-preview', {
        authorizationContextToken: contextToken,
        selectedActionIds: narrowed,
      });
      expect(preview.status).toBe(200);
      const previewParsed = parseStrictSiwe(preview.body.signedMessage as string);
      expect(previewParsed.ok).toBe(true);
      if (!previewParsed.ok) return;
      expect(previewParsed.siwe.recap?.delegationMode).toBe(mode);

      const signed = await post('/authorize-sign', {
        authorizationContextToken: contextToken,
        previewApprovalToken: preview.body.previewApprovalToken,
        selectedActionIds: narrowed,
        protocolVersion: 1,
      });
      expect(signed.status).toBe(200);
      const signedParsed = parseStrictSiwe(signed.body.signedMessage as string);
      expect(signedParsed.ok).toBe(true);
      if (!signedParsed.ok) return;
      expect(signedParsed.siwe.recap?.delegationMode).toBe(mode);
      expect(
        verifyMessage(signed.body.signedMessage as string, signed.body.signature as string).toLowerCase(),
      ).toBe(account.address.toLowerCase());
    });
  }

  test('unknown request delegationMode normalizes to terminal (never attenuable) and conflicting SIWE mode is refused', async () => {
    const unknownRes = await post('/authorize-sign-prepare', {
      keyId: managed.id,
      siwe: makeSiwe(undefined, 'outside.example.com'),
      jwk,
      host,
      requestOrigin: 'https://outside.example.com',
      delegationMode: 'Attenuable',
    });
    expect(unknownRes.status).toBe(200);
    expect(unknownRes.body.delegationMode).toBe('terminal');

    const conflict = await post('/authorize-sign-prepare', {
      keyId: managed.id,
      siwe: makeSiwe('attenuable', 'outside.example.com'),
      jwk,
      host,
      requestOrigin: 'https://outside.example.com',
      delegationMode: 'terminal',
    });
    expect(conflict.status).toBe(400);
    expect(conflict.body).toMatchObject({
      code: SIGNED_SUBSET_REFUSAL_CODE,
      reason: 'delegation_mode',
    });
  });

  test('undeclared sign-in stays attenuable (no mode emitted) and logs origin-only undeclared_delegation_mode_signin', async () => {
    const siwe = makeSiwe(undefined, 'tinychat.xyz');
    const { result: prepared, lines } = await captureStdout(() =>
      post('/authorize-sign-prepare', {
        keyId: managed.id,
        siwe,
        jwk,
        host,
        requestOrigin: 'https://tinychat.xyz',
      }),
    );
    expect(prepared.status).toBe(200);
    expect(prepared.body.delegationMode).toBeUndefined();

    const undeclaredLines = lines.filter((l) => l.event === 'undeclared_delegation_mode_signin');
    expect(undeclaredLines).toHaveLength(1);
    const line = undeclaredLines[0]!;
    expect(Object.keys(line).sort()).toEqual(['event', 'level', 'origin', 'request_id', 'ts']);
    expect(line.origin).toBe('https://tinychat.xyz');
    const raw = JSON.stringify(line);
    for (const forbidden of [user.id, user.email, account.address, 'did:pkh:', 'tinycloud:', 'session_step4']) {
      expect(raw).not.toContain(forbidden);
    }

    const allowed = prepared.body.allowedActionIds as string[];
    const contextToken = prepared.body.authorizationContextToken as string;
    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken: contextToken,
      selectedActionIds: allowed,
    });
    expect(preview.status).toBe(200);
    expect(preview.body.signedMessage).toBe(siwe);
    const signed = await post('/authorize-sign', {
      authorizationContextToken: contextToken,
      previewApprovalToken: preview.body.previewApprovalToken,
      selectedActionIds: allowed,
      protocolVersion: 1,
    });
    expect(signed.status).toBe(200);
    expect(signed.body.signedMessage).toBe(siwe);
    const parsed = parseStrictSiwe(signed.body.signedMessage as string);
    expect(parsed.ok && parsed.siwe.recap?.delegationMode).toBeUndefined();
  });

  test('logUndeclaredDelegationModeSignIn sanitizes non-origin inputs to "unknown"', async () => {
    const { lines } = await captureStdout(() => {
      logUndeclaredDelegationModeSignIn('https://one.tinycloud.xyz');
      logUndeclaredDelegationModeSignIn('https://evil.example/path?token=secret-canary');
      logUndeclaredDelegationModeSignIn('did:pkh:eip155:1:0x1234567890123456789012345678901234567890');
      logUndeclaredDelegationModeSignIn(null);
    });
    expect(lines.map((l) => l.origin)).toEqual(['https://one.tinycloud.xyz', 'unknown', 'unknown', 'unknown']);
    const joined = JSON.stringify(lines);
    expect(joined).not.toContain('secret-canary');
    expect(joined).not.toContain('did:pkh:');
  });
});

describe('TC-3810 step 4: third-party flows mint terminal; plain /delegate honors declarations', () => {
  const perms = [
    { service: 'tinycloud.kv', space: 'default', path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
    { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
  ];

  async function registerApprovalRequest(id = 'aaaaaaaaaaaaaaaaaaaaaaaaaa'): Promise<string> {
    const relay = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const relayJwk = await crypto.subtle.exportKey('jwk', relay.publicKey);
    const did = strictSessionDid(jwk);
    await approvalStore.register({
      id,
      bodyCid: 'bafytestbodycid',
      issuer: did,
      request: {
        requestVersion: 1,
        issuer: did,
        targetDid: did,
        targetPublicJwk: jwk as any,
        nodeOrigin: host,
        permissions: perms,
        grantLifetimeSeconds: 3600,
        resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x!, y: relayJwk.y! },
      },
      expiresAt: new Date(Date.now() + 60_000),
      createdAt: new Date(),
      resultRef: null,
      encryptedResult: null,
      resultExpiresAt: null,
    });
    return id;
  }

  test('/a/ approval request honors terminal and attenuable, keeps undeclared omitted, and refuses mode tampering on /complete', async () => {
    const approvalRequestId = await registerApprovalRequest();

    // Undeclared /a/ (e.g. legacy CLI auth login / tc auth grant before step 5) stays omitted.
    const undeclared = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      approvalRequestId,
    });
    expect(undeclared.status).toBe(200);
    const parsedUndec = parseStrictSiwe((undeclared.body.prepared as { siwe: string }).siwe);
    expect(parsedUndec.ok && parsedUndec.siwe.recap?.delegationMode).toBeUndefined();

    // Declared attenuable /a/ (e.g. step-2 CLI auth login / auth grant) is honored, never refused.
    const attenuablePrep = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      approvalRequestId,
      delegationMode: 'attenuable',
    });
    expect(attenuablePrep.status).toBe(200);
    const parsedAtt = parseStrictSiwe((attenuablePrep.body.prepared as { siwe: string }).siwe);
    expect(parsedAtt.ok && parsedAtt.siwe.recap?.delegationMode).toBe('attenuable');

    // Declared terminal /a/ (e.g. step-2 tc auth request --grant) mints terminal.
    const prepared = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      approvalRequestId,
      delegationMode: 'terminal',
    });
    expect(prepared.status).toBe(200);
    const prepPayload = prepared.body.prepared as Record<string, unknown> & { siwe: string };
    const parsedPrep = parseStrictSiwe(prepPayload.siwe);
    expect(parsedPrep.ok).toBe(true);
    if (!parsedPrep.ok) return;
    expect(parsedPrep.siwe.recap?.delegationMode).toBe('terminal');

    // Dropping or flipping the bound mode on /complete is refused before activation.
    for (const tampered of [
      rewriteRecapMode(prepPayload.siwe, undefined),
      rewriteRecapMode(prepPayload.siwe, 'attenuable'),
    ]) {
      const sig = await account.signMessage({ message: tampered });
      const refused = await post('/complete', {
        prepared: { ...prepPayload, siwe: tampered },
        signature: sig,
        host,
        jwk,
        permissions: perms,
        approvalRequestId,
        authorizationContextToken: (prepared.body.authorizationContext as { token: string }).token,
        selectedActionIds: prepared.body.selectedActionKeys,
        protocolVersion: 1,
      });
      expect(refused.status).toBe(400);
      expect(refused.body).toMatchObject({ code: SIGNED_SUBSET_REFUSAL_CODE, reason: 'delegation_mode' });
    }
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    // Approving via managed / signs the declared terminal SIWE.
    const approved = await post('/', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      approvalRequestId,
      prepared: prepPayload,
      authorizationContextToken: (prepared.body.authorizationContext as { token: string }).token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(approved.status).toBe(200);
    const parsedSigned = parseStrictSiwe(approved.body.siwe as string);
    expect(parsedSigned.ok && parsedSigned.siwe.recap?.delegationMode).toBe('terminal');
  });

  test('device flow honors terminal and attenuable, keeps undeclared omitted, and refuses mode tampering on /complete', async () => {
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
        permissions: perms,
        nodeOrigin: host,
        shareOrigin: 'https://share.tinycloud.xyz',
        delegationTtlSeconds: 60,
      },
      '198.51.100.77',
    );
    const deviceTransactionId = started.transactionId;

    // Undeclared device login (tc auth login --device before step 5) stays omitted.
    const undeclared = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      deviceTransactionId,
    });
    expect(undeclared.status).toBe(200);
    const parsedUndec = parseStrictSiwe((undeclared.body.prepared as { siwe: string }).siwe);
    expect(parsedUndec.ok && parsedUndec.siwe.recap?.delegationMode).toBeUndefined();

    // Declared attenuable device login is honored.
    const attenuablePrep = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      deviceTransactionId,
      delegationMode: 'attenuable',
    });
    expect(attenuablePrep.status).toBe(200);
    const parsedAtt = parseStrictSiwe((attenuablePrep.body.prepared as { siwe: string }).siwe);
    expect(parsedAtt.ok && parsedAtt.siwe.recap?.delegationMode).toBe('attenuable');

    // Declared terminal device flow mints terminal and enforces it on /complete.
    const prepared = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      deviceTransactionId,
      delegationMode: 'terminal',
    });
    expect(prepared.status).toBe(200);
    const prepPayload = prepared.body.prepared as Record<string, unknown> & { siwe: string };
    const parsedPrep = parseStrictSiwe(prepPayload.siwe);
    expect(parsedPrep.ok && parsedPrep.siwe.recap?.delegationMode).toBe('terminal');

    for (const tampered of [
      rewriteRecapMode(prepPayload.siwe, undefined),
      rewriteRecapMode(prepPayload.siwe, 'attenuable'),
    ]) {
      const sig = await account.signMessage({ message: tampered });
      const refused = await post('/complete', {
        prepared: { ...prepPayload, siwe: tampered },
        signature: sig,
        host,
        jwk,
        permissions: perms,
        deviceTransactionId,
        authorizationContextToken: (prepared.body.authorizationContext as { token: string }).token,
        selectedActionIds: prepared.body.selectedActionKeys,
        protocolVersion: 1,
      });
      expect(refused.status).toBe(400);
      expect(refused.body).toMatchObject({ code: SIGNED_SUBSET_REFUSAL_CODE, reason: 'delegation_mode' });
    }
    expect(activateSessionWithHost).not.toHaveBeenCalled();

    const sig = await account.signMessage({ message: prepPayload.siwe });
    const completed = await post('/complete', {
      prepared: prepPayload,
      signature: sig,
      host,
      jwk,
      permissions: perms,
      deviceTransactionId,
      authorizationContextToken: (prepared.body.authorizationContext as { token: string }).token,
      selectedActionIds: prepared.body.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(completed.status).toBe(200);
    expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
  });

  test('device + managed-key /delegate flow (doManagedDelegate) completes terminal, attenuable, and undeclared, and refuses tampered mode', async () => {
    const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
    const startDevice = async () =>
      (
        await deviceService.start(
          {
            deviceSecretHash: digest(`secret-managed-${Math.random()}`),
            codeChallenge: digest(`verifier-managed-${Math.random()}`),
            sessionDid: sessionDidForPublicJwk(jwk),
            publicJwk: jwk,
            relayPublicJwk: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
              format: 'jwk',
            }) as Record<string, unknown>,
            permissions: perms,
            nodeOrigin: host,
            shareOrigin: 'https://share.tinycloud.xyz',
            delegationTtlSeconds: 60,
          },
          `198.51.100.${Math.floor(Math.random() * 200) + 10}`,
        )
      ).transactionId;

    // 1. Declared terminal, 2. Declared attenuable, 3. Undeclared — all complete through POST /prepare -> POST /.
    for (const declared of ['terminal', 'attenuable', undefined] as const) {
      activateSessionWithHost.mockClear();
      signManagedMessage.mockClear();
      const deviceTransactionId = await startDevice();
      const prepared = await post('/prepare', {
        keyId: managed.id,
        jwk,
        host,
        expiry: '60s',
        permissions: perms,
        deviceTransactionId,
        ...(declared !== undefined ? { delegationMode: declared } : {}),
      });
      expect(prepared.status).toBe(200);
      const prepPayload = prepared.body.prepared as Record<string, unknown> & { siwe: string };
      const parsedPrep = parseStrictSiwe(prepPayload.siwe);
      expect(parsedPrep.ok).toBe(true);
      if (!parsedPrep.ok) return;
      expect(parsedPrep.siwe.recap?.delegationMode).toBe(declared);

      const approved = await post('/', {
        keyId: managed.id,
        jwk,
        host,
        expiry: '60s',
        permissions: perms,
        deviceTransactionId,
        prepared: prepPayload,
        authorizationContextToken: (prepared.body.authorizationContext as { token: string }).token,
        selectedActionIds: prepared.body.selectedActionKeys,
        protocolVersion: 1,
        ...(declared !== undefined ? { delegationMode: declared } : {}),
      });
      expect(approved.status).toBe(200);
      const parsedSigned = parseStrictSiwe(approved.body.siwe as string);
      expect(parsedSigned.ok).toBe(true);
      if (!parsedSigned.ok) return;
      expect(parsedSigned.siwe.recap?.delegationMode).toBe(declared);
      expect(signManagedMessage).toHaveBeenCalledTimes(1);
      expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
    }

    // 4. Tampering with the mode in POST / (dropped or flipped) is refused before signing or activation.
    activateSessionWithHost.mockClear();
    signManagedMessage.mockClear();
    const tamperedTx = await startDevice();
    const preparedTerm = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      deviceTransactionId: tamperedTx,
      delegationMode: 'terminal',
    });
    expect(preparedTerm.status).toBe(200);
    const prepPayload = preparedTerm.body.prepared as Record<string, unknown> & { siwe: string };
    for (const tamperedMode of [undefined, 'attenuable'] as const) {
      const refused = await post('/', {
        keyId: managed.id,
        jwk,
        host,
        expiry: '60s',
        permissions: perms,
        deviceTransactionId: tamperedTx,
        prepared: { ...prepPayload, siwe: rewriteRecapMode(prepPayload.siwe, tamperedMode) },
        authorizationContextToken: (preparedTerm.body.authorizationContext as { token: string }).token,
        selectedActionIds: preparedTerm.body.selectedActionKeys,
        protocolVersion: 1,
        delegationMode: 'terminal',
      });
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('prepared_siwe_mismatch');
    }
    expect(signManagedMessage).not.toHaveBeenCalled();
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });

  test('plain /delegate honors auth request --grant terminal declaration, attenuable declaration, and keeps undeclared absent', async () => {
    const grantTerminal = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      delegationMode: 'terminal',
    });
    expect(grantTerminal.status).toBe(200);
    const parsedTerm = parseStrictSiwe((grantTerminal.body.prepared as { siwe: string }).siwe);
    expect(parsedTerm.ok && parsedTerm.siwe.recap?.delegationMode).toBe('terminal');

    const grantAttenuable = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
      delegationMode: 'attenuable',
    });
    expect(grantAttenuable.status).toBe(200);
    const parsedAtt = parseStrictSiwe((grantAttenuable.body.prepared as { siwe: string }).siwe);
    expect(parsedAtt.ok && parsedAtt.siwe.recap?.delegationMode).toBe('attenuable');

    const undeclared = await post('/prepare', {
      keyId: managed.id,
      jwk,
      host,
      expiry: '60s',
      permissions: perms,
    });
    expect(undeclared.status).toBe(200);
    const parsedUndec = parseStrictSiwe((undeclared.body.prepared as { siwe: string }).siwe);
    expect(parsedUndec.ok && parsedUndec.siwe.recap?.delegationMode).toBeUndefined();
  });

  // TC-3810 (Naomi): unskip in the @tinycloud/sdk-core bump commit once step 2's
  // reCapAttenuation accepts `xyz.tinycloud.policy/delegationMode`. On pinned
  // @tinycloud/sdk-core@3.12.0-beta.22, admitOwnerRenewalLease throws
  // "ReCap fields are invalid" when parsing a grant carrying delegationMode.
  test.skip('the bumped OpenKey renews a lease signed with a delegationMode key', async () => {
    const now = new Date();
    const nodeOrigin = 'http://127.0.0.1:41234';
    const nodeDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const renewerDid = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
    const nodeKeys = {
      nodeDid,
      renewerDid,
      renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
      renewerEpoch: 1,
    };
    const mockNodeFetch = (async (input: string | URL | Request) => {
      const href = String(input instanceof Request ? input.url : input);
      if (href === `${nodeOrigin}/info`) return new Response(JSON.stringify({ nodeId: nodeDid }), { status: 200 });
      if (href === `${nodeOrigin}/.well-known/tinycloud/node-keys`) {
        return new Response(JSON.stringify(nodeKeys), { status: 200 });
      }
      if (href === `${nodeOrigin}/delegate`) {
        return new Response(JSON.stringify({ activated: [space] }), { status: 200 });
      }
      return new Response('not found', { status: 404 });
    }) as typeof fetch;

    const prevFetch = globalThis.fetch;
    globalThis.fetch = mockNodeFetch;
    try {
      for (const mode of ['attenuable', 'terminal'] as const) {
        const grantPrepared = prepareSession({
          address: account.address,
          chainId: 1,
          domain: 'openkey.so',
          issuedAt: new Date(now.getTime() - 1_000).toISOString(),
          expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
          spaceId: space,
          jwk,
          abilities: { kv: { 'notes/': ['tinycloud.kv/get'] } },
        });
        const grantSiwe = withRecapDelegationMode(grantPrepared.siwe, mode);
        const grantSig = await account.signMessage({ message: grantSiwe });
        const session = completeSessionSetup({ ...grantPrepared, siwe: grantSiwe, signature: grantSig });

        const preparedStage = await prepareRenewalStage({
          userId: user.id,
          host: nodeOrigin,
          leaseLifetimeSeconds: 7 * 86_400,
          delegation: {
            delegationHeader: session.delegationHeader,
            delegationCid: session.delegationCid,
            spaceId: space,
            siwe: grantSiwe,
            hostActivated: true,
          },
          now,
          fetchImpl: mockNodeFetch,
        });
        const leaseSig = await account.signMessage({ message: preparedStage.leaseSiwe });
        const signedStage = signLease(preparedStage, leaseSig);
        const admitted = await admitLease(signedStage, { nodeOrigin, targetPublicJwk: jwk });
        expect(admitted.version).toBe(1);
        expect(admitted.receipt.originalCid).toBe(session.delegationCid);
        expect(admitted.receipt.leaseCid).toBe(signedStage.leaseCid);
      }
    } finally {
      globalThis.fetch = prevFetch;
    }
  });
});
