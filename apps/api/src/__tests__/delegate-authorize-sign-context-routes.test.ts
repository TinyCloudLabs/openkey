// TC-645: a refused editable-sign request must leave BOTH single-use tokens
// available for a corrected attempt; only the successful signer consumes them.
import { beforeAll, beforeEach, describe, expect, mock, setSystemTime, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { verifyMessage } from 'ethers';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import * as signing from '../services/authorization-signing';
import * as realNarrowing from '../services/siwe-narrow';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const otherSigner = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const otherUser = { id: 'user_2', email: 'bob@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
// Two database rows may hold the same wallet under different address casing:
// key linking checks the submitted spelling, while signer lookup normalizes it.
const otherExternal = {
  id: 'external_other', userId: otherUser.id, address: account.address.toLowerCase() as typeof account.address,
  keyType: 'EXTERNAL', archivedAt: null, sealedBlob: null, sealingContext: null,
};
const managed = {
  id: 'managed_1', userId: user.id, address: account.address, keyType: 'MANAGED',
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const external = { ...managed, id: 'external_1', keyType: 'EXTERNAL', sealedBlob: null };
let currentUser = user;
let currentKey: typeof managed | typeof external = managed;
let narrowingFault: 'failure' | 'immutable-drift' | null = null;

const findMany = mock(async () => [currentKey]);
const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id: string; userId: string } }) =>
      where.id === currentKey.id && where.userId === currentUser.id ? currentKey : null),
    findMany,
    findUnique: mock(async () => currentKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
// Captured before mocking: bun rewrites the imported namespace in place.
const narrow = realNarrowing.narrowSiwePreservingImmutable;
const unseal = mock(async () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));
replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', currentUser);
      c.set('session', { id: 'session_test', userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal,
    createWalletFromPrivateKey: () => ({ signMessage: ({ message }: { message: string }) => signManagedMessage(message) }),
    generatePrivateKey: () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    getAddressFromPrivateKey: () => account.address,
  }),
  // Fault injection at the SIWE regenerator, NOT at the authorization service:
  // valid prepared inputs cannot naturally produce a corrupt regenerated result.
  '../services/siwe-narrow': () => ({
    narrowSiwePreservingImmutable: (input: Parameters<typeof narrow>[0]) => {
      if (narrowingFault === 'failure') return narrow({ ...input, originalSiwe: '' });
      const result = narrow(input);
      if (narrowingFault === 'immutable-drift' && result.ok) {
        return { ...result, siwe: result.siwe.replace(/^(Nonce: .+)$/m, '$1x') };
      }
      return result;
    },
  }),
});

let router: typeof delegateRouter;
// Load the router after mock.module registrations; a static import would bind
// real Prisma/TEE dependencies before this isolated HTTP test installs fakes.
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?authorize-sign-context-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: currentUser.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  signing._resetAuthorizationContextStoreForTests();
  currentUser = user;
  currentKey = managed;
  narrowingFault = null;
  findMany.mockImplementation(async () => [currentKey]);
  unseal.mockClear();
  signManagedMessage.mockClear();
});

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

function stringField(value: unknown): string {
  expect(typeof value).toBe('string');
  if (typeof value !== 'string') throw new Error('Expected string response field');
  return value;
}

function stringArray(value: unknown): string[] {
  expect(Array.isArray(value) && value.every((item: unknown) => typeof item === 'string')).toBe(true);
  if (!Array.isArray(value) || !value.every((item: unknown): item is string => typeof item === 'string')) {
    throw new Error('Expected string array response field');
  }
  return value;
}

function originalSiwe(withRequiredAction = true) {
  const now = Date.now();
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'openkey.so',
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + 3_600_000).toISOString(),
    spaceId: space,
    jwk,
    // The WASM declaration is narrower than its runtime-supported service/action map.
    abilities: {
      kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      ...(withRequiredAction ? { capabilities: { [space]: ['tinycloud.capabilities/read'] } } : {}),
    } as unknown as Parameters<typeof prepareSession>[0]['abilities'],
  }).siwe;
}

type Approval = {
  siwe: string;
  allowed: string[];
  selected: string[];
  contextToken: string;
  previewToken: string;
  previewBytes: string;
  body: Record<string, unknown>;
};

async function approve(selection: 'exact' | 'narrowed' = 'exact', withRequiredAction = true): Promise<Approval> {
  const siwe = originalSiwe(withRequiredAction);
  const prepared = await post('/authorize-sign-prepare', { keyId: currentKey.id, siwe, jwk, host });
  expect(prepared.status).toBe(200);
  const allowed = stringArray(prepared.body.allowedActionIds);
  const selected = selection === 'narrowed' ? allowed.filter((id) => !id.includes('kv/put')) : allowed;
  expect(allowed.some((id) => id.includes('kv/put'))).toBe(true);
  expect(selected.length).toBe(selection === 'narrowed' ? allowed.length - 1 : allowed.length);
  const contextToken = stringField(prepared.body.authorizationContextToken);
  const preview = await post('/authorize-sign-preview', { authorizationContextToken: contextToken, selectedActionIds: selected });
  expect(preview.status).toBe(200);
  const previewToken = stringField(preview.body.previewApprovalToken);
  const previewBytes = stringField(preview.body.signedMessage);
  return {
    siwe, allowed, selected, contextToken, previewToken, previewBytes,
    body: { authorizationContextToken: contextToken, previewApprovalToken: previewToken, selectedActionIds: selected, protocolVersion: 1 },
  };
}

async function validBody(approval: Approval) {
  return currentKey.keyType === 'EXTERNAL'
    ? { ...approval.body, externalSignature: await account.signMessage({ message: approval.previewBytes }) }
    : approval.body;
}

function noSignatureIssued() {
  expect(unseal).not.toHaveBeenCalled();
  expect(signManagedMessage).not.toHaveBeenCalled();
}

async function finishAfterRefusal(approval: Approval) {
  const corrected = await post('/authorize-sign', await validBody(approval));
  expect(corrected.status).toBe(200);
  expect(corrected.body.signedMessage).toBe(approval.previewBytes);
  expect(verifyMessage(stringField(corrected.body.signedMessage), stringField(corrected.body.signature)).toLowerCase()).toBe(account.address.toLowerCase());
  expect(signing.checkPreviewApproval({
    token: approval.previewToken,
    authorizationContextToken: approval.contextToken,
    userId: user.id,
    keyAddress: account.address,
    selectedActionIds: new Set(approval.selected),
    candidateSignedMessage: approval.previewBytes,
  })).toMatchObject({ ok: false, error: 'preview-approval-not-found' });
  expect((await post('/authorize-sign', await validBody(approval))).body.code).toBe('context-not-found');
  if (currentKey.keyType === 'MANAGED') {
    expect(unseal).toHaveBeenCalledTimes(1);
    expect(signManagedMessage).toHaveBeenCalledTimes(1);
  } else {
    noSignatureIssued();
  }
}

// Test-only access to the REAL context record via the checked claim. There is
// deliberately no production API for fabricating an internally inconsistent
// prepared context; mutate it only between a real preview and finalize.
function contextRecord(approval: Approval): Record<string, unknown> {
  const lines = approval.siwe.split(/\r?\n/);
  const uriIndex = lines.findIndex((line) => line.startsWith('URI:'));
  let statementEnd = uriIndex - 1;
  while (statementEnd > 3 && lines[statementEnd] === '') statementEnd--;
  const header = (name: string) => approval.siwe.match(new RegExp(`^${name}:\\s*(.+)$`, 'm'))?.[1]?.trim() ?? '';
  const immutableDigest = signing.digestImmutableFields({
    address: account.address, chainId: 1, domain: 'openkey.so', spaceId: space,
    issuedAt: header('Issued At'), expirationTime: header('Expiration Time'),
    nonce: header('Nonce'), uri: header('URI'), version: header('Version'),
    notBefore: header('Not Before'), requestId: header('Request ID'),
    statement: statementEnd >= 3 ? lines.slice(3, statementEnd + 1).join('\n') : '',
    nonRecapResources: lines.filter((line) => line.startsWith('- ') && !line.startsWith('- urn:recap:')).join('\n'),
  });
  const baseline = signing.extractRecapAttenuationFromSiwe(approval.siwe);
  const check = signing.checkAuthorizationContext({
    token: approval.contextToken, userId: user.id, keyId: currentKey.id,
    keyAddress: account.address, jwk, host, spaceId: space,
    selectedActionIds: new Set(approval.selected), candidateImmutableFieldsDigest: immutableDigest,
    baselineAttenuation: baseline, candidateAttenuation: baseline, requiredActionIds: new Set(),
  });
  expect(check.ok).toBe(true);
  if (!check.ok) throw new Error('Prepared context did not pass its own bindings');
  return check.claim.record as Record<string, unknown>;
}

function previewRecord(approval: Approval): Record<string, unknown> {
  const check = signing.checkPreviewApproval({
    token: approval.previewToken, authorizationContextToken: approval.contextToken,
    userId: user.id, keyAddress: account.address,
    selectedActionIds: new Set(approval.selected), candidateSignedMessage: approval.previewBytes,
  });
  expect(check.ok).toBe(true);
  if (!check.ok) throw new Error('Preview approval did not pass its own bindings');
  return check.claim.record as Record<string, unknown>;
}

describe('authorize-sign checks every binding before consuming context and preview', () => {
  test('another account with the same external wallet cannot probe a selection', async () => {
    currentKey = external;
    const approval = await approve();
    const externalSignature = await account.signMessage({ message: approval.previewBytes });
    currentUser = otherUser;
    currentKey = otherExternal;
    for (const selectedActionIds of [approval.selected, ['not-in-the-baseline']]) {
      const refused = await post('/authorize-sign', {
        ...approval.body, selectedActionIds, externalSignature,
      });
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('user_mismatch');
      expect(refused.body.signature).toBeUndefined();
    }
    noSignatureIssued();
    currentUser = user;
    currentKey = external;
    await finishAfterRefusal(approval);
  });

  const contextFaults: Array<{
    name: string; code: string; field: string; change: (value: unknown, approval: Approval) => unknown;
  }> = [
    { name: 'user', code: 'user_mismatch', field: 'userId', change: () => otherUser.id },
    { name: 'key identity', code: 'key-mismatch', field: 'keyId', change: () => 'another_key' },
    { name: 'JWK digest', code: 'jwk-mismatch', field: 'jwkDigest', change: () => '0'.repeat(64) },
    { name: 'immutable header digest', code: 'immutable-fields-changed', field: 'immutableFieldsDigest', change: () => '0'.repeat(64) },
    { name: 'baseline digest', code: 'baseline-digest-mismatch', field: 'baselineAbilitiesDigest', change: () => '0'.repeat(64) },
    { name: 'allowed actions', code: 'action-not-in-baseline', field: 'allowedActionIds', change: () => [] },
    { name: 'initial selection', code: 'action-not-in-initial-selection', field: 'initialSelectionActionIds', change: (_value, approval) => approval.allowed.slice(1) },
  ];
  for (const fault of contextFaults) {
    test(`refuses ${fault.name}, then signs with the same context and preview tokens`, async () => {
      const approval = await approve();
      const record = contextRecord(approval);
      const original = record[fault.field];
      record[fault.field] = fault.change(original, approval);
      try {
        const refused = await post('/authorize-sign', approval.body);
        expect(refused.status).toBe(400);
        expect(refused.body.code).toBe(fault.code);
        expect(refused.body.signature).toBeUndefined();
        noSignatureIssued();
      } finally {
        record[fault.field] = original;
      }
      await finishAfterRefusal(approval);
    });
  }

  for (const [field, code] of [['host', 'host-mismatch'], ['spaceId', 'space-mismatch']] as const) {
    test(`refuses ${field} drifting between lookup and check`, async () => {
      const approval = await approve();
      const record = contextRecord(approval);
      const original = record[field];
      let reads = 0;
      Object.defineProperty(record, field, {
        configurable: true,
        get: () => ++reads === 1 ? original : `${original}-altered`,
      });
      try {
        const refused = await post('/authorize-sign', approval.body);
        expect(refused.status).toBe(400);
        expect(refused.body.code).toBe(code);
        expect(refused.body.signature).toBeUndefined();
        noSignatureIssued();
      } finally {
        Object.defineProperty(record, field, { configurable: true, writable: true, value: original });
      }
      await finishAfterRefusal(approval);
    });
  }

  const previewFaults: Array<{ name: string; code: string; field: string; change: (approval: Approval) => unknown }> = [
    { name: 'preview user', code: 'preview-approval-user-mismatch', field: 'userId', change: () => otherUser.id },
    { name: 'preview context', code: 'preview-approval-context-mismatch', field: 'authorizationContextToken', change: () => 'different-context' },
    { name: 'preview selection', code: 'preview-approval-selection-mismatch', field: 'selectedActionIds', change: (approval) => approval.allowed.slice(1) },
    { name: 'preview bytes', code: 'preview-approval-bytes-mismatch', field: 'signedMessageDigest', change: () => '0'.repeat(64) },
  ];
  for (const fault of previewFaults) {
    test(`refuses ${fault.name} and keeps both original tokens usable`, async () => {
      const approval = await approve();
      const record = previewRecord(approval);
      const original = record[fault.field];
      record[fault.field] = fault.change(approval);
      try {
        const refused = await post('/authorize-sign', approval.body);
        expect(refused.status).toBe(400);
        expect(refused.body.code).toBe(fault.code);
        expect(refused.body.signature).toBeUndefined();
        noSignatureIssued();
      } finally {
        record[fault.field] = original;
      }
      await finishAfterRefusal(approval);
    });
  }

  test('a mismatched selected action is refused without consuming either token', async () => {
    const approval = await approve();
    const selectedActionIds = approval.allowed.filter((id) => !id.includes('kv/put'));
    const refused = await post('/authorize-sign', { ...approval.body, selectedActionIds });
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('preview-approval-selection-mismatch');
    expect(refused.body.signature).toBeUndefined();
    noSignatureIssued();
    await finishAfterRefusal(approval);
  });

  for (const [name, selected, code] of [
    ['an empty selection with required actions', () => [], 'required-action-missing'],
    ['a removed required action', (approval: Approval) => approval.allowed.filter((id) => !id.includes('capabilities/read')), 'required-action-missing'],
  ] as const) {
    test(`refuses ${name} before signing and allows corrected retry`, async () => {
      const approval = await approve();
      const refused = await post('/authorize-sign', { ...approval.body, selectedActionIds: selected(approval) });
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe(code);
      expect(refused.body.signature).toBeUndefined();
      noSignatureIssued();
      await finishAfterRefusal(approval);
    });
  }
  test('unknown action IDs keep the baseline refusal, not empty_selection', async () => {
    const approval = await approve();
    const refused = await post('/authorize-sign', {
      ...approval.body, selectedActionIds: ['not-in-the-baseline'],
    });
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('action-not-in-baseline');
    noSignatureIssued();
    await finishAfterRefusal(approval);
  });

  test('an empty selection without required actions is refused after the context check', async () => {
    const approval = await approve('exact', false);
    const refused = await post('/authorize-sign', { ...approval.body, selectedActionIds: [] });
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('empty_selection');
    noSignatureIssued();
    await finishAfterRefusal(approval);
  });

  test('expired contexts are distinguished from missing contexts on preview and sign', async () => {
    const approval = await approve();
    setSystemTime(new Date(Date.now() + 6 * 60 * 1000));
    try {
      for (const [path, body] of [
        ['/authorize-sign-preview', { authorizationContextToken: approval.contextToken, selectedActionIds: approval.selected }],
        ['/authorize-sign', approval.body],
      ] as const) {
        const refused = await post(path, body);
        expect(refused.status).toBe(400);
        expect(refused.body.code).toBe('context-expired');
      }
      noSignatureIssued();
    } finally {
      setSystemTime();
    }
    await finishAfterRefusal(approval);
  });

  test('an expired preview approval is distinguished from a missing one', async () => {
    const approval = await approve();
    const record = previewRecord(approval);
    const originalExpiry = record.expiresAt;
    record.expiresAt = Date.now() - 1;
    try {
      const refused = await post('/authorize-sign', approval.body);
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('preview-approval-expired');
      noSignatureIssued();
    } finally {
      record.expiresAt = originalExpiry;
    }
    await finishAfterRefusal(approval);
  });

  for (const [name, fault, code] of [
    ['failed narrowing', 'failure', 'siwe_not_parseable'],
    ['regenerated immutable drift', 'immutable-drift', 'regenerated_immutable_drift'],
  ] as const) {
    test(`refuses ${name} without burning a narrowed approval`, async () => {
      const approval = await approve('narrowed');
      narrowingFault = fault;
      try {
        const refused = await post('/authorize-sign', approval.body);
        expect(refused.status).toBe(400);
        expect(refused.body.code).toBe(code);
        expect(refused.body.signature).toBeUndefined();
        noSignatureIssued();
      } finally {
        narrowingFault = null;
      }
      await finishAfterRefusal(approval);
      expect(approval.previewBytes).not.toBe(approval.siwe);
    });
  }
});

describe('managed and external signer finalization', () => {
  for (const kind of ['MANAGED', 'EXTERNAL'] as const) {
    for (const selection of ['exact', 'narrowed'] as const) {
      test(`${kind} ${selection} bytes sign exactly once`, async () => {
        currentKey = kind === 'MANAGED' ? managed : external;
        const approval = await approve(selection);
        if (selection === 'exact') expect(approval.previewBytes).toBe(approval.siwe);
        else expect(approval.previewBytes).not.toBe(approval.siwe);
        await finishAfterRefusal(approval);
      });
    }
  }

  for (const selection of ['exact', 'narrowed'] as const) {
    const invalid: Array<{ name: string; code: string; signature: (approval: Approval) => Promise<string | undefined> }> = [
      { name: 'missing signature', code: 'external_signature_required', signature: async () => undefined },
      { name: 'malformed signature', code: 'external_signature_invalid', signature: async () => 'not-a-signature' },
      { name: 'wrong signer', code: 'external_signature_mismatch', signature: (a) => otherSigner.signMessage({ message: a.previewBytes }) },
      { name: 'other signed bytes', code: 'external_signature_mismatch', signature: (a) => account.signMessage({ message: `${a.previewBytes}x` }) },
    ];
    for (const refusal of invalid) {
      test(`external ${selection}: ${refusal.name} leaves context and preview usable`, async () => {
        currentKey = external;
        const approval = await approve(selection);
        const refused = await post('/authorize-sign', {
          ...approval.body, externalSignature: await refusal.signature(approval),
        });
        expect(refused.status).toBe(400);
        expect(refused.body.code).toBe(refusal.code);
        expect(refused.body.signature).toBeUndefined();
        noSignatureIssued();
        await finishAfterRefusal(approval);
      });
    }
  }

  test('two requests paused at the real async key lookup yield only one signature', async () => {
    // This barrier is before peek: it proves requests overlap and only one
    // signs via single-use lookup. The identity compare is exercised by the
    // service tests; it matters if an await is ever added after check.
    const approval = await approve();
    let arrivals = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    findMany.mockImplementation(async () => {
      arrivals += 1;
      if (arrivals === 2) release();
      await gate;
      return [currentKey];
    });
    const results = await Promise.all([
      post('/authorize-sign', approval.body),
      post('/authorize-sign', approval.body),
    ]);
    expect(arrivals).toBe(2);
    expect(results.map((result) => result.status).sort()).toEqual([200, 400]);
    expect(results.find((result) => result.status === 400)?.body.code).toBe('context-not-found');
    const winner = results.find((result) => result.status === 200)!;
    expect(winner.body.signedMessage).toBe(approval.previewBytes);
    expect(verifyMessage(stringField(winner.body.signedMessage), stringField(winner.body.signature)).toLowerCase()).toBe(account.address.toLowerCase());
    expect(results.find((result) => result.status === 400)?.body.signature).toBeUndefined();
    expect(unseal).toHaveBeenCalledTimes(1);
    expect(signManagedMessage).toHaveBeenCalledTimes(1);
  });
});
