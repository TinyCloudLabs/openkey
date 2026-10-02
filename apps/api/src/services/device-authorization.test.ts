import { describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS,
  type DevicePermission,
  type DeviceRelayEnvelope,
  DeviceAuthorizationError,
  DeviceAuthorizationService,
  MemoryDeviceAuthorizationStore,
  sessionDidForPublicJwk,
} from './device-authorization';
import { parsePreparedRecap, prepareDelegationSession } from '../routes/delegate-session';

const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
const deviceSecret = 'device-secret-with-at-least-256-bits-of-entropy';
const codeVerifier = 'pkce-verifier-with-at-least-256-bits-of-entropy';

// The TC-539 acceptance scope: the CLI's built-in publishing manifest in the
// owner's default space.
function publishingPermissions(): DevicePermission[] {
  return [
    { service: 'tinycloud.kv', space: 'default', path: 'xyz.tinycloud.share/shares/', actions: ['tinycloud.kv/put', 'tinycloud.kv/get'] },
    { service: 'tinycloud.kv', space: 'default', path: 'shares/', actions: ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/metadata', 'tinycloud.kv/list'] },
    { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
  ];
}

function fixture() {
  let nowMs = Date.UTC(2026, 7, 14, 12, 0, 0);
  const store = new MemoryDeviceAuthorizationStore();
  const service = new DeviceAuthorizationService(store, {
    verificationOrigin: 'https://openkey.so',
    encryptionSecret: 'test-device-authorization-secret-is-long-enough',
    now: () => new Date(nowMs),
  });
  const publicJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: randomBytes(32).toString('base64url'),
  };
  const relayKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const relayPublicJwk = relayKeys.publicKey.export({ format: 'jwk' });
  const request = {
    deviceSecretHash: digest('device-secret-with-at-least-256-bits-of-entropy'),
    codeChallenge: digest('pkce-verifier-with-at-least-256-bits-of-entropy'),
    sessionDid: sessionDidForPublicJwk(publicJwk),
    publicJwk,
    relayPublicJwk,
    permissions: [{
      service: 'tinycloud.capabilities',
      space: 'applications',
      path: '',
      actions: ['tinycloud.capabilities/read'],
    }],
    nodeOrigin: 'https://node.tinycloud.xyz',
    shareOrigin: 'https://share.tinycloud.xyz',
  };
  const advance = (milliseconds: number) => { nowMs += milliseconds; };
  return { store, service, request, publicJwk, advance, now: () => new Date(nowMs) };
}

function encryptedApproval(
  input: ReturnType<typeof fixture>,
  transaction: Awaited<ReturnType<DeviceAuthorizationService['start']>>,
  permissions: unknown = input.request.permissions,
  expiresAt = new Date(input.now().getTime() + DEVICE_AUTH_DEFAULT_DELEGATION_TTL_MS - 1000),
) {
  const ephemeral = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const delegationExpiresAt = expiresAt.toISOString();
  return {
    relay: {
      version: 1 as const,
      algorithm: 'ECDH-P256-A256GCM' as const,
      ephemeralPublicJwk: ephemeral.publicKey.export({ format: 'jwk' }) as DeviceRelayEnvelope['ephemeralPublicJwk'],
      nonce: randomBytes(12).toString('base64url'),
      ciphertext: randomBytes(128).toString('base64url'),
    },
    binding: {
      sessionDid: input.request.sessionDid,
      nodeOrigin: input.request.nodeOrigin,
      shareOrigin: input.request.shareOrigin,
      permissions,
      transactionId: transaction.transactionId,
      delegationExpiresAt,
    },
  };
}

describe('OpenKey device authorization service', () => {
  test('delivers an end-to-end encrypted relay result exactly once without plaintext disclosure', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.9');
    expect(transaction.userCode).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(transaction.verificationUri).toBe('https://openkey.so/device');
    expect((await input.service.lookup(transaction.userCode))?.sessionDid).toBe(input.request.sessionDid);

    expect(await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).toEqual({ status: 'pending', interval: 2 });

    const approval = encryptedApproval(input, transaction);
    await input.service.approve(transaction.transactionId, 'user-1', approval);
    const stored = await input.store.findById(transaction.transactionId);
    expect(JSON.parse(stored?.encryptedResult ?? 'null')).toEqual(approval.relay);
    expect(JSON.stringify(stored)).not.toContain('delegationHeader');

    input.advance(2000);
    const approved = await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    });
    expect(approved.status).toBe('approved');
    if (approved.status === 'approved') {
      expect(approved.relay).toEqual(approval.relay);
      expect(approved.binding).toMatchObject({
        transactionId: transaction.transactionId,
        sessionDid: input.request.sessionDid,
        nodeOrigin: input.request.nodeOrigin,
        shareOrigin: input.request.shareOrigin,
      });
    }
    expect(await input.store.findById(transaction.transactionId)).not.toHaveProperty('encryptedResult');
    input.advance(2000);
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'invalid_grant', status: 409 });
  });

  test('binds the transaction to both the device secret and PKCE verifier', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.10');
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'wrong-secret',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'invalid_grant', status: 401 });
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'wrong-verifier',
    })).rejects.toMatchObject({ code: 'invalid_grant', status: 401 });
  });

  test('rejects widened result bindings, expiry, fast polls, expired transactions, and excess starts', async () => {
    const input = fixture();
    const transaction = await input.service.start(input.request, '203.0.113.11');
    await input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    });
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'slow_down', status: 429 });

    const widened = encryptedApproval(input, transaction);
    widened.binding.transactionId = 'another-transaction';
    await expect(input.service.approve(transaction.transactionId, 'user-1', widened))
      .rejects.toMatchObject({ code: 'invalid_result' });

    input.advance(10 * 60 * 1000 + 1);
    await expect(input.service.poll({
      transactionId: transaction.transactionId,
      deviceSecret: 'device-secret-with-at-least-256-bits-of-entropy',
      codeVerifier: 'pkce-verifier-with-at-least-256-bits-of-entropy',
    })).rejects.toMatchObject({ code: 'expired_token', status: 410 });

    const rate = fixture();
    for (let index = 0; index < 5; index += 1) {
      await rate.service.start({
        ...rate.request,
        deviceSecretHash: digest(`device-secret-${index}`),
        codeChallenge: digest(`pkce-verifier-${index}`),
      }, '198.51.100.2');
    }
    await expect(rate.service.start({
      ...rate.request,
      deviceSecretHash: digest('device-secret-six'),
      codeChallenge: digest('pkce-verifier-six'),
    }, '198.51.100.2')).rejects.toBeInstanceOf(DeviceAuthorizationError);
  });

  test('rejects a DID that is not derived from the supplied public key', async () => {
    const input = fixture();
    await expect(input.service.start({ ...input.request, sessionDid: 'did:key:z6Mismatched' }, '203.0.113.12'))
      .rejects.toMatchObject({ code: 'invalid_request' });
  });

  test('returns structured validation errors for non-object request bodies', async () => {
    const input = fixture();
    await expect(input.service.start(null as never, '203.0.113.13'))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 });
    await expect(input.service.poll(null as never))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 });
  });

  test('approves an explicit manifest scope narrowed by the owner and binds exactly the approved subset', async () => {
    const input = fixture();
    const requested = publishingPermissions();
    const transaction = await input.service.start({
      ...input.request,
      permissions: requested,
      reason: '  Publish  notes\u202e from\u200b my\u2060 agent\u061c\u180e\ufeff\u00ad\u034f\u115f\u1160\u3164\uffa0\u{e0041}\u{e007f} ',
    }, '203.0.113.20');
    const pending = await input.service.lookup(transaction.userCode);
    expect(pending).toMatchObject({ permissions: requested, reason: 'Publish notes from my agent', shareOnly: false });

    const approved = [
      { ...requested[1]!, actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
      requested[2]!,
    ];
    const approval = encryptedApproval(input, transaction, approved);
    await input.service.approve(transaction.transactionId, 'user-1', approval);
    expect(await input.service.lookup(transaction.userCode)).toBeNull();

    const result = await input.service.poll({ transactionId: transaction.transactionId, deviceSecret, codeVerifier });
    expect(result.status).toBe('approved');
    if (result.status !== 'approved') return;
    expect(result.relay).toEqual(approval.relay);
    expect(result.binding.permissions).toEqual(approved);
    expect(result.binding.delegationExpiresAt).toBe(approval.binding.delegationExpiresAt);
  });

  test('keeps the legacy Share-only request and normalizes its historical spellings', async () => {
    const input = fixture();
    const transaction = await input.service.start({
      ...input.request,
      permissions: [{ service: 'capabilities', space: 'tinycloud:pkh:eip155:1:0xabc:applications', path: '', actions: ['tinycloud.capabilities/read'] }],
    }, '203.0.113.21');
    const pending = await input.service.lookup(transaction.userCode);
    expect(pending?.shareOnly).toBe(true);
    expect(pending?.permissions).toEqual(input.request.permissions);
    // The legacy CLI binds the canonical constant, not its own spelling.
    await input.service.approve(transaction.transactionId, 'user-1', encryptedApproval(input, transaction));
    const result = await input.service.poll({ transactionId: transaction.transactionId, deviceSecret, codeVerifier });
    expect(result.status === 'approved' && result.binding.permissions).toEqual(input.request.permissions);
  });

  test('rejects out-of-policy device scopes with invalid_scope', async () => {
    const input = fixture();
    const valid = publishingPermissions()[0]!;
    const rejected: Array<[string, unknown]> = [
      ['short service name', [{ ...valid, service: 'kv' }]],
      ['SQL (deferred over the device flow)', [{ service: 'tinycloud.sql', space: 'default', path: 'notes', actions: ['tinycloud.sql/read'] }]],
      ['secrets service', [{ service: 'tinycloud.secrets', space: 'default', path: 'API_KEY', actions: ['tinycloud.secrets/get'] }]],
      ['delegation service', [{ service: 'tinycloud.delegation', space: 'default', path: '', actions: ['tinycloud.delegation/list'] }]],
      ['wildcard ability', [{ ...valid, actions: ['tinycloud.kv/*'] }]],
      ['account registry space', [{ ...valid, space: 'account' }]],
      ['secrets space URI', [{ ...valid, space: 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:secrets' }]],
      ['applications registry beyond the legacy read', [{ ...valid, space: 'applications' }]],
      ['two spaces', [valid, { ...valid, path: 'shares/', space: 'public' }]],
      ['same owner on another chain', [
        { ...valid, space: 'tinycloud:pkh:eip155:1:0x00000000000000000000000000000000000000ab:default' },
        { ...valid, path: 'shares/', space: 'tinycloud:pkh:eip155:10:0x00000000000000000000000000000000000000ab:default' },
      ]],
      ['bare name mixed with a full URI', [valid, { ...valid, path: 'shares/', space: 'tinycloud:pkh:eip155:1:0x00000000000000000000000000000000000000ab:default' }]],
      ['whole-space KV grant', [{ ...valid, path: '' }]],
      ['path traversal', [{ ...valid, path: 'shares/../vault/' }]],
      ['secret path root', [{ ...valid, path: 'vault/secrets/DEPLOY_KEY' }]],
      ['scoped capabilities path', [{ service: 'tinycloud.capabilities', space: 'default', path: 'x', actions: ['tinycloud.capabilities/read'] }]],
      ['repeated resource', [valid, valid]],
      ['path covered by a trailing-slash twin', [{ ...valid, path: 'shares' }, { ...valid, path: 'shares/' }]],
      ['path beneath another path', [{ ...valid, path: 'a/b' }, { ...valid, path: 'a' }]],
      ['repeated ability', [{ ...valid, actions: ['tinycloud.kv/get', 'tinycloud.kv/get'] }]],
      ['unknown permission field', [{ ...valid, caveats: { anything: true } }]],
      ['too many capabilities', Array.from({ length: 17 }, (_, index) => ({ ...valid, path: `p${index}/` }))],
      ['no capabilities', []],
    ];
    for (const [label, permissions] of rejected) {
      await expect(input.service.start({ ...input.request, permissions } as never, '198.51.100.7'), label)
        .rejects.toMatchObject({ code: 'invalid_scope', status: 400 });
    }
  });

  test('requires tinycloud.capabilities/read on path "" instead of adding it silently', async () => {
    const input = fixture();
    const kvOnly = publishingPermissions().slice(0, 2);
    await expect(input.service.start({ ...input.request, permissions: kvOnly }, '203.0.113.60'))
      .rejects.toMatchObject({ code: 'invalid_scope', status: 400, message: expect.stringContaining('tinycloud.capabilities/read') });

    // Overlap is per service and per segment: siblings and prefixes of a
    // segment name are distinct resources.
    const siblings = [
      { service: 'tinycloud.kv', space: 'default', path: 'shares', actions: ['tinycloud.kv/get'] },
      { service: 'tinycloud.kv', space: 'default', path: 'sharesX/', actions: ['tinycloud.kv/get'] },
      { service: 'tinycloud.kv', space: 'default', path: 'xyz.tinycloud.share/shares/', actions: ['tinycloud.kv/get'] },
      publishingPermissions()[2]!,
    ];
    await input.service.start({ ...input.request, permissions: siblings }, '203.0.113.61');
  });

  test('caps the reason at 200 characters and the lifetime at the requested TTL from approval', async () => {
    const input = fixture();
    const thirtyDays = 30 * 24 * 60 * 60;
    await expect(input.service.start({ ...input.request, delegationTtlSeconds: thirtyDays + 1 }, '203.0.113.30'))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 });
    await expect(input.service.start({ ...input.request, permissions: publishingPermissions(), reason: 'x'.repeat(201) }, '203.0.113.31'))
      .rejects.toMatchObject({ code: 'invalid_request', status: 400 });
    const transaction = await input.service.start({
      ...input.request,
      permissions: publishingPermissions(),
      reason: 'x'.repeat(200),
      delegationTtlSeconds: 60,
    }, '203.0.113.32');
    expect((await input.service.lookup(transaction.userCode))?.delegationTtlSeconds).toBe(60);

    // Approve five minutes later: at most approval time + 60 s, never the
    // 60 s + ten-minute transaction window.
    input.advance(5 * 60 * 1000);
    const approvedAt = input.now().getTime();
    for (const late of [61_000, 10 * 60 * 1000 + 60_000]) {
      await expect(input.service.approve(
        transaction.transactionId,
        'user-1',
        encryptedApproval(input, transaction, publishingPermissions(), new Date(approvedAt + late)),
      )).rejects.toMatchObject({ code: 'invalid_result', status: 400 });
    }
    await input.service.approve(
      transaction.transactionId,
      'user-1',
      encryptedApproval(input, transaction, publishingPermissions(), new Date(approvedAt + 60_000)),
    );
    const result = await input.service.poll({ transactionId: transaction.transactionId, deviceSecret, codeVerifier });
    expect(result.status === 'approved' && result.binding.delegationExpiresAt).toBe(new Date(approvedAt + 60_000).toISOString());
  });

  test('signs and binds a mixed-casing owner space URI end to end', async () => {
    const input = fixture();
    const eip55Address = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
    const lower = `tinycloud:pkh:eip155:1:${eip55Address.toLowerCase()}:default`;
    const eip55 = `tinycloud:pkh:eip155:1:${eip55Address}:default`;
    const requested = publishingPermissions().map((permission, index) => ({ ...permission, space: index === 0 ? eip55 : lower }));
    const transaction = await input.service.start({ ...input.request, permissions: requested }, '203.0.113.50');
    const pending = (await input.service.lookup(transaction.userCode))!;

    // /delegate/prepare with the same request: one space, signed in EIP-55.
    const prepared = prepareDelegationSession({
      address: eip55Address,
      chainId: 1,
      prefix: 'default',
      jwk: input.publicJwk as never,
      permissions: pending.permissions,
      expiryMs: 60 * 60 * 1000,
    });
    expect(new Set(parsePreparedRecap(prepared.prepared.siwe).map((entry) => entry.space))).toEqual(new Set([eip55]));

    // A binding re-spelled in the signed EIP-55 form is not the request's spelling.
    await expect(input.service.approve(transaction.transactionId, 'user-1',
      encryptedApproval(input, transaction, requested.map((permission) => ({ ...permission, space: eip55 })))))
      .rejects.toMatchObject({ code: 'invalid_result' });
    await input.service.approve(transaction.transactionId, 'user-1', encryptedApproval(input, transaction, requested));
    const result = await input.service.poll({ transactionId: transaction.transactionId, deviceSecret, codeVerifier });
    expect(result.status === 'approved' && result.binding.permissions).toEqual(requested);
  });

  test('rejects approvals that widen, duplicate, reorder, or empty the requested scope', async () => {
    const input = fixture();
    const requested = publishingPermissions();
    const transaction = await input.service.start({ ...input.request, permissions: requested }, '203.0.113.40');
    const attempts: Array<[string, unknown]> = [
      ['extra ability', [{ ...requested[2]!, actions: ['tinycloud.capabilities/read', 'tinycloud.kv/get'] }]],
      ['unrequested path', [{ ...requested[0]!, path: 'other/' }]],
      ['other space', [{ ...requested[0]!, space: 'public' }]],
      ['duplicate resource', [requested[0], requested[0], requested[2]]],
      ['reordered entries', [requested[2], requested[0]]],
      ['reordered actions', [{ ...requested[1]!, actions: [...requested[1]!.actions].reverse() }, requested[2]]],
      ['drops capabilities/read', [requested[0]]],
      ['empty actions', [{ ...requested[0]!, actions: [] }]],
      ['empty set', []],
      ['missing', undefined],
    ];
    for (const [label, permissions] of attempts) {
      await expect(input.service.approve(transaction.transactionId, 'user-1', encryptedApproval(input, transaction, permissions)), label)
        .rejects.toMatchObject({ code: 'invalid_result', status: 400 });
    }
    expect((await input.store.findById(transaction.transactionId))?.status).toBe('pending');
  });

  test('handles KV paths named like Object.prototype members end to end', async () => {
    const input = fixture();
    const address = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
    const requested: DevicePermission[] = [
      ...['constructor', 'toString', '__proto__'].map((path) => ({
        service: 'tinycloud.kv', space: 'default', path, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'],
      })),
      publishingPermissions()[2]!,
    ];
    const transaction = await input.service.start({ ...input.request, permissions: requested }, '203.0.113.70');
    const pending = (await input.service.lookup(transaction.userCode))!;
    const base = { address, chainId: 1, prefix: 'default', jwk: input.publicJwk as never, permissions: pending.permissions, expiryMs: 60 * 60 * 1000 };
    const baseline = prepareDelegationSession(base);
    // The owner unchecks put on `__proto__`; narrowing rebuilds the maps.
    const narrowed = prepareDelegationSession({
      ...base,
      actionKeys: baseline.selectedActionKeys.filter((key) => !(key.includes('\0__proto__\0') && key.endsWith('tinycloud.kv/put'))),
    });
    expect(parsePreparedRecap(narrowed.prepared.siwe).map((entry) => [entry.path, entry.actions])).toEqual([
      ['', ['tinycloud.capabilities/read']],
      ['__proto__', ['tinycloud.kv/get']],
      ['constructor', ['tinycloud.kv/get', 'tinycloud.kv/put']],
      ['toString', ['tinycloud.kv/get', 'tinycloud.kv/put']],
    ]);
    const approved = requested.map((permission) => (permission.path === '__proto__' ? { ...permission, actions: ['tinycloud.kv/get'] } : permission));
    await input.service.approve(transaction.transactionId, 'user-1', encryptedApproval(input, transaction, approved));
    const result = await input.service.poll({ transactionId: transaction.transactionId, deviceSecret, codeVerifier });
    expect(result.status === 'approved' && result.binding.permissions).toEqual(approved);
  });

  test('limits delegations signed for a device transaction to its key, origin, and lifetime', async () => {
    const input = fixture();
    const transaction = await input.service.start({ ...input.request, delegationTtlSeconds: 60 }, '203.0.113.80');
    const window = (seconds: number, overrides: { nodeOrigin?: string; jwk?: unknown } = {}) =>
      input.service.assertDelegationWindow(transaction.transactionId, {
        expiresAt: new Date(input.now().getTime() + seconds * 1000),
        nodeOrigin: overrides.nodeOrigin ?? input.request.nodeOrigin,
        jwk: overrides.jwk ?? input.publicJwk,
      });
    input.advance(5 * 60 * 1000);
    await window(60);
    await expect(window(66)).rejects.toMatchObject({ code: 'invalid_request', status: 400 });
    await expect(window(90 * 24 * 60 * 60)).rejects.toMatchObject({ code: 'invalid_request', status: 400 });
    await expect(window(60, { nodeOrigin: 'https://attacker.example' })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(window(60, { jwk: { kty: 'OKP', crv: 'Ed25519', x: randomBytes(32).toString('base64url') } }))
      .rejects.toMatchObject({ code: 'invalid_request' });
    await expect(input.service.assertDelegationWindow('unknown', { expiresAt: input.now(), nodeOrigin: '', jwk: input.publicJwk }))
      .rejects.toMatchObject({ code: 'expired_token', status: 410 });
    input.advance(5 * 60 * 1000);
    await expect(window(30)).rejects.toMatchObject({ code: 'expired_token', status: 410 });
  });
});
