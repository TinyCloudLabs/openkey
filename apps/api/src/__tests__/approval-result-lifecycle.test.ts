import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { ApprovalResultService, type ApprovalRequestRecord, type ApprovalRequestStore } from '../services/approval-results';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { createDelegationCodeRouter, createPrismaDelegationCodeStore, type ApprovalCodeStore } from '../routes/delegation-codes';
import { Wallet } from 'ethers';
import { SiweMessage } from 'siwe';
import { strictSessionDid } from '../services/device-authorization';

// The production adapter uses compare-and-set writes; this isolated store keeps
// those same transitions so failure/retry tests don't depend on a live account.
function fixture(codeStore?: ApprovalCodeStore) {
  let clock = new Date('2026-10-28T20:00:00Z');
  const pair = generateKeyPairSync('ed25519');
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const record = {
    id: 'abcdefghijklmnopqrstuvwxyz', bodyCid: 'sealed-body-cid', issuer: 'synthetic-requester',
    request: { targetDid: 'synthetic-requester', targetPublicJwk: jwk },
    expiresAt: new Date(clock.getTime() + 1000), createdAt: clock,
    resultRef: 'synthetic-result-reference', encryptedResult: '{"ciphertext":"opaque"}',
    resultExpiresAt: new Date(clock.getTime() + 600_000), ownerDid: 'synthetic-owner',
  } as ApprovalRequestRecord;
  const store: ApprovalRequestStore = {
    async register() { return record; },
    async findById(id) { return id === record.id ? record : null; },
    async findByResultRef(ref) { return ref === record.resultRef ? record : null; },
    async admit() { throw new Error('not used in read/ACK regression'); },
    async release() { throw new Error('not used in read/ACK regression'); },
    async approve() { throw new Error('not used in read/ACK regression'); },
    async saveRenewal() { throw new Error('not used in read/ACK regression'); },
    async acknowledge(ref, ackId, now) {
      if (ref !== record.resultRef || record.resultExpiresAt! <= now || (record.ackId && record.ackId !== ackId)) return null;
      record.ackId = ackId; record.acknowledgedAt ??= now; record.encryptedResult = null;
      return record;
    },
    async deny() { throw new Error('not used'); },
  };
  const origin = 'http://localhost:3001';
  const service = new ApprovalResultService(store, { apiOrigin: origin, retentionSeconds: 600, now: () => clock, codeStore });
  function proof(action: 'discover' | 'fetch' | 'ack', path: string, ackId = '', key = pair.privateKey, codeBinding?: [string, string]) {
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
    const head = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: jkt, typ: 'openkey-session-proof+jwt' })).toString('base64url');
    const credential = JSON.stringify([action, record.id, record.bodyCid, action === 'discover' ? '' : record.resultRef, ackId, ...(codeBinding ?? [])]);
    const claims = Buffer.from(JSON.stringify({ client_id: 'openkey-approval-result-v1', cred_hash: createHash('sha256').update(credential).digest('base64url'), htm: 'POST', htu: origin + path, iat: clock.getTime() / 1000, jti: 'isolated-synthetic-jti-0001' })).toString('base64url');
    return `${head}.${claims}.${sign(null, Buffer.from(`${head}.${claims}`), key).toString('base64url')}`;
  }
  return { service, store, record, proof, advance(ms: number) { clock = new Date(clock.getTime() + ms); } };
}

describe('requester-bound durable approval results', () => {
  test('repeated fetch survives lost replies and request expiry; only explicit ACK removes ciphertext', async () => {
    const f = fixture();
    const path = `/api/approval-results/${f.record.resultRef}/fetch`;
    const body = { requestId: f.record.id, bodyCid: f.record.bodyCid };
    const first = await f.service.fetch(f.record.resultRef!, body, f.proof('fetch', path));
    f.advance(2000);
    expect(await f.service.fetch(f.record.resultRef!, body, f.proof('fetch', path))).toEqual(first);
    expect(f.record.encryptedResult).toBe('{"ciphertext":"opaque"}');
    const ackPath = `/api/approval-results/${f.record.resultRef}/ack`;
    const ackBody = { ...body, ackId: 'durably-saved-ack-id-0001' };
    const ack = await f.service.acknowledge(f.record.resultRef!, ackBody, f.proof('ack', ackPath, ackBody.ackId));
    expect(await f.service.acknowledge(f.record.resultRef!, ackBody, f.proof('ack', ackPath, ackBody.ackId))).toEqual(ack);
    expect(ack).toEqual({ ackId: ackBody.ackId, status: 'acknowledged' });
    expect(f.record.encryptedResult).toBeNull();
    await expect(f.service.fetch(f.record.resultRef!, body, f.proof('fetch', path))).rejects.toMatchObject({ code: 'acknowledged' });
  });

  test('wrong signer, action, request, reference and ACK intent cannot access or consume a result', async () => {
    const f = fixture();
    const path = `/api/approval-results/${f.record.resultRef}/fetch`;
    const body = { requestId: f.record.id, bodyCid: f.record.bodyCid };
    const attacker = generateKeyPairSync('ed25519');
    await expect(f.service.fetch(f.record.resultRef!, body, f.proof('fetch', path, '', attacker.privateKey))).rejects.toMatchObject({ code: 'invalid_proof' });
    await expect(f.service.fetch(f.record.resultRef!, body, f.proof('discover', path))).rejects.toMatchObject({ code: 'invalid_proof' });
    await expect(f.service.fetch(f.record.resultRef!, { ...body, requestId: 'other' }, f.proof('fetch', path))).rejects.toMatchObject({ code: 'request_binding' });
    await expect(f.service.fetch('other', body, f.proof('fetch', path))).rejects.toMatchObject({ code: 'not_found' });
    const ackPath = `/api/approval-results/${f.record.resultRef}/ack`;
    await expect(f.service.acknowledge(f.record.resultRef!, { ...body, ackId: 'different-durable-id' }, f.proof('ack', ackPath, 'original-durable-id'))).rejects.toMatchObject({ code: 'invalid_proof' });
    expect(f.record.encryptedResult).toBe('{"ciphertext":"opaque"}');
  });

  test('retention deadline is independent and refuses fetch and ACK at its exact boundary', async () => {
    const f = fixture();
    f.advance(600_000);
    const body = { requestId: f.record.id, bodyCid: f.record.bodyCid };
    const path = `/api/approval-results/${f.record.resultRef}/fetch`;
    await expect(f.service.fetch(f.record.resultRef!, body, f.proof('fetch', path))).rejects.toMatchObject({ code: 'expired_result' });
    const ackPath = `/api/approval-results/${f.record.resultRef}/ack`;
    await expect(f.service.acknowledge(f.record.resultRef!, { ...body, ackId: 'durable-intent-0001' }, f.proof('ack', ackPath, 'durable-intent-0001'))).rejects.toMatchObject({ code: 'expired_result' });
  });
});

describe('durable approval codes use the saved request before claiming delivery', () => {
  let database: PGlite;
  let client: PrismaClient;
  beforeAll(async () => {
    database = new PGlite();
    await database.waitReady;
    for (const migration of ['20261005_0001_delegation_code_broker', '20261103_0001_delegation_code_claim']) {
      await database.exec(await readFile(new URL(`../../../../packages/db/prisma/migrations/${migration}/migration.sql`, import.meta.url), 'utf8'));
    }
    client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  });
  afterAll(async () => {
    await client.$disconnect();
    await database.close();
  });
  beforeEach(async () => {
    await client.delegationCodeClaim.deleteMany();
    await client.delegationCode.deleteMany();
  });
  const claim = 'durable-client-claim-intent-0001';
  const code = 'abcd-efgh';
  async function ready(overrides: Record<string, unknown> = {}) {
    const codeStore = createPrismaDelegationCodeStore(client);
    const f = fixture(codeStore);
    const delivery = { kind: 'approval-result', requestId: f.record.id, bodyCid: f.record.bodyCid, resultRef: f.record.resultRef,
      expiresAt: '2026-10-28T20:05:00.000Z', ...overrides };
    await codeStore.create(code, delivery, new Date(delivery.expiresAt));
    const body = { bodyCid: f.record.bodyCid, approvalCode: code.toUpperCase() };
    const proof = (intent = claim, approvalCode = code) => f.proof('discover', `/api/approval-requests/${f.record.id}/result`, '', undefined, [
      createHash('sha256').update(approvalCode.trim().toLowerCase()).digest('base64url'),
      createHash('sha256').update(intent).digest('base64url'),
    ]);
    return { ...f, signProof: f.proof, codeStore, body, proof };
  }

  async function pendingApproval(codeStore: ApprovalCodeStore, lifetime = 3600) {
    const f = fixture(codeStore);
    const now = new Date('2026-10-28T20:00:00Z');
    const relay = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const relayJwk = await crypto.subtle.exportKey('jwk', relay.publicKey);
    const jwk = f.record.request.targetPublicJwk;
    const did = strictSessionDid(jwk);
    const owner = Wallet.createRandom();
    f.record.resultRef = null;
    f.record.encryptedResult = null;
    f.record.request = { ...f.record.request, issuer: did, requestVersion: 1, targetDid: did, nodeOrigin: 'https://node.example.test',
      permissions: [{ service: 'tinycloud.kv', space: 'qa', path: '', actions: ['tinycloud.kv/get'] }],
      grantLifetimeSeconds: lifetime, resultEncryptionPublicJwk: { kty: 'EC', crv: 'P-256', x: relayJwk.x!, y: relayJwk.y! } };
    const siwe = new SiweMessage({ domain: 'openkey.example.test', address: owner.address, uri: did, version: '1', chainId: 1,
      nonce: 'qa123456', issuedAt: now.toISOString(), expirationTime: new Date(now.getTime() + lifetime * 1000).toISOString() }).prepareMessage();
    const body = { jwk, host: f.record.request.nodeOrigin, permissions: f.record.request.permissions };
    const delegation = {
      siwe, signature: await owner.signMessage(siwe), jwk, verificationMethod: did, ownerDid: `did:pkh:eip155:1:${owner.address}`,
    };
    const store: ApprovalRequestStore = {
      ...f.store,
      async approve(id, result, now) {
        if (id !== f.record.id || f.record.resultRef || f.record.expiresAt <= now) return false;
        Object.assign(f.record, result);
        return true;
      },
    };
    const service = new ApprovalResultService(store, {
      apiOrigin: 'http://localhost:3001', retentionSeconds: 600, now: () => now, codeStore,
    });
    return { ...f, service, now, body, delegation };
  }

  for (const lifetime of [90, 3600]) {
    test(`a real signed approval issues a code bounded by its ${lifetime}-second delegation and five minutes`, async () => {
      const f = await pendingApproval(createPrismaDelegationCodeStore(client), lifetime);
      const approvalCode = await f.service.approve(f.record.id, 'qa-owner', f.body, f.delegation);
      expect(approvalCode?.code).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
      const expiresAt = new Date(f.now.getTime() + Math.min(lifetime, 300) * 1000).toISOString();
      expect(approvalCode?.expiresAt).toBe(expiresAt);
      const stored = await client.delegationCode.findUniqueOrThrow({ where: { code: approvalCode!.code.toLowerCase() } });
      expect(stored.delegation).toEqual({ kind: 'approval-result', requestId: f.record.id, bodyCid: f.record.bodyCid,
        resultRef: f.record.resultRef, expiresAt });
      expect(f.record.encryptedResult).not.toBeNull();
      await expect(f.service.approve(f.record.id, 'qa-owner', f.body, f.delegation)).rejects.toMatchObject({ code: 'expired_request' });
      expect(await client.delegationCode.count()).toBe(1);
    });
  }

  test('ACK winning during code allocation suppresses the new code and removes its delivery', async () => {
    const real = createPrismaDelegationCodeStore(client);
    let resume!: () => void;
    let reached!: () => void;
    const paused = new Promise<void>(resolve => { reached = resolve; });
    const released = new Promise<void>(resolve => { resume = resolve; });
    const f = await pendingApproval({
      ...real,
      async create(...args) {
        reached();
        await released;
        return real.create(...args);
      },
    });
    const approving = f.service.approve(f.record.id, 'qa-owner', f.body, f.delegation);
    await paused;
    try {
      const path = `/api/approval-results/${f.record.resultRef}/ack`;
      const ackId = 'durable-polling-client-ack-0001';
      await f.service.acknowledge(f.record.resultRef!, { requestId: f.record.id, bodyCid: f.record.bodyCid, ackId }, f.proof('ack', path, ackId));
    } finally {
      resume();
    }
    expect(await approving).toBeNull();
    expect(await client.delegationCode.count()).toBe(0);
    expect(await client.delegationCodeClaim.count()).toBe(0);
  });

  for (const failure of ['error', 'non-error'] as const) {
    test(`allocation ${failure} logs only request identifiers and error class while returning no code`, async () => {
      let allocatedCode = '';
      const f = await pendingApproval({
        ...createPrismaDelegationCodeStore(client),
        async create(code) {
          allocatedCode = code;
          if (failure === 'non-error') throw code;
          throw Object.assign(new TypeError(`allocation-message-canary ${code}`), {
            name: code, code: 'P2010', stack: `allocation-stack-canary ${code}`,
          });
        },
      });
      const emitted: string[] = [];
      const stdoutWrite = process.stdout.write;
      let approvalCode: unknown;
      try {
        process.stdout.write = ((chunk: string | Uint8Array) => {
          emitted.push(String(chunk));
          return true;
        }) as typeof process.stdout.write;
        approvalCode = await f.service.approve(f.record.id, 'qa-owner', f.body, f.delegation);
      } finally {
        process.stdout.write = stdoutWrite;
      }
      expect(approvalCode).toBeNull();
      expect(emitted.map(line => JSON.parse(line) as Record<string, unknown>)).toEqual([{
        ts: expect.any(String),
        level: 'warn',
        event: 'approval_code_allocation_failed',
        request_id: expect.any(String),
        approval_request_id: f.record.id,
        error_name: failure === 'error' ? 'TypeError' : 'Unknown',
      }]);
      expect(emitted.join('')).not.toContain(allocatedCode);
      expect(emitted.join('')).not.toContain('allocation-message-canary');
      expect(emitted.join('')).not.toContain('allocation-stack-canary');
    });
  }

  test('an unavailable optional code broker does not prevent ordinary result fetch and durable ACK', async () => {
    const real = createPrismaDelegationCodeStore(client);
    const f = await pendingApproval({
      ...real,
      async create() { throw new Error('synthetic broker unavailable'); },
      async invalidateApproval() { throw new Error('synthetic broker unavailable'); },
    });
    expect(await f.service.approve(f.record.id, 'qa-owner', f.body, f.delegation)).toBeNull();
    const binding = { requestId: f.record.id, bodyCid: f.record.bodyCid };
    const fetchPath = `/api/approval-results/${f.record.resultRef}/fetch`;
    expect((await f.service.fetch(f.record.resultRef!, binding, f.proof('fetch', fetchPath))).resultRef).toBe(f.record.resultRef!);
    const ackPath = `/api/approval-results/${f.record.resultRef}/ack`;
    const ackId = 'durable-no-code-client-ack-0001';
    const body = { ...binding, ackId };
    expect(await f.service.acknowledge(f.record.resultRef!, body, f.proof('ack', ackPath, ackId))).toEqual({ status: 'acknowledged', ackId });
    expect(await f.service.acknowledge(f.record.resultRef!, body, f.proof('ack', ackPath, ackId))).toEqual({ status: 'acknowledged', ackId });
    expect(f.record.encryptedResult).toBeNull();
    await expect(f.service.fetch(f.record.resultRef!, binding, f.proof('fetch', fetchPath))).rejects.toMatchObject({ code: 'acknowledged' });
  });

  test('code discovery proof binds both the normalized code hash and saved claim hash', async () => {
    const f = await ready();
    const path = `/api/approval-requests/${f.record.id}/result`;
    for (const proof of [f.signProof('discover', path), f.proof(claim, 'ijkl-mnop'), f.proof('another-client-claim-intent-0002')]) {
      await expect(f.service.discover(f.record.id, f.body, proof, claim)).rejects.toMatchObject({ code: 'invalid_proof' });
      expect(await client.delegationCode.count()).toBe(1);
      expect(await client.delegationCodeClaim.count()).toBe(0);
    }
    expect((await f.service.discover(f.record.id, { ...f.body, approvalCode: ` ${code.toUpperCase()} ` }, f.proof(), claim)).status).toBe('approved');
  });

  test('cleanup failure logging keeps ACK successful and emits only safe identifiers and error class', async () => {
    const real = createPrismaDelegationCodeStore(client);
    const poisoned = Object.assign(new Error('private cleanup detail'), { name: 'not-an-allowlisted-name', code: 'P2025' });
    const f = await pendingApproval({ ...real, async invalidateApproval() { throw poisoned; } });
    await f.service.approve(f.record.id, 'qa-owner', f.body, f.delegation);
    const logs: string[] = [];
    const original = process.stdout.write;
    process.stdout.write = ((chunk: unknown) => { logs.push(String(chunk)); return true; }) as typeof process.stdout.write;
    try {
      const ackId = 'durable-cleanup-log-ack-0001';
      expect(await f.service.acknowledge(f.record.resultRef!, { requestId: f.record.id, bodyCid: f.record.bodyCid, ackId },
        f.proof('ack', `/api/approval-results/${f.record.resultRef}/ack`, ackId))).toEqual({ status: 'acknowledged', ackId });
    } finally {
      process.stdout.write = original;
    }
    const event = logs.map(line => JSON.parse(line)).find(value => value.event === 'approval_code_cleanup_failed');
    expect(event).toEqual({ ts: expect.any(String), level: 'warn', event: 'approval_code_cleanup_failed',
      request_id: expect.any(String), approval_request_id: f.record.id, error_name: 'Error' });
    expect(f.record.encryptedResult).toBeNull();
  });

  test('concurrent first code claims have one winner', async () => {
    const f = await ready();
    const results = await Promise.allSettled(Array.from({ length: 8 }, (_, index) =>
      f.service.discover(f.record.id, f.body, f.proof(`${claim}-${index}`), `${claim}-${index}`)));
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(result => result.status === 'rejected')).toHaveLength(7);
    expect(await client.delegationCodeClaim.count()).toBe(1);
  });

  test('claiming returns the existing result and retries only for the same persisted claim', async () => {
    const f = await ready();
    const first = await f.service.discover(f.record.id, f.body, f.proof(), claim);
    expect(first).toEqual({ status: 'approved', resultRef: f.record.resultRef!, expiresAt: f.record.resultExpiresAt!.toISOString() });
    expect(await client.delegationCode.count()).toBe(0);
    expect(await f.service.discover(f.record.id, f.body, f.proof(), claim)).toEqual(first);
    await expect(f.service.discover(f.record.id, f.body, f.proof('another-client-claim-intent-0002'), 'another-client-claim-intent-0002')).rejects.toMatchObject({ code: 'approval_code_unavailable' });
  });

  test('a different signer or digest does not spend the code for the saved request', async () => {
    const f = await ready();
    const wrongKey = generateKeyPairSync('ed25519');
    const path = `/api/approval-requests/${f.record.id}/result`;
    await expect(f.service.discover(f.record.id, f.body, f.signProof('discover', path, '', wrongKey.privateKey), claim)).rejects.toMatchObject({ code: 'invalid_proof' });
    await expect(f.service.discover(f.record.id, { ...f.body, bodyCid: 'another-digest' }, f.proof(), claim)).rejects.toMatchObject({ code: 'request_binding' });
    expect(await client.delegationCode.count()).toBe(1);
    expect((await f.service.discover(f.record.id, f.body, f.proof(), claim)).status).toBe('approved');
  });

  for (const [field, value] of [['requestId', 'other-request'], ['bodyCid', 'other-digest'], ['resultRef', 'other-result'], ['kind', 'other-delivery']] as const) {
    test(`a code for another ${field} is refused without consuming it`, async () => {
      const f = await ready({ [field]: value });
      await expect(f.service.discover(f.record.id, f.body, f.proof(), claim)).rejects.toMatchObject({ code: 'approval_code_unavailable' });
      expect(await client.delegationCode.count()).toBe(1);
      expect(await client.delegationCodeClaim.count()).toBe(0);
    });
  }

  test('a missing or malformed claim cannot spend the code', async () => {
    const f = await ready();
    for (const invalid of [undefined, 'short']) {
      await expect(f.service.discover(f.record.id, f.body, f.proof(), invalid)).rejects.toMatchObject({ code: 'invalid_claim' });
    }
    expect(await client.delegationCode.count()).toBe(1);
  });

  test('a code expires at five minutes even for its first claimant and a retained claim', async () => {
    const f = await ready();
    f.advance(4 * 60_000);
    await f.service.discover(f.record.id, f.body, f.proof(), claim);
    f.advance(60_000);
    await expect(f.service.discover(f.record.id, f.body, f.proof(), claim)).rejects.toMatchObject({ code: 'approval_code_unavailable' });
  });

  test('result ACK invalidates both unclaimed codes and a previously claimed delivery', async () => {
    const f = await ready();
    const second = 'ijkl-mnop';
    const row = await client.delegationCode.findUniqueOrThrow({ where: { code } });
    await f.codeStore.create(second, row.delegation, row.expiresAt);
    await f.service.discover(f.record.id, f.body, f.proof(), claim);
    const path = `/api/approval-results/${f.record.resultRef}/ack`;
    const ackId = 'durably-saved-code-ack-0001';
    await f.service.acknowledge(f.record.resultRef!, { requestId: f.record.id, bodyCid: f.record.bodyCid, ackId }, f.signProof('ack', path, ackId));
    expect(await client.delegationCode.count()).toBe(0);
    expect(await client.delegationCodeClaim.count()).toBe(0);
    await expect(f.service.discover(f.record.id, f.body, f.proof(), claim)).rejects.toMatchObject({ code: 'acknowledged' });
  });

  test('legacy code redemption cannot retrieve or spend a durable delivery', async () => {
    const f = await ready();
    const router = createDelegationCodeRouter({ store: f.codeStore, sessionMiddleware: async (_c, next) => next(), now: () => new Date('2026-10-28T20:00:00Z') });
    for (const headers of [new Headers(), new Headers({ 'OpenKey-Delegation-Claim': claim })]) {
      expect((await router.request(`/${code}`, { headers })).status).toBe(404);
      expect(await client.delegationCode.count()).toBe(1);
    }
    expect((await f.service.discover(f.record.id, f.body, f.proof(), claim)).status).toBe('approved');
  });
});
