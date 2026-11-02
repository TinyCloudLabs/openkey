import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { ApprovalResultService, type ApprovalRequestRecord, type ApprovalRequestStore } from '../services/approval-results';

// The production adapter uses compare-and-set writes; this isolated store keeps
// those same transitions so failure/retry tests don't depend on a live account.
function fixture() {
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
    async approve() { throw new Error('not used in read/ACK regression'); },
    async acknowledge(ref, ackId, now) {
      if (ref !== record.resultRef || record.resultExpiresAt! <= now || (record.ackId && record.ackId !== ackId)) return null;
      record.ackId = ackId; record.acknowledgedAt ??= now; record.encryptedResult = null;
      return record;
    },
  };
  const origin = 'http://localhost:3001';
  const service = new ApprovalResultService(store, { apiOrigin: origin, retentionSeconds: 600, now: () => clock });
  function proof(action: 'discover' | 'fetch' | 'ack', path: string, ackId = '', key = pair.privateKey) {
    const jkt = createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })).digest('base64url');
    const head = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: jkt, typ: 'openkey-session-proof+jwt' })).toString('base64url');
    const credential = JSON.stringify([action, record.id, record.bodyCid, action === 'discover' ? '' : record.resultRef, ackId]);
    const claims = Buffer.from(JSON.stringify({ client_id: 'openkey-approval-result-v1', cred_hash: createHash('sha256').update(credential).digest('base64url'), htm: 'POST', htu: origin + path, iat: clock.getTime() / 1000, jti: 'isolated-synthetic-jti-0001' })).toString('base64url');
    return `${head}.${claims}.${sign(null, Buffer.from(`${head}.${claims}`), key).toString('base64url')}`;
  }
  return { service, record, proof, advance(ms: number) { clock = new Date(clock.getTime() + ms); } };
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
