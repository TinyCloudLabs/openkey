import { test, expect } from 'bun:test';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { buildReviewSnapshot, reviewDecisionDomain, reviewJcs, signResourceReviewDecision, validateDependencyObservation, type ResourceDependencyObservation } from './account-deletion-decision';
const resource = 'urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
const snapshot = { configured: [{ hostId: 'node-a', url: 'https://a.test' }], recorded: ['https://a.test'], uncertain: false };
const observation: ResourceDependencyObservation = { hostId: 'node-a', ownerHmac: 'a'.repeat(64), dependentResourceCount: 1, resourceHmacs: ['b'.repeat(64)], targets: [{ resourceId: resource, targetResourceHmac: 'b'.repeat(64), dependentCount: 1, dependencyFingerprint: 'c'.repeat(64), fingerprintKeyId: 'fp-1' }] };
const input = () => { const now = Math.floor(Date.now() / 1000); return { decisionId: crypto.randomUUID(), jobId: crypto.randomUUID(), hostId: 'node-a', resourceId: resource, disposition: 'proceed' as const, decisionMaker: 'Naomi', decidedAt: now, expiresAt: now + 172800, reason: 'Reviewed "recipient" \\ café e\u0301 😀 \u2028' }; };

test('JCS decision signature binds exact paired HMAC without raw identifiers', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const proof = await signResourceReviewDecision(input(), snapshot, [observation], { writerId: 'openkey-review', keyId: 'test-1', sign: async bytes => sign(null, bytes, privateKey) });
  expect(verify(null, Buffer.from(reviewDecisionDomain + reviewJcs(proof.payload)), publicKey, Buffer.from(proof.signature, 'base64url'))).toBe(true);
  expect(proof.payload[7]).toBe(observation.targets[0]!.targetResourceHmac);
  expect(JSON.stringify(proof)).not.toContain(resource);
  expect(JSON.stringify(proof)).not.toContain('resourceId');
  expect(reviewJcs([0, Number.MAX_SAFE_INTEGER])).toBe('[0,9007199254740991]');
  expect(reviewJcs(['é'])).not.toBe(reviewJcs(['e\u0301']));
  expect(reviewJcs(['\u2028'])).toBe('["\u2028"]');
});

test('missing key, incomplete hosts, bad pair, unsafe numbers and invalid Unicode fail closed', async () => {
  const signer = { writerId: 'openkey-review', keyId: 'test-1', sign: async () => new Uint8Array(64) };
  await expect(signResourceReviewDecision(input(), snapshot, [observation])).rejects.toThrow();
  await expect(signResourceReviewDecision({ ...input(), resourceId: `${resource}/other` }, snapshot, [observation], signer)).rejects.toThrow();
  expect(() => buildReviewSnapshot(snapshot, [])).toThrow();
  expect(() => validateDependencyObservation({ ...observation, targets: [] }, [resource])).toThrow();
  expect(() => validateDependencyObservation({ ...observation, dependentResourceCount: 0 }, [resource])).toThrow();
  expect(() => validateDependencyObservation({ ...observation, dependentResourceCount: Number.MAX_SAFE_INTEGER + 1 }, [resource])).toThrow();
  expect(() => validateDependencyObservation({ ...observation, dependentResourceCount: 0.5 }, [resource])).toThrow();
  expect(() => reviewJcs(['\ud800'])).toThrow();
  expect(() => reviewJcs([Infinity])).toThrow();
  await expect(signResourceReviewDecision({ ...input(), reason: '\ud800' }, snapshot, [observation], signer)).rejects.toThrow();
  const decision = input();
  await expect(signResourceReviewDecision({ ...decision, expiresAt: decision.decidedAt + 172801 }, snapshot, [observation], signer)).rejects.toThrow();
});

test('shared public vectors preserve exact JCS bytes and Ed25519 signatures', async () => {
  const fixture = await Bun.file(new URL('./fixtures/account-deletion-decision-jcs.json', import.meta.url)).json();
  for (const vector of fixture.vectors) {
    expect(reviewJcs(vector.proof.payload)).toBe(vector.payloadJcs);
    expect(reviewJcs([1, vector.proof.payload[13]])).toBe(vector.snapshotJcs);
    expect(verify(null, Buffer.from(reviewDecisionDomain + reviewJcs(vector.proof.payload)), fixture.publicKeySpkiPem, Buffer.from(vector.proof.signature, 'base64url'))).toBe(true);
  }
  expect(fixture.vectors[1].payloadJcs).not.toBe(fixture.vectors[2].payloadJcs);
});


test('Rust-signed public vectors verify with identical TypeScript canonical bytes', async () => {
  const fixture = await Bun.file(new URL('./fixtures/account-deletion-decision-jcs-rust.json', import.meta.url)).json();
  for (const vector of fixture.vectors) {
    expect(reviewJcs(vector.proof.payload)).toBe(vector.payloadJcs);
    expect(reviewJcs([1, vector.proof.payload[13]])).toBe(vector.snapshotJcs);
    expect(verify(null, Buffer.from(reviewDecisionDomain + reviewJcs(vector.proof.payload)), fixture.publicKeySpkiPem, Buffer.from(vector.proof.signature, 'base64url'))).toBe(true);
  }
});

test('deadline signing cannot run early, use caller time, reissue or bypass revocation', async () => {
  const { signDeadlineReviewDecisions } = await import('./account-deletion-decision');
  const { privateKey } = generateKeyPairSync('ed25519');
  const jobId = crypto.randomUUID();
  const requestedAt = 1_700_000_000;
  let now = requestedAt + 604799;
  let claimed = false;
  let revoked = false;
  let claims = 0;
  const authority = {
    writerId: 'review-test', keyId: 'key-1',
    sign: async (bytes: Uint8Array) => sign(null, bytes, privateKey),
    verifiedRequest: async () => ({ jobId, requestId: jobId, requestedAt, hosts: snapshot, ownerHmacs: { 'node-a': observation.ownerHmac } }), teeNow: async () => now,
    deadlineRevoked: async () => revoked,
    claimDeadline: async () => { claims += 1; if (claimed) return false; claimed = true; return true; },
  };
  await expect(signResourceReviewDecision({ ...input(), decisionMaker: 'deadline' }, snapshot, [observation], authority)).rejects.toThrow();
  await expect(signDeadlineReviewDecisions(jobId, snapshot, [observation], authority)).rejects.toThrow();
  expect(claims).toBe(0);
  now += 1;
  await expect(signDeadlineReviewDecisions(jobId, snapshot, [{ ...observation, ownerHmac: 'f'.repeat(64) }], authority)).rejects.toThrow('scope mismatch');
  expect(claims).toBe(0);
  const proofs = await signDeadlineReviewDecisions(jobId, snapshot, [observation], authority);
  expect(proofs).toHaveLength(1);
  expect(proofs[0]!.payload[9]).toBe('deadline');
  expect(proofs[0]!.payload[10]).toBe(now);
  await expect(signDeadlineReviewDecisions(jobId, snapshot, [observation], authority)).rejects.toThrow();
  revoked = true;
  await expect(signDeadlineReviewDecisions(jobId, snapshot, [observation], authority)).rejects.toThrow('revoked');
  expect(claims).toBe(2);
});

test('reviewed target fingerprints remain exact while unrelated resource changes do not invalidate authority', async () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const signer = { writerId: 'review-test', keyId: 'key-1', sign: async (bytes: Uint8Array) => sign(null, bytes, privateKey) };
  const reviewedSnapshot = buildReviewSnapshot(snapshot, [observation]);
  const current = { ...observation, dependentResourceCount: 2, resourceHmacs: ['b'.repeat(64), 'd'.repeat(64)], targets: [...observation.targets, { resourceId: resource.replace(':default', ':archive'), targetResourceHmac: 'd'.repeat(64), dependentCount: 1, dependencyFingerprint: 'e'.repeat(64), fingerprintKeyId: 'fp-1' }] };
  const proof = await signResourceReviewDecision({ ...input(), reviewedSnapshot }, snapshot, [current], signer);
  expect(proof.payload[13]).toEqual(reviewedSnapshot);
  const changed = { ...current, targets: [{ ...current.targets[0]!, dependencyFingerprint: 'f'.repeat(64) }, current.targets[1]!] };
  await expect(signResourceReviewDecision({ ...input(), reviewedSnapshot }, snapshot, [changed], signer)).rejects.toThrow('snapshot changed');
});
