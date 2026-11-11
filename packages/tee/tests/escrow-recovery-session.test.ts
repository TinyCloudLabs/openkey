import { expect, test, setSystemTime } from 'bun:test';
import { EscrowRecoverySessions, freezeRecoveryDescriptor, wrapRecoveryShare } from '../src/escrow-recovery-session';
import { splitEscrowKey, escrowKeyCommitment, recoverEscrowKey } from '../src/escrow-shares';
import { freezeEscrowHeader, type EscrowHeader } from '../src/escrow-header';
import vector from './fixtures/escrow-header-v1.json';

test('recovery ingress is nonce-bound, exactly two holders, single-use and clears opened shares', async () => {
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  const shares = await splitEscrowKey(contentKey);
  const base = vector.header as EscrowHeader;
  const header: EscrowHeader = { ...base, contentKeyCommitment: escrowKeyCommitment(contentKey, base.escrowId), holders: base.holders.map((holder, i) => ({ ...holder, x: shares[i]![32]! })) };
  const frozen = await freezeEscrowHeader(header);
  const target = { targetAppId: 'a'.repeat(40), targetComposeHash: 'b'.repeat(64), targetImageDigest: 'sha256:' + 'c'.repeat(64), targetCodeHash: 'd'.repeat(64), bootReference: 'synthetic-boot', newPolicyId: 'e'.repeat(64) };
  const options = { enabled: true, isInTee: async () => true, quote: async (hash: string) => ({ quote: 'synthetic', eventLog: '[]', reportDataSha256: hash }) };
  await expect(new EscrowRecoverySessions({ ...options, enabled: false }).create(frozen.hash, target)).rejects.toThrow();
  await expect(new EscrowRecoverySessions({ ...options, isInTee: async () => false }).create(frozen.hash, target)).rejects.toThrow();
  const manager = new EscrowRecoverySessions(options);
  const session = await manager.create(frozen.hash, target);
  expect((await freezeRecoveryDescriptor(session.descriptor)).descriptorHash).toBe(session.descriptorHash);
  expect(Date.parse(session.descriptor.expiresAt) - Date.parse(session.descriptor.createdAt)).toBe(3600000);
  const packets = await Promise.all([0, 1].map(i => wrapRecoveryShare(shares[i]!, session.descriptor, base.holders[i]!.id, shares[i]![32]!)));
  await expect(wrapRecoveryShare(shares[0]!, session.descriptor, base.holders[0]!.id, shares[1]![32]!)).rejects.toThrow();
  await expect(manager.consume(session.descriptor.sessionId, session.descriptorHash, header, [packets[0]!, packets[0]!], async () => ({ completed: 1 }))).rejects.toThrow();
  const junk = structuredClone(packets);
  junk[0]!.ciphertext = Buffer.alloc(49).toString('base64url');
  await expect(manager.consume(session.descriptor.sessionId, session.descriptorHash, header, junk, async () => ({ completed: 1 }))).rejects.toThrow();
  let references: readonly Uint8Array[] = [];
  let restores = 0;
  const restore = async (opened: readonly Uint8Array[]) => {
    restores++; references = opened;
    const recovered = await recoverEscrowKey(opened, header.contentKeyCommitment, header.escrowId);
    expect(recovered).toEqual(contentKey); recovered.fill(0);
    return { completed: 1, secret: 'LEAK' };
  };
  const attempts = await Promise.allSettled([manager.consume(session.descriptor.sessionId, session.descriptorHash, header, packets, restore), manager.consume(session.descriptor.sessionId, session.descriptorHash, header, packets, restore)]);
  expect(attempts.filter(result => result.status === 'fulfilled').length).toBe(1);
  expect(restores).toBe(1);
  expect(references.every(share => share.every(byte => byte === 0))).toBe(true);
  const success = attempts.find(result => result.status === 'fulfilled')!;
  if (success.status === 'fulfilled') expect(JSON.stringify(success.value)).not.toContain('LEAK');
  await expect(manager.consume(session.descriptor.sessionId, session.descriptorHash, header, packets, restore)).rejects.toThrow();
  const failed = await manager.create(frozen.hash, target);
  const failedPackets = await Promise.all([0, 1].map(i => wrapRecoveryShare(shares[i]!, failed.descriptor, base.holders[i]!.id, shares[i]![32]!)));
  let failedReferences: readonly Uint8Array[] = [];
  await expect(manager.consume(failed.descriptor.sessionId, failed.descriptorHash, header, failedPackets, async opened => { failedReferences = opened; throw new Error('import failed'); })).rejects.toThrow();
  expect(failedReferences.length).toBe(2);
  expect(failedReferences.every(share => share.every(byte => byte === 0))).toBe(true);
  const expired = await manager.create(frozen.hash, target);
  try {
    setSystemTime(new Date(Date.parse(expired.descriptor.expiresAt) + 1));
    await expect(manager.consume(expired.descriptor.sessionId, expired.descriptorHash, header, packets, restore)).rejects.toThrow();
  } finally { setSystemTime(); }
  await expect(freezeRecoveryDescriptor({ ...session.descriptor, expiresAt: new Date(Date.parse(session.descriptor.createdAt) + 3600001).toISOString() })).rejects.toThrow();
});
