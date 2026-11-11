// Synthetic attestation seam, executed in a separate test process.
import { mock, expect } from 'bun:test';
import { createHash, webcrypto } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256 } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { EscrowRecoverySessions, freezeEscrowHeader, recoveryPolicyId, type EscrowHeader } from '@openkey/tee';
import { splitEscrowKey, escrowKeyCommitment, recoverEscrowKey } from '../../../tee/src/escrow-shares';
import { wrapEscrowShare } from '../../../tee/src/escrow-envelope';
import vector from '../../../tee/tests/fixtures/escrow-header-v1.json';

const app = privateKeyToAccount(('0x' + '11'.padStart(64, '0')) as `0x${string}`);
const root = privateKeyToAccount(('0x' + '12'.padStart(64, '0')) as `0x${string}`);
const derived = Buffer.from(secp256k1.getPublicKey(Buffer.from('13'.padStart(64, '0'), 'hex'), true)).toString('hex');
const appId = 'a'.repeat(40), composeHash = 'b'.repeat(64);
const signature0 = (await app.sign({ hash: keccak256(Buffer.from(':' + derived)) })).slice(2);
const issued = Buffer.concat([Buffer.from('dstack-kms-issued:'), Buffer.from(appId, 'hex'), Buffer.from(secp256k1.Point.fromBytes(Buffer.from(app.publicKey.slice(2), 'hex')).toBytes(true))]);
const signature1 = (await root.sign({ hash: keccak256(issued) })).slice(2);
const evidence = { derivedPublicKey: derived, sourcePublicKey: app.publicKey, signatureChain: [signature0, signature1] };
const keys = await Promise.all([0, 1, 2].map(() => webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])));
const contentKey = crypto.getRandomValues(new Uint8Array(32));
const shares = await splitEscrowKey(contentKey);
const header: EscrowHeader = { ...vector.header as EscrowHeader, appId, composeHash, holders: await Promise.all(keys.map(async (key, i) => ({ id: 'holder-' + i, x: shares[i]![32]!, publicKey: Buffer.from(await webcrypto.subtle.exportKey('raw', key.publicKey)).toString('base64url') }))), paths: [{ ...vector.header.paths[0]!, ...evidence, transform: 'sha256-getkey' }], contentKeyCommitment: escrowKeyCommitment(contentKey, vector.header.escrowId) };
const frozen = await freezeEscrowHeader(header);
const wrappers = await Promise.all(keys.map((key, i) => wrapEscrowShare(shares[i]!, key.publicKey, { escrowId: header.escrowId, holderId: header.holders[i]!.id, x: shares[i]![32]!, headerHash: frozen.hash })));
const events = [['app-id', appId], ['compose-hash', composeHash], ['boot-mr-done', ''], ['system-ready', '']].map(([event, event_payload]) => ({ imr: 3, event_type: 0x08000001, event: event!, event_payload: event_payload!, digest: '' }));
let register: Buffer = Buffer.alloc(48);
for (const e of events) {
  const type = Buffer.alloc(4); type.writeUInt32LE(e.event_type);
  const digest = createHash('sha384').update(type).update(':' + e.event + ':').update(Buffer.from(e.event_payload, 'hex')).digest();
  register = createHash('sha384').update(register).update(digest).digest();
}
const pin = { appId, composeHash, imageDigest: header.imageDigest, codeHash: header.codeHash, kmsRootPublicKey: root.publicKey, mrTd: '01'.repeat(48), rtmr0: '02'.repeat(48), rtmr1: '03'.repeat(48), rtmr2: '04'.repeat(48) };
mock.module('../../src/trust', () => ({ SERVICE_RELEASES: [pin] }));
mock.module('../../src/recovery-trust', () => ({ RECOVERY_RELEASES: [pin] }));
let recoveryHash = '';
mock.module('@phala/dcap-qvl', () => ({ getCollateral: async () => ({}), verify: (quote: Uint8Array) => {
  const recovery = quote[0] === 1;
  const reportData = Buffer.concat([createHash('sha256').update(recovery ? 'tinycloud/escrow/recovery-quote/v1\0' : 'tinycloud/escrow/export-quote/v1\0').update(recovery ? recoveryHash : frozen.hash).digest(), Buffer.alloc(32)]);
  return { status: 'UpToDate', report: { asTd10: () => ({ reportData, mrTd: Buffer.alloc(48, 1), rtMr0: Buffer.alloc(48, 2), rtMr1: Buffer.alloc(48, 3), rtMr2: Buffer.alloc(48, 4), rtMr3: register }) } };
} }));
const targetFields = { targetAppId: appId, targetComposeHash: composeHash, targetImageDigest: header.imageDigest, targetCodeHash: header.codeHash, bootReference: 'synthetic-boot' };
const sessions = new EscrowRecoverySessions({ enabled: true, isInTee: async () => true, quote: async hash => { recoveryHash = hash; return { quote: '01', eventLog: JSON.stringify(events), reportDataSha256: hash }; } });
const session = await sessions.create(frozen.hash, { ...targetFields, newPolicyId: recoveryPolicyId(targetFields, evidence) });
const target = { descriptor: session.descriptor, targetPolicyEvidence: evidence, quote: session.quote };
const bundle = { header, wrappers, quote: { quote: '00', eventLog: JSON.stringify(events) } };
const { releaseEscrowShare } = await import('../../src/index');
const packets = await Promise.all([0, 1].map(i => releaseEscrowShare(bundle, target, header.holders[i]!.id, header.holders[i]!.publicKey, keys[i]!)));
expect(packets.every(p => Object.keys(p).sort().join(',') === 'ciphertext,descriptorHash,enc,exportHeaderHash,holderId,version,x')).toBe(true);
expect(JSON.stringify(packets)).not.toContain(Buffer.from(contentKey).toString('hex'));
await sessions.consume(session.descriptor.sessionId, session.descriptorHash, header, packets, async opened => {
  const recovered = await recoverEscrowKey(opened, header.contentKeyCommitment, header.escrowId);
  try { expect(recovered).toEqual(contentKey); } finally { recovered.fill(0); }
  return { completed: 1 };
});
await expect(releaseEscrowShare(bundle, { ...target, quote: bundle.quote }, header.holders[0]!.id, header.holders[0]!.publicKey, keys[0]!)).rejects.toThrow('binding');
for (const share of shares) share.fill(0); contentKey.fill(0);
