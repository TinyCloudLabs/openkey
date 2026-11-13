import { expect, test, mock } from 'bun:test';
import { createHash, webcrypto, randomBytes } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256 } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { freezeRecoveryDescriptor, recoveryPolicyId, type RecoveryDescriptor } from '@openkey/tee';

test('recovery release binds the selected release, recovery quote domain and both target key signatures', async () => {
  const app = privateKeyToAccount(('0x' + '04'.padStart(64, '0')) as `0x${string}`);
  const root = privateKeyToAccount(('0x' + '05'.padStart(64, '0')) as `0x${string}`);
  const derivedPublicKey = Buffer.from(secp256k1.getPublicKey(Buffer.from('06'.padStart(64, '0'), 'hex'), true)).toString('hex');
  const targetAppId = 'a'.repeat(40), targetComposeHash = 'b'.repeat(64);
  const signature0 = (await app.sign({ hash: keccak256(Buffer.from(':' + derivedPublicKey)) })).slice(2);
  const issued = Buffer.concat([Buffer.from('dstack-kms-issued:'), Buffer.from(targetAppId, 'hex'), Buffer.from(secp256k1.Point.fromBytes(Buffer.from(app.publicKey.slice(2), 'hex')).toBytes(true))]);
  const signature1 = (await root.sign({ hash: keccak256(issued) })).slice(2);
  const targetPolicyEvidence = { derivedPublicKey, sourcePublicKey: app.publicKey, signatureChain: [signature0, signature1] };
  const keys = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const now = Date.now();
  const descriptor: RecoveryDescriptor = { version: 1, exportHeaderHash: '1'.repeat(64), recipientPublicKey: Buffer.from(await webcrypto.subtle.exportKey('raw', keys.publicKey)).toString('base64url'), nonce: randomBytes(32).toString('base64url'), sessionId: randomBytes(16).toString('base64url'), targetAppId, targetComposeHash, targetImageDigest: 'sha256:' + 'c'.repeat(64), targetCodeHash: 'd'.repeat(64), bootReference: 'synthetic-boot', newPolicyId: '', createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 3600000).toISOString() };
  descriptor.newPolicyId = recoveryPolicyId(descriptor, targetPolicyEvidence);
  const events = [['app-id', targetAppId], ['compose-hash', targetComposeHash], ['boot-mr-done', ''], ['system-ready', '']].map(([event, event_payload]) => ({ imr: 3, event_type: 0x08000001, event: event!, event_payload: event_payload!, digest: '' }));
  let register: Buffer = Buffer.alloc(48);
  for (const event of events) {
    const type = Buffer.alloc(4); type.writeUInt32LE(event.event_type);
    const digest = createHash('sha384').update(type).update(':' + event.event + ':').update(Buffer.from(event.event_payload, 'hex')).digest();
    register = createHash('sha384').update(register).update(digest).digest();
  }
  const pin = { appId: targetAppId, composeHash: targetComposeHash, imageDigest: descriptor.targetImageDigest, codeHash: descriptor.targetCodeHash, kmsRootPublicKey: root.publicKey, mrTd: '01'.repeat(48), rtmr0: '02'.repeat(48), rtmr1: '03'.repeat(48), rtmr2: '04'.repeat(48) };
  mock.module('../src/recovery-trust', () => ({ RECOVERY_RELEASES: [pin] }));
  const { verifyRecoveryTarget } = await import('../src/recovery');
  const makeDependencies = async (d: RecoveryDescriptor, domain = 'tinycloud/escrow/recovery-quote/v1\0') => {
    const { descriptorHash } = await freezeRecoveryDescriptor(d);
    const td = { reportData: Buffer.concat([createHash('sha256').update(domain).update(descriptorHash).digest(), Buffer.alloc(32)]), mrTd: Buffer.alloc(48, 1), rtMr0: Buffer.alloc(48, 2), rtMr1: Buffer.alloc(48, 3), rtMr2: Buffer.alloc(48, 4), rtMr3: register };
    return { getCollateral: async (url: string) => { expect(url).toBe('https://pccs.phala.network'); return {} as never; }, verify: () => ({ status: 'UpToDate', report: { asTd10: () => td } }) as never };
  };
  const target = { descriptor, targetPolicyEvidence, quote: { quote: '00', eventLog: JSON.stringify(events) } };
  const dependencies = await makeDependencies(descriptor);
  expect(await verifyRecoveryTarget(target, descriptor.exportHeaderHash, dependencies)).toBe((await freezeRecoveryDescriptor(descriptor)).descriptorHash);
  await expect(verifyRecoveryTarget(target, '2'.repeat(64), dependencies)).rejects.toThrow('export');
  await expect(verifyRecoveryTarget(target, descriptor.exportHeaderHash, await makeDependencies(descriptor, 'tinycloud/escrow/export-quote/v1\0'))).rejects.toThrow('binding');
  const altered = { ...descriptor, newPolicyId: '0'.repeat(64) };
  await expect(verifyRecoveryTarget({ ...target, descriptor: altered }, descriptor.exportHeaderHash, await makeDependencies(altered))).rejects.toThrow('policy');
  const swapped = { ...targetPolicyEvidence, sourcePublicKey: root.publicKey };
  const swappedDescriptor = { ...descriptor, newPolicyId: recoveryPolicyId(descriptor, swapped) };
  await expect(verifyRecoveryTarget({ ...target, descriptor: swappedDescriptor, targetPolicyEvidence: swapped }, descriptor.exportHeaderHash, await makeDependencies(swappedDescriptor))).rejects.toThrow('source');
  const wrongRoot = privateKeyToAccount(('0x' + '07'.padStart(64, '0')) as `0x${string}`);
  const foreignEvidence = { ...targetPolicyEvidence, signatureChain: [signature0, (await wrongRoot.sign({ hash: keccak256(issued) })).slice(2)] };
  await expect(verifyRecoveryTarget({ ...target, targetPolicyEvidence: foreignEvidence }, descriptor.exportHeaderHash, dependencies)).rejects.toThrow('KMS');
  for (const field of ['targetAppId', 'targetImageDigest', 'targetCodeHash'] as const) {
    const replacement = { ...descriptor, [field]: field === 'targetAppId' ? 'f'.repeat(40) : field === 'targetImageDigest' ? 'sha256:' + 'f'.repeat(64) : 'f'.repeat(64) };
    await expect(verifyRecoveryTarget({ ...target, descriptor: replacement }, descriptor.exportHeaderHash, await makeDependencies(replacement))).rejects.toThrow('identity');
  }
  await expect(verifyRecoveryTarget(target, descriptor.exportHeaderHash, { ...dependencies, verify: () => ({ status: 'SWHardeningNeeded' }) as never })).rejects.toThrow('TCB');
  const future = { ...descriptor, createdAt: new Date(now + 600000).toISOString(), expiresAt: new Date(now + 3600000).toISOString() };
  await expect(verifyRecoveryTarget({ ...target, descriptor: future }, descriptor.exportHeaderHash, await makeDependencies(future))).rejects.toThrow('time');
  const script = `import { verifyRecoveryForHolder } from ${JSON.stringify(new URL('../src/index.ts', import.meta.url).pathname)}; try { await verifyRecoveryForHolder(${JSON.stringify(target)}, ${JSON.stringify(descriptor.exportHeaderHash)}); process.exit(2); } catch(e) { if(e.message !== 'Recovery verifier trust not configured') process.exit(3); }`;
  const child = Bun.spawn([process.execPath, '-e', script], { env: {}, stdout: 'pipe', stderr: 'pipe' });
  expect(await child.exited).toBe(0);
});
