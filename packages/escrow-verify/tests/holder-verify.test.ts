import { expect, test, mock } from 'bun:test';
import { createHash } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256 } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { freezeEscrowHeader, type EscrowHeader } from '@openkey/tee';
import type { ServiceReleasePin } from '../src/trust';
import vector from '../../tee/tests/fixtures/escrow-header-v1.json';

// Synthetic DCAP seam; real signature-chain checks and event replay execute.
// It is not a passing hardware-attestation claim.
test('holder release verifies bound header, replay, pinned service and both real GetKey signatures', async () => {
  const app = privateKeyToAccount(('0x' + '01'.padStart(64, '0')) as `0x${string}`);
  const root = privateKeyToAccount(('0x' + '02'.padStart(64, '0')) as `0x${string}`);
  const derived = Buffer.from(secp256k1.getPublicKey(Buffer.from('03'.padStart(64, '0'), 'hex'), true)).toString('hex');
  const appId = 'd'.repeat(40);
  const signature0 = (await app.sign({ hash: keccak256(Buffer.from(':' + derived)) })).slice(2);
  const appCompressed = secp256k1.Point.fromBytes(Buffer.from(app.publicKey.slice(2), 'hex')).toBytes(true);
  const signature1 = (await root.sign({ hash: keccak256(Buffer.concat([Buffer.from('dstack-kms-issued:'), Buffer.from(appId, 'hex'), Buffer.from(appCompressed)])) })).slice(2);
  const header: EscrowHeader = { ...vector.header as EscrowHeader, appId, paths: [{ ...vector.header.paths[0]!, purpose: 'business-label-not-signed', transform: 'sha256-getkey', derivedPublicKey: derived, sourcePublicKey: app.publicKey, signatureChain: [signature0, signature1] }] };
  const frozen = await freezeEscrowHeader(header);
  const events = [['app-id', appId], ['compose-hash', header.composeHash], ['boot-mr-done', ''], ['system-ready', '']].map(([event, event_payload]) => ({ imr: 3, event_type: 0x08000001, event: event!, event_payload: event_payload!, digest: '' }));
  let register: Buffer = Buffer.alloc(48);
  for (const e of events) {
    const type = Buffer.alloc(4); type.writeUInt32LE(e.event_type);
    const digest = createHash('sha384').update(Buffer.concat([type, Buffer.from(':' + e.event + ':'), Buffer.from(e.event_payload, 'hex')])).digest();
    register = createHash('sha384').update(register).update(digest).digest();
  }
  const reportData = Buffer.concat([createHash('sha256').update('tinycloud/escrow/export-quote/v1\0').update(frozen.hash).digest(), Buffer.alloc(32)]);
  const td = { reportData, mrTd: Buffer.alloc(48, 1), rtMr0: Buffer.alloc(48, 2), rtMr1: Buffer.alloc(48, 3), rtMr2: Buffer.alloc(48, 4), rtMr3: register };
  const pins = { appId, composeHash: header.composeHash, imageDigest: header.imageDigest, mrTd: td.mrTd.toString('hex'), rtmr0: td.rtMr0.toString('hex'), rtmr1: td.rtMr1.toString('hex'), rtmr2: td.rtMr2.toString('hex'), kmsRootPublicKey: root.publicKey, holderId: header.holders[0]!.id, holderPublicKey: header.holders[0]!.publicKey };
  mock.module('../src/trust', () => ({ KMS_ROOT_PUBLIC_KEY: root.publicKey, SERVICE_RELEASES: [pins as ServiceReleasePin] }));
  const { verifyHolderBundle, PCCS_URL } = await import('../src/internal');
  const bundle = { header, quote: { quote: '00', eventLog: JSON.stringify(events) } };
  const dependencies = {
    getCollateral: async (url: string) => { expect(url).toBe(PCCS_URL); return {} as never; },
    verify: () => ({ status: 'UpToDate', report: { asTd10: () => td } }) as never,
  };
  expect(await verifyHolderBundle(bundle, pins.holderId, pins.holderPublicKey, dependencies)).toBe(frozen.hash);
  for (const status of ['SWHardeningNeeded', 'OutOfDate', 'TDRelaunchAdvised', 'Revoked']) {
    await expect(verifyHolderBundle(bundle, pins.holderId, pins.holderPublicKey, { ...dependencies, verify: () => ({ status, report: { asTd10: () => td } }) as never })).rejects.toThrow();
  }
  await expect(verifyHolderBundle(bundle, pins.holderId, pins.holderPublicKey, { ...dependencies, getCollateral: async () => { throw new Error('Unavailable'); } })).rejects.toThrow();
  await expect(verifyHolderBundle(bundle, pins.holderId, 'different', dependencies)).rejects.toThrow();
  await expect(verifyHolderBundle(bundle, pins.holderId, pins.holderPublicKey, { ...dependencies, verify: () => ({ status: 'UpToDate', report: { asTd10: () => ({ ...td, rtMr0: Buffer.alloc(48, 9) }) } }) as never })).rejects.toThrow();
  await expect(verifyHolderBundle({ ...bundle, quote: { ...bundle.quote, eventLog: JSON.stringify(events.map((e, i) => i === 0 ? { ...e, event_payload: 'e'.repeat(40) } : e)) } }, pins.holderId, pins.holderPublicKey, dependencies)).rejects.toThrow();
  await expect(verifyHolderBundle({ ...bundle, header: { ...header, paths: [{ ...header.paths[0]!, sourcePublicKey: root.publicKey }] } }, pins.holderId, pins.holderPublicKey, dependencies)).rejects.toThrow();
  const futureHeader = { ...header, createdAt: new Date(Date.now() + 600_000).toISOString(), expiresAt: new Date(Date.now() + 900_000).toISOString() };
  await expect(verifyHolderBundle({ ...bundle, header: futureHeader }, pins.holderId, pins.holderPublicKey, dependencies)).rejects.toThrow('future');
  await expect(verifyHolderBundle({ ...bundle, quote: { ...bundle.quote, eventLog: JSON.stringify(events.map(e => ({ ...e, version: 2 }))) } }, pins.holderId, pins.holderPublicKey, dependencies)).rejects.toThrow('version');
  const wrongChain = { ...header, paths: [{ ...header.paths[0]!, signatureChain: [signature0, signature0] }] };
  const wrongHash = (await freezeEscrowHeader(wrongChain)).hash;
  const wrongReportData = Buffer.concat([createHash('sha256').update('tinycloud/escrow/export-quote/v1\0').update(wrongHash).digest(), Buffer.alloc(32)]);
  await expect(verifyHolderBundle({ ...bundle, header: wrongChain }, pins.holderId, pins.holderPublicKey, { ...dependencies, verify: () => ({ status: 'UpToDate', report: { asTd10: () => ({ ...td, reportData: wrongReportData }) } }) as never })).rejects.toThrow('KMS');
  const replacement = { ...header, imageDigest: 'sha256:' + 'f'.repeat(64) };
  const replacementHash = (await freezeEscrowHeader(replacement)).hash;
  const replacementData = Buffer.concat([createHash('sha256').update('tinycloud/escrow/export-quote/v1\0').update(replacementHash).digest(), Buffer.alloc(32)]);
  await expect(verifyHolderBundle({ ...bundle, header: replacement }, pins.holderId, pins.holderPublicKey, { ...dependencies, verify: () => ({ status: 'UpToDate', report: { asTd10: () => ({ ...td, reportData: replacementData }) } }) as never })).rejects.toThrow('identity');
  const historical = { ...header, createdAt: new Date(Date.now() - 172800000).toISOString(), expiresAt: new Date(Date.now() - 86400000).toISOString() };
  const historicalHash = (await freezeEscrowHeader(historical)).hash;
  const historicalData = Buffer.concat([createHash('sha256').update('tinycloud/escrow/export-quote/v1\0').update(historicalHash).digest(), Buffer.alloc(32)]);
  expect(await verifyHolderBundle({ ...bundle, header: historical }, pins.holderId, pins.holderPublicKey, { ...dependencies, verify: () => ({ status: 'UpToDate', report: { asTd10: () => ({ ...td, reportData: historicalData }) } }) as never })).toBe(historicalHash);
  // The actual shipped module runs in a clean subprocess, without this test-only trust mock.
  const script = `import { verifyEscrowForHolder } from ${JSON.stringify(new URL('../src/index.ts', import.meta.url).pathname)};
try { await verifyEscrowForHolder(${JSON.stringify(bundle)}, ${JSON.stringify(pins.holderId)}, ${JSON.stringify(pins.holderPublicKey)}); process.exit(2); } catch(e) { if(e.message !== 'Escrow verifier trust not configured') process.exit(3); }`;
  const child = Bun.spawn([process.execPath, '-e', script], { env: {}, stdout: 'pipe', stderr: 'pipe' });
  expect(await child.exited).toBe(0);

});
