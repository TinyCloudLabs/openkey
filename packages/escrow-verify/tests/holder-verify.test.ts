import { expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256 } from 'viem';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { freezeEscrowHeader, type EscrowHeader } from '@openkey/tee';
import { verifyHolderBundle, PCCS_URL, type HolderPins } from '../src/internal';
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
  const pins: HolderPins = { appId, composeHash: header.composeHash, imageDigest: header.imageDigest, mrTd: td.mrTd.toString('hex'), rtmr0: td.rtMr0.toString('hex'), rtmr1: td.rtMr1.toString('hex'), rtmr2: td.rtMr2.toString('hex'), kmsRootPublicKey: root.publicKey, holderId: header.holders[0]!.id, holderPublicKey: header.holders[0]!.publicKey };
  const bundle = { header, quote: { quote: '00', eventLog: JSON.stringify(events) } };
  const dependencies = {
    getCollateral: async (url: string) => { expect(url).toBe(PCCS_URL); return {} as never; },
    verify: () => ({ status: 'UpToDate', report: { asTd10: () => td } }) as never,
  };
  expect(await verifyHolderBundle(bundle, pins, dependencies)).toBe(frozen.hash);
  for (const status of ['SWHardeningNeeded', 'OutOfDate', 'TDRelaunchAdvised', 'Revoked']) {
    await expect(verifyHolderBundle(bundle, pins, { ...dependencies, verify: () => ({ status, report: { asTd10: () => td } }) as never })).rejects.toThrow();
  }
  await expect(verifyHolderBundle(bundle, pins, { ...dependencies, getCollateral: async () => { throw new Error('Unavailable'); } })).rejects.toThrow();
  for (const patch of [{ holderPublicKey: 'different' }, { imageDigest: 'sha256:' + 'f'.repeat(64) }, { kmsRootPublicKey: app.publicKey }, { rtmr0: 'f'.repeat(96) }]) {
    await expect(verifyHolderBundle(bundle, { ...pins, ...patch }, dependencies)).rejects.toThrow();
  }
  await expect(verifyHolderBundle({ ...bundle, quote: { ...bundle.quote, eventLog: JSON.stringify(events.map((e, i) => i === 0 ? { ...e, event_payload: 'e'.repeat(40) } : e)) } }, pins, dependencies)).rejects.toThrow();
  await expect(verifyHolderBundle({ ...bundle, header: { ...header, paths: [{ ...header.paths[0]!, sourcePublicKey: root.publicKey }] } }, pins, dependencies)).rejects.toThrow();
});
