import { createHash } from 'node:crypto';
import { freezeEscrowHeader, type EscrowHeader } from '@openkey/tee';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256, recoverPublicKey } from 'viem';
import { KMS_ROOT_PUBLIC_KEY, SERVICE_RELEASES } from './trust';
import type { getCollateral, verify } from '@phala/dcap-qvl';

export const GETKEY_SIGNED_PURPOSE = '';
export const PCCS_URL = 'https://pccs.phala.network';
export interface HolderBundle { header: EscrowHeader; quote: { quote: string; eventLog: string } }
type Event = { imr: number; event_type: number; event: string; event_payload: string; digest: string; version?: number; preimage?: string };
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');
function compressed(value: string): string {
  if (typeof value !== 'string' || !/^(?:0x)?(?:[a-f0-9]{66}|[a-f0-9]{130})$/.test(value)) throw new Error('Invalid source public key');
  return hex(secp256k1.Point.fromBytes(Buffer.from(value.replace(/^0x/, ''), 'hex')).toBytes(true));
}
function replay(log: Event[]): { register: string; appId: string; composeHash: string } {
  if (!Array.isArray(log) || log.length === 0 || log.length > 100_000) throw new Error('Invalid event log');
  let register: Buffer = Buffer.alloc(48);
  const names = new Map<string, { index: number; payload: string }[]>();
  for (const [index, e] of log.entries()) {
    if (!e || !Number.isInteger(e.imr) || e.imr < 0 || e.imr > 3) throw new Error('Invalid event register');
    if (e.imr !== 3) continue;
    if (e.event_type !== 0x08000001 || typeof e.event !== 'string' || !/^(?:[a-fA-F0-9]{2})*$/.test(e.event_payload)) throw new Error('Invalid runtime event');
    const payload = Buffer.from(e.event_payload, 'hex');
    let preimage: Buffer;
    if ((e.version ?? 1) === 1) {
      const type = Buffer.alloc(4); type.writeUInt32LE(0x08000001);
      preimage = Buffer.concat([type, Buffer.from(':' + e.event + ':'), payload]);
    } else throw new Error('Unsupported event version');
    const digest = createHash('sha384').update(preimage).digest();
    if (e.digest !== '' && e.digest !== hex(digest)) throw new Error('Invalid event digest');
    register = createHash('sha384').update(register).update(digest).digest();
    names.set(e.event, [...(names.get(e.event) ?? []), { index, payload: hex(payload) }]);
  }
  const one = (name: string) => { const entries = names.get(name); if (entries?.length !== 1) throw new Error('Invalid boot bindings'); return entries[0]!; };
  const app = one('app-id'), compose = one('compose-hash'), boot = one('boot-mr-done'), ready = one('system-ready');
  if (app.index >= boot.index || compose.index >= boot.index || ready.index <= boot.index) throw new Error('Invalid boot order');
  return { register: hex(register), appId: app.payload, composeHash: compose.payload };
}

/** Test seam is not exposed from the package entry point. */
export async function verifyHolderBundle(bundle: HolderBundle, holderId: string, holderPublicKey: string, dependencies: { getCollateral: typeof getCollateral; verify: typeof verify }): Promise<string> {
  if (KMS_ROOT_PUBLIC_KEY === null) throw new Error('Escrow verifier trust not configured');
  // Copy before any network await so caller mutation cannot change the decision.
  const input = structuredClone(bundle);
  const candidates = SERVICE_RELEASES.filter(pin => pin.composeHash === input.header.composeHash);
  if (candidates.length !== 1) throw new Error('Escrow release not configured');
  const trusted = candidates[0]!;
  const frozen = await freezeEscrowHeader(input.header);
  if (!/^[a-f0-9]{40}$/.test(trusted.appId) || !/^[a-f0-9]{64}$/.test(trusted.composeHash)
    || !/^sha256:[a-f0-9]{64}$/.test(trusted.imageDigest)) throw new Error('Invalid service pins');
  for (const value of [trusted.mrTd, trusted.rtmr0, trusted.rtmr1, trusted.rtmr2]) {
    if (!/^[a-f0-9]{96}$/.test(value) || /^0+$/.test(value)) throw new Error('Invalid measurement pin');
  }
  if (Date.parse(frozen.header.createdAt) > Date.now() + 300_000) throw new Error('Escrow creation time is in the future');
  const root = compressed(KMS_ROOT_PUBLIC_KEY);
  if (typeof input.quote.quote !== 'string' || !/^(?:[a-f0-9]{2})+$/.test(input.quote.quote)) throw new Error('Invalid quote encoding');
  const quote = Buffer.from(input.quote.quote, 'hex');
  const collateral = await dependencies.getCollateral(PCCS_URL, quote);
  const verified = dependencies.verify(quote, collateral, Math.floor(Date.now() / 1000));
  if (verified.status !== 'UpToDate') throw new Error('Unacceptable TCB status');
  const td = verified.report.asTd10(); if (!td) throw new Error('Not a TDX quote');
  const digest = createHash('sha256').update('tinycloud/escrow/export-quote/v1\0').update(frozen.hash).digest();
  if (hex(td.reportData) !== hex(Buffer.concat([digest, Buffer.alloc(32)]))) throw new Error('Quote header mismatch');
  const measured = replay(JSON.parse(input.quote.eventLog));
  if (hex(td.rtMr3) !== measured.register) throw new Error('Event replay mismatch');
  if (measured.appId !== frozen.header.appId || measured.appId !== trusted.appId
    || measured.composeHash !== frozen.header.composeHash || measured.composeHash !== trusted.composeHash
    || frozen.header.imageDigest !== trusted.imageDigest) throw new Error('Service identity mismatch');
  for (const [field, pin] of [['mrTd', 'mrTd'], ['rtMr0', 'rtmr0'], ['rtMr1', 'rtmr1'], ['rtMr2', 'rtmr2']] as const) {
    if (hex(td[field]) !== trusted[pin]) throw new Error('Measurement mismatch');
  }
  for (const path of frozen.header.paths) {
    if (path.signatureChain.length !== 2 || path.signatureChain.some(s => !/^[a-f0-9]{130}$/.test(s))) throw new Error('Invalid GetKey chain');
    // The guest-api-v0 purpose is exactly empty, independent of service inventory labels.
    const app = await recoverPublicKey({ hash: keccak256(Buffer.from(GETKEY_SIGNED_PURPOSE + ':' + path.derivedPublicKey)), signature: `0x${path.signatureChain[0]!}` });
    if (compressed(app) !== compressed(path.sourcePublicKey)) throw new Error('Invalid app source claim');
    const issued = Buffer.concat([Buffer.from('dstack-kms-issued:'), Buffer.from(trusted.appId, 'hex'), Buffer.from(compressed(app), 'hex')]);
    const recoveredRoot = await recoverPublicKey({ hash: keccak256(issued), signature: `0x${path.signatureChain[1]!}` });
    if (compressed(recoveredRoot) !== root) throw new Error('Untrusted KMS chain');
  }
  const holder = frozen.header.holders.find(h => h.id === holderId);
  if (!holder || holder.publicKey !== holderPublicKey) throw new Error('Holder recipient mismatch');
  return frozen.hash;
}
