import { createHash, randomBytes, webcrypto } from 'node:crypto';
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { freezeEscrowHeader, type EscrowHeader } from './escrow-header';
import type { EscrowQuote } from './escrow-provenance';

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
export interface RecoveryDescriptor {
  version: 1; exportHeaderHash: string; recipientPublicKey: string; nonce: string; sessionId: string;
  targetAppId: string; targetComposeHash: string; targetImageDigest: string; targetCodeHash: string;
  bootReference: string; newPolicyId: string; createdAt: string; expiresAt: string;
}
export interface RecoveryShareEnvelope {
  version: 1; exportHeaderHash: string; descriptorHash: string; holderId: string; x: number; enc: string; ciphertext: string;
}
function decode(value: string, length: number): Uint8Array {
  if (typeof value !== 'string') throw new Error('Invalid recovery encoding');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || bytes.toString('base64url') !== value) throw new Error('Invalid recovery encoding');
  return new Uint8Array(bytes);
}
function timestamp(value: string): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new Error('Invalid recovery time');
  return Date.parse(value);
}
export async function freezeRecoveryDescriptor(input: RecoveryDescriptor) {
  const d = structuredClone(input);
  if (d.version !== 1 || typeof d.targetAppId !== 'string' || !/^[a-f0-9]{40}$/.test(d.targetAppId)
    || typeof d.targetImageDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(d.targetImageDigest)
    || typeof d.bootReference !== 'string' || !d.bootReference || Buffer.byteLength(d.bootReference) > 4096 || d.bootReference.includes('\0')) throw new Error('Invalid recovery descriptor');
  for (const value of [d.exportHeaderHash, d.targetComposeHash, d.targetCodeHash, d.newPolicyId]) if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid recovery hash');
  decode(d.nonce, 32); decode(d.sessionId, 16);
  const created = timestamp(d.createdAt), expires = timestamp(d.expiresAt);
  if (expires <= created || expires > created + 3_600_000) throw new Error('Invalid recovery expiry');
  const raw = decode(d.recipientPublicKey, 65);
  if (raw[0] !== 4) throw new Error('Invalid recovery recipient');
  const recipient = await suite.kem.deserializePublicKey(raw);
  const tuple = ['tinycloud/escrow/recovery-descriptor', 1, d.exportHeaderHash, d.recipientPublicKey, d.nonce, d.sessionId,
    d.targetAppId, d.targetComposeHash, d.targetImageDigest, d.targetCodeHash, d.bootReference, d.newPolicyId, d.createdAt, d.expiresAt];
  const descriptor: RecoveryDescriptor = Object.freeze({ version: 1, exportHeaderHash: d.exportHeaderHash, recipientPublicKey: d.recipientPublicKey, nonce: d.nonce, sessionId: d.sessionId,
    targetAppId: d.targetAppId, targetComposeHash: d.targetComposeHash, targetImageDigest: d.targetImageDigest, targetCodeHash: d.targetCodeHash, bootReference: d.bootReference,
    newPolicyId: d.newPolicyId, createdAt: d.createdAt, expiresAt: d.expiresAt });
  const bytes = new TextEncoder().encode(JSON.stringify(tuple));
  return { descriptor, descriptorHash: createHash('sha256').update(bytes).digest('hex'), bytes, recipient };
}
function shareBinding(domain: string, d: RecoveryDescriptor, descriptorHash: string, holderId: string, x: number) {
  if (typeof holderId !== 'string' || !holderId || Buffer.byteLength(holderId) > 1024 || !Number.isInteger(x) || x < 1 || x > 255) throw new Error('Invalid recovery share binding');
  return new TextEncoder().encode(JSON.stringify([domain, 1, d.exportHeaderHash, descriptorHash, holderId, x]));
}

/** Holder device: call only after both export and recovery attestations verify. */
export async function wrapRecoveryShare(share: Uint8Array, descriptor: RecoveryDescriptor, holderId: string, x: number): Promise<RecoveryShareEnvelope> {
  const frozen = await freezeRecoveryDescriptor(descriptor);
  if (Date.parse(frozen.descriptor.expiresAt) <= Date.now() || share.length !== 33 || share[32] !== x) throw new Error('Invalid recovery share');
  const info = shareBinding('tinycloud/escrow/recovery-share-info', frozen.descriptor, frozen.descriptorHash, holderId, x);
  const aad = shareBinding('tinycloud/escrow/recovery-share-aad', frozen.descriptor, frozen.descriptorHash, holderId, x);
  const result = await suite.seal({ recipientPublicKey: frozen.recipient, info }, share, aad);
  return { version: 1, exportHeaderHash: frozen.descriptor.exportHeaderHash, descriptorHash: frozen.descriptorHash, holderId, x,
    enc: Buffer.from(result.enc).toString('base64url'), ciphertext: Buffer.from(result.ct).toString('base64url') };
}

type Target = Pick<RecoveryDescriptor, 'targetAppId' | 'targetComposeHash' | 'targetImageDigest' | 'targetCodeHash' | 'bootReference' | 'newPolicyId'>;
export class EscrowRecoverySessions {
  #creating = 0;
  #sessions = new Map<string, { descriptor: RecoveryDescriptor; descriptorHash: string; keys: CryptoKeyPair; claimed?: boolean }>();
  constructor(private readonly options: { enabled?: boolean; isInTee: () => boolean | Promise<boolean>; quote: (descriptorHash: string) => Promise<EscrowQuote> }) {}
  async create(exportHeaderHash: string, target: Target) {
    if (this.options.enabled !== true || await this.options.isInTee() !== true) throw new Error('Recovery disabled');
    for (const [id, session] of this.#sessions) if (Date.parse(session.descriptor.expiresAt) <= Date.now()) this.#sessions.delete(id);
    if (this.#sessions.size + this.#creating >= 6) throw new Error('Recovery session limit');
    this.#creating++;
    try {
    const keys = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const now = Date.now();
    const frozen = await freezeRecoveryDescriptor({ version: 1, ...target, exportHeaderHash,
      recipientPublicKey: Buffer.from(await webcrypto.subtle.exportKey('raw', keys.publicKey)).toString('base64url'),
      nonce: randomBytes(32).toString('base64url'), sessionId: randomBytes(16).toString('base64url'), createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString() });
    const quote = await this.options.quote(frozen.descriptorHash);
    this.#sessions.set(frozen.descriptor.sessionId, { descriptor: frozen.descriptor, descriptorHash: frozen.descriptorHash, keys });
    return { descriptor: frozen.descriptor, descriptorHash: frozen.descriptorHash, quote };
    } finally { this.#creating--; }
  }
  async consume(sessionId: string, descriptorHash: string, header: EscrowHeader, envelopes: readonly RecoveryShareEnvelope[], restore: (shares: readonly Uint8Array[]) => Promise<{ completed: number }>) {
    if (this.options.enabled !== true || await this.options.isInTee() !== true) throw new Error('Recovery disabled');
    const session = this.#sessions.get(sessionId);
    if (!session || session.descriptorHash !== descriptorHash || Date.parse(session.descriptor.expiresAt) <= Date.now()) {
      if (session && Date.parse(session.descriptor.expiresAt) <= Date.now()) this.#sessions.delete(sessionId);
      throw new Error('Recovery session unavailable');
    }
    const frozen = await freezeEscrowHeader(header);
    const packets = structuredClone(envelopes);
    if (frozen.hash !== session.descriptor.exportHeaderHash || !Array.isArray(packets) || packets.length !== 2) throw new Error('Recovery header mismatch');
    const ids = new Set<string>(), coordinates = new Set<number>();
    for (const packet of packets) {
      const holder = frozen.header.holders.find(holder => holder.id === packet.holderId);
      if (packet.version !== 1 || packet.exportHeaderHash !== frozen.hash || packet.descriptorHash !== descriptorHash || !holder || holder.x !== packet.x || ids.has(packet.holderId) || coordinates.has(packet.x)) throw new Error('Invalid recovery holders');
      ids.add(packet.holderId); coordinates.add(packet.x);
    }
    // Claim synchronously; malformed ciphertext must not consume a public session.
    if (this.#sessions.get(sessionId) !== session || session.claimed || Date.parse(session.descriptor.expiresAt) <= Date.now()) throw new Error('Recovery session already used');
    session.claimed = true;
    const shares: Uint8Array[] = [];
    try {
      for (const packet of packets) {
        const info = shareBinding('tinycloud/escrow/recovery-share-info', session.descriptor, descriptorHash, packet.holderId, packet.x);
        const aad = shareBinding('tinycloud/escrow/recovery-share-aad', session.descriptor, descriptorHash, packet.holderId, packet.x);
        const share = new Uint8Array(await suite.open({ recipientKey: session.keys, enc: decode(packet.enc, 65), info }, decode(packet.ciphertext, 49), aad));
        shares.push(share);
        if (share.length !== 33 || share[32] !== packet.x) throw new Error('Invalid recovered share');
      }
      this.#sessions.delete(sessionId);
      const result = await restore(shares);
      if (!Number.isSafeInteger(result.completed) || result.completed < 0) throw new Error('Invalid recovery result');
      return { completed: result.completed, escrowId: frozen.header.escrowId, descriptorHash };
    } finally { session.claimed = false; for (const share of shares) share.fill(0); }
  }
}
