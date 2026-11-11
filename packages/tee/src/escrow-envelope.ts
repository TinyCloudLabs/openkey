import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
export interface ShareBinding {
  escrowId: string;
  holderId: string;
  x: number;
  headerHash: string;
}
export interface ShareEnvelope extends ShareBinding {
  version: 1;
  enc: string;
  ciphertext: string;
}

// Fixed-position JSON tuple: UTF-8, no whitespace, strings escaped by JSON.stringify.
// Separate domains prevent info and AAD from being interchanged.
function bindingBytes(domain: string, b: ShareBinding): Uint8Array {
  if (!b.escrowId || Buffer.byteLength(b.escrowId) > 1024 || !b.holderId
    || Buffer.byteLength(b.holderId) > 1024 || !Number.isInteger(b.x) || b.x < 1 || b.x > 255
    || !/^[a-f0-9]{64}$/.test(b.headerHash)) throw new Error('Invalid share binding');
  return new TextEncoder().encode(JSON.stringify([domain, 1, b.escrowId, b.holderId, b.x, b.headerHash]));
}
function decode(value: string, length?: number): Uint8Array {
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) {
    throw new Error('Invalid share envelope');
  }
  return new Uint8Array(bytes);
}

/** Encrypt internal share memory directly; only ciphertext is returned. */
export async function wrapEscrowShare(share: Uint8Array, recipientPublicKey: CryptoKey, binding: ShareBinding): Promise<ShareEnvelope> {
  if (share.length !== 33 || share[32] !== binding.x) throw new Error('Invalid escrow share');
  const info = bindingBytes('tinycloud/escrow/share-info', binding);
  const aad = bindingBytes('tinycloud/escrow/share-aad', binding);
  const result = await suite.seal({ recipientPublicKey, info }, share, aad);
  return { version: 1, escrowId: binding.escrowId, holderId: binding.holderId, x: binding.x, headerHash: binding.headerHash, enc: Buffer.from(result.enc).toString('base64url'), ciphertext: Buffer.from(result.ct).toString('base64url') };
}

/** Recovery enclave only. Expected binding comes from the verified frozen header. */
export async function unwrapEscrowShare(envelope: ShareEnvelope, recipientKey: CryptoKey, expected: ShareBinding): Promise<Uint8Array> {
  const info = bindingBytes('tinycloud/escrow/share-info', expected);
  const aad = bindingBytes('tinycloud/escrow/share-aad', expected);
  if (envelope.version !== 1 || envelope.escrowId !== expected.escrowId || envelope.holderId !== expected.holderId
    || envelope.x !== expected.x || envelope.headerHash !== expected.headerHash) throw new Error('Share binding mismatch');
  const share = new Uint8Array(await suite.open({ recipientKey, enc: decode(envelope.enc, 65), info }, decode(envelope.ciphertext, 49), aad));
  if (share.length !== 33 || share[32] !== expected.x) {
    share.fill(0);
    throw new Error('Invalid escrow share');
  }
  return share;
}
