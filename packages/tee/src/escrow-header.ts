import { createHash } from 'node:crypto';
import { DhkemP256HkdfSha256 } from '@hpke/core';

export interface EscrowHeader {
  version: 1;
  escrowId: string;
  appId: string;
  imageDigest: string;
  composeHash: string;
  codeHash: string;
  osVersion: string;
  agentVersion: string;
  bootReference: string;
  snapshotId: string;
  nonce: string;
  approvalReference: string;
  operatorId: string;
  approverId: string;
  holders: readonly { id: string; publicKey: string }[];
  paths: readonly {
    path: string; purpose: string; version: number;
    transform: 'sha256-getkey'; sourcePublicKey: string;
    signatureChain: readonly string[]; expectedCount: number;
  }[];
}

function text(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096
    || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
    throw new Error('Invalid escrow header');
  }
}
function count(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error('Invalid escrow header');
}
function hash(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid escrow header');
}

/** Canonical v1 encoding is a UTF-8 JSON tuple, with fixed nested tuple positions. */
export function encodeEscrowHeader(header: EscrowHeader): Uint8Array {
  if (header.version !== 1) throw new Error('Invalid escrow header');
  for (const value of [header.escrowId, header.appId, header.osVersion, header.agentVersion,
    header.bootReference, header.snapshotId, header.nonce, header.approvalReference,
    header.operatorId, header.approverId]) text(value);
  if (Buffer.byteLength(header.escrowId) > 1024 || header.operatorId === header.approverId
    || !/^sha256:[a-f0-9]{64}$/.test(header.imageDigest)) throw new Error('Invalid escrow header');
  hash(header.composeHash); hash(header.codeHash);
  if (!Array.isArray(header.holders) || header.holders.length !== 3
    || !Array.isArray(header.paths) || header.paths.length === 0) throw new Error('Invalid escrow header');
  const holderIds = new Set<string>(); const publicKeys = new Set<string>();
  const holders = header.holders.map(holder => {
    text(holder.id); text(holder.publicKey);
    const bytes = Buffer.from(holder.publicKey, 'base64url');
    if (bytes.length !== 65 || bytes[0] !== 4 || bytes.toString('base64url') !== holder.publicKey
      || holderIds.has(holder.id) || publicKeys.has(holder.publicKey)) throw new Error('Invalid escrow holder');
    holderIds.add(holder.id); publicKeys.add(holder.publicKey);
    return [holder.id, holder.publicKey];
  }).sort((a, b) => a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : 0);
  const pathsSeen = new Set<string>();
  const paths = header.paths.map(item => {
    text(item.path); text(item.purpose); text(item.sourcePublicKey);
    count(item.version); count(item.expectedCount);
    if (item.transform !== 'sha256-getkey' || !Array.isArray(item.signatureChain) || item.signatureChain.length === 0) throw new Error('Invalid escrow path');
    for (const entry of item.signatureChain) text(entry);
    const identity = JSON.stringify([item.path, item.purpose, item.version]);
    if (pathsSeen.has(identity)) throw new Error('Duplicate escrow path');
    pathsSeen.add(identity);
    return [item.path, item.purpose, item.version, item.transform, item.sourcePublicKey, [...item.signatureChain], item.expectedCount];
  }).sort((a, b) => JSON.stringify(a) < JSON.stringify(b) ? -1 : JSON.stringify(a) > JSON.stringify(b) ? 1 : 0);
  return new TextEncoder().encode(JSON.stringify([
    'tinycloud/escrow/header', 1, header.escrowId, header.appId,
    header.imageDigest, header.composeHash, header.codeHash, header.osVersion,
    header.agentVersion, header.bootReference, header.snapshotId, header.nonce,
    header.approvalReference, header.operatorId, header.approverId,
    [16, 1, 2, 'gf256-0x11b', 2, 3], holders, paths,
  ]));
}

/** Copies inputs before awaiting; returns only validated, frozen policy data. */
export async function freezeEscrowHeader(input: EscrowHeader): Promise<{
  header: EscrowHeader; bytes: Uint8Array; hash: string;
  recipients: ReadonlyMap<string, CryptoKey>;
}> {
  const header: EscrowHeader = structuredClone(input);
  const bytes = encodeEscrowHeader(header);
  const kem = new DhkemP256HkdfSha256();
  const recipients = new Map<string, CryptoKey>();
  for (const holder of header.holders) {
    recipients.set(holder.id, await kem.deserializePublicKey(Buffer.from(holder.publicKey, 'base64url')));
    Object.freeze(holder);
  }
  for (const path of header.paths) { Object.freeze(path.signatureChain); Object.freeze(path); }
  Object.freeze(header.holders); Object.freeze(header.paths); Object.freeze(header);
  return { header, bytes, hash: createHash('sha256').update(bytes).digest('hex'), recipients };
}
