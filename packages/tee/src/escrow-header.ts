import { isEmptyLegacyDeclaration } from './escrow-legacy';
import { escrowMaterialLength, type EscrowTransform } from './escrow-transform';
import { createHash } from 'node:crypto';
import { DhkemP256HkdfSha256 } from '@hpke/core';

export interface EscrowHeader {
  version: 1;
  escrowId: string;
  appId: string;
  contentKeyCommitment: string;
  createdAt: string;
  expiresAt: string;
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
  holders: readonly { id: string; x: number; publicKey: string }[];
  paths: readonly {
    path: string; purpose: string; version: number;
    transform: EscrowTransform; sourcePublicKey: string;
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
  if (Object.is(value, -0) || !Number.isSafeInteger(value) || (value as number) < 0) throw new Error('Invalid escrow header');
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
    || typeof header.imageDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(header.imageDigest)) throw new Error('Invalid escrow header');
  hash(header.contentKeyCommitment);
  for (const timestamp of [header.createdAt, header.expiresAt]) {
    if (typeof timestamp !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(timestamp) || !Number.isFinite(Date.parse(timestamp)) || new Date(timestamp).toISOString() !== timestamp) throw new Error('Invalid escrow time');
  }
  if (header.expiresAt <= header.createdAt) throw new Error('Invalid escrow time');
  hash(header.composeHash); hash(header.codeHash);
  if (!Array.isArray(header.holders) || header.holders.length !== 3
    || !Array.isArray(header.paths) || header.paths.length === 0) throw new Error('Invalid escrow header');
  const coordinates = new Set<number>();
  const holderIds = new Set<string>(); const publicKeys = new Set<string>();
  const holders = header.holders.map(holder => {
    text(holder.id); text(holder.publicKey);
    if (!Number.isInteger(holder.x) || holder.x < 1 || holder.x > 255 || coordinates.has(holder.x)) throw new Error('Invalid holder coordinate');
    coordinates.add(holder.x);
    const bytes = Buffer.from(holder.publicKey, 'base64url');
    if (bytes.length !== 65 || bytes[0] !== 4 || bytes.toString('base64url') !== holder.publicKey
      || holderIds.has(holder.id) || publicKeys.has(holder.publicKey)) throw new Error('Invalid escrow holder');
    holderIds.add(holder.id); publicKeys.add(holder.publicKey);
    return [holder.id, holder.x, holder.publicKey];
  }).sort((a, b) => (a[0] as string) < (b[0] as string) ? -1 : (a[0] as string) > (b[0] as string) ? 1 : 0);
  if (header.paths.some(isEmptyLegacyDeclaration) && header.paths.some(p => p.purpose === 'legacy-user-encryption')) throw new Error('Conflicting legacy inventory');
  const pathsSeen = new Set<string>();
  const paths = header.paths.map(item => {
    text(item.path); text(item.purpose); text(item.sourcePublicKey);
    count(item.version); count(item.expectedCount);
    escrowMaterialLength(item.transform);
    if ((item.expectedCount === 0 && !isEmptyLegacyDeclaration(item)) || !Array.isArray(item.signatureChain) || item.signatureChain.length === 0) throw new Error('Invalid escrow path');
    for (const entry of item.signatureChain) text(entry);
    const identity = JSON.stringify([item.path, item.purpose, item.version]);
    if (pathsSeen.has(identity)) throw new Error('Duplicate escrow path');
    pathsSeen.add(identity);
    return [item.path, item.purpose, item.version, item.transform, item.sourcePublicKey, [...item.signatureChain], item.expectedCount];
  }).sort((a, b) => JSON.stringify(a) < JSON.stringify(b) ? -1 : JSON.stringify(a) > JSON.stringify(b) ? 1 : 0);
  return new TextEncoder().encode(JSON.stringify([
    'tinycloud/escrow/header', 1, header.escrowId, header.appId, header.contentKeyCommitment, header.createdAt, header.expiresAt,
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
  const copied: EscrowHeader = structuredClone(input);
  const bytes = encodeEscrowHeader(copied);
  const tuple = JSON.parse(new TextDecoder().decode(bytes));
  const header: EscrowHeader = {
    version: 1, escrowId: tuple[2], appId: tuple[3], contentKeyCommitment: tuple[4], createdAt: tuple[5], expiresAt: tuple[6],
    imageDigest: tuple[7], composeHash: tuple[8], codeHash: tuple[9], osVersion: tuple[10], agentVersion: tuple[11],
    bootReference: tuple[12], snapshotId: tuple[13], nonce: tuple[14], approvalReference: tuple[15], operatorId: tuple[16], approverId: tuple[17],
    holders: tuple[19].map((h: [string, number, string]) => ({ id: h[0], x: h[1], publicKey: h[2] })),
    paths: tuple[20].map((p: [string, string, number, EscrowTransform, string, string[], number]) => ({ path: p[0], purpose: p[1], version: p[2], transform: p[3], sourcePublicKey: p[4], signatureChain: p[5], expectedCount: p[6] })),
  };
  const kem = new DhkemP256HkdfSha256();
  const recipients = new Map<string, CryptoKey>();
  for (const holder of header.holders) {
    recipients.set(holder.id, await kem.deserializePublicKey(Buffer.from(holder.publicKey, 'base64url')));
    Object.freeze(holder);
  }
  for (const path of header.paths) { Object.freeze(path.signatureChain); Object.freeze(path); }
  Object.freeze(header.holders); Object.freeze(header.paths); Object.freeze(header);
  const digest = createHash('sha256').update(bytes).digest('hex');
  return Object.freeze({ header, get bytes() { return bytes.slice(); }, hash: digest, get recipients() { return new Map(recipients); } });
}
