import { isEmptyLegacyDeclaration } from './escrow-legacy';
import { escrowMaterialLength } from './escrow-transform';
import { createDecipheriv, createHash } from 'node:crypto';
import { freezeEscrowHeader, type EscrowHeader } from './escrow-header';
import { recoverEscrowKey } from './escrow-shares';
import type { EscrowPathKey } from './escrow-export';

export interface EscrowCiphertextItem {
  path: string; purpose: string; version: number; ciphertext: string; checksum: string;
}
export interface EscrowRecoveryOptions {
  enabled?: boolean;
  isInTee: () => boolean | Promise<boolean>;
  header: EscrowHeader;
  /** Trusted authenticated manifest/header binding, not an unverified bundle field. */
  expectedHeaderHash: string;
  /** Two shares already HPKE-opened and bound to this header inside the enclave. */
  shares: readonly Uint8Array[];
  items: readonly EscrowCiphertextItem[];
  /** Validate all dependent sealed records and identities before any reseal/import. */
  validate: (keys: readonly EscrowPathKey[], header: EscrowHeader) => Promise<readonly { path: string; purpose: string; version: number; validatedCount: number }[]>;
  /** Transactional import/reseal under the new policy, inside this enclave. */
  importAndReseal: (keys: readonly EscrowPathKey[], header: EscrowHeader) => Promise<true>;
}

export async function recoverEscrowPaths(options: EscrowRecoveryOptions): Promise<{ completed: number; headerHash: string }> {
  if (options.enabled !== true || await options.isInTee() !== true) throw new Error('Escrow recovery disabled');
  const items = structuredClone(options.items);
  const frozen = await freezeEscrowHeader(options.header);
  if (frozen.hash !== options.expectedHeaderHash) throw new Error('Escrow header mismatch');
  const identity = (p: { path: string; purpose: string; version: number }) => JSON.stringify([p.path, p.purpose, p.version]);
  const paths = new Map(frozen.header.paths.filter(p => !isEmptyLegacyDeclaration(p)).map(p => [identity(p), p]));
  if (items.length !== paths.size || items.length > 2 ** 20) throw new Error('Incomplete recovery inventory');
  const seen = new Set<string>();
  for (const item of items) {
    const id = identity(item);
    if (!paths.has(id) || seen.has(id)) throw new Error('Invalid recovery inventory');
    seen.add(id);
  }
  let contentKey: Uint8Array | undefined;
  const recovered: EscrowPathKey[] = [];
  try {
    contentKey = await recoverEscrowKey(options.shares, frozen.header.contentKeyCommitment, frozen.header.escrowId);
    for (const item of items) {
      const p = paths.get(identity(item))!;
      if (typeof item.ciphertext !== 'string' || typeof item.checksum !== 'string') throw new Error('Invalid recovery item');
      const bytes = Buffer.from(item.ciphertext, 'base64url');
      if (bytes.length !== 12 + escrowMaterialLength(p.transform) + 16 || bytes.toString('base64url') !== item.ciphertext
        || createHash('sha256').update(bytes).digest('hex') !== item.checksum) throw new Error('Invalid recovery ciphertext');
      const aad = Buffer.from(JSON.stringify(['tinycloud/escrow/path-key', 1, frozen.hash,
        frozen.header.escrowId, frozen.header.appId, p.path, p.purpose, p.version,
        p.transform, p.sourcePublicKey, p.signatureChain]));
      const decipher = createDecipheriv('aes-256-gcm', contentKey, bytes.subarray(0, 12));
      decipher.setAAD(aad); decipher.setAuthTag(bytes.subarray(-16));
      const partial = decipher.update(bytes.subarray(12, -16));
      let key: Buffer;
      try { key = Buffer.concat([partial, decipher.final()]); } finally { partial.fill(0); }
      recovered.push({ path: p.path, purpose: p.purpose, version: p.version, key });
    }
    const counts = await options.validate(recovered, frozen.header);
    const expectedCounts = new Map(frozen.header.paths.map(p => [identity(p), p.expectedCount]));
    if (!Array.isArray(counts) || counts.length !== expectedCounts.size) throw new Error('Recovery validation failed');
    for (const result of counts) {
      const id = identity(result);
      if (!expectedCounts.has(id) || result.validatedCount !== expectedCounts.get(id)) throw new Error('Recovery validation failed');
      expectedCounts.delete(id);
    }
    if (await options.importAndReseal(recovered, frozen.header) !== true) throw new Error('Recovery import failed');
    return { completed: recovered.length, headerHash: frozen.hash };
  } finally {
    contentKey?.fill(0);
    for (const path of recovered) path.key.fill(0);
  }
}
