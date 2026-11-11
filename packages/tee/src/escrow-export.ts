import { randomBytes, createCipheriv, createHash } from 'node:crypto';
import { freezeEscrowHeader, type EscrowHeader } from './escrow-header';
import { escrowKeyCommitment, splitEscrowKey } from './escrow-shares';
import { wrapEscrowShare } from './escrow-envelope';

export interface EscrowPathKey {
  path: string;
  purpose: string;
  version: number;
  key: Uint8Array;
}
export type ExportPolicy = Omit<EscrowHeader, 'contentKeyCommitment' | 'holders'> & {
  holders: readonly { id: string; publicKey: string }[];
};
export interface EscrowExportOptions {
  enabled?: boolean;
  dryRun?: boolean;
  policy: ExportPolicy;
  /** Atomic persistent nonce consumption, distinct authenticated people, rate limit and audit. */
  authorize: (policy: ExportPolicy, dryRun: boolean) => Promise<void>;
  /** Hold a consistent snapshot/fence through validation and export; return only validated keys. */
  snapshot: <T>(operation: (keys: readonly EscrowPathKey[]) => Promise<T>) => Promise<T>;
  /** Verify every ciphertext and identity in the snapshot; failure must throw. */
  validateSnapshot: (policy: ExportPolicy) => Promise<void>;
  isInTee: () => boolean;
}

/** Internal measured-process entry; transport/auth adapters must be installed by the service. */
export async function prepareEscrowExport(options: EscrowExportOptions) {
  if (options.enabled !== true || !options.isInTee()) throw new Error('Escrow export disabled');
  const dryRun = options.dryRun !== false;
  const policy: ExportPolicy = structuredClone(options.policy);
  const now = Date.now();
  if (!(Date.parse(policy.createdAt) <= now && now < Date.parse(policy.expiresAt))) throw new Error('Escrow approval expired');
  await options.authorize(structuredClone(policy), dryRun);
  return options.snapshot(async keys => {
    await options.validateSnapshot(structuredClone(policy));
    const identity = (p: { path: string; purpose: string; version: number }) => JSON.stringify([p.path, p.purpose, p.version]);
    const expected = new Set(policy.paths.map(identity));
    if (expected.size !== policy.paths.length || keys.length !== expected.size) throw new Error('Incomplete escrow inventory');
    for (const item of keys) {
      if (item.key.length !== 32 || !expected.delete(identity(item))) throw new Error('Incomplete escrow inventory');
    }
    if (dryRun) return { dryRun: true as const, paths: keys.length, expectedRecords: policy.paths.reduce((n, p) => n + p.expectedCount, 0) };
    const contentKey = new Uint8Array(32);
    crypto.getRandomValues(contentKey);
    const shares: Uint8Array[] = [];
    try {
      shares.push(...await splitEscrowKey(contentKey));
      if (policy.holders.length !== 3) throw new Error('Invalid escrow holders');
      const frozen = await freezeEscrowHeader({
        ...policy, contentKeyCommitment: escrowKeyCommitment(contentKey, policy.escrowId),
        holders: policy.holders.map((holder, i) => ({ id: holder.id, publicKey: holder.publicKey, x: shares[i]![32]! })),
      });
      const wrappers = [];
      for (let i = 0; i < policy.holders.length; i++) {
        const holder = policy.holders[i]!;
        wrappers.push(await wrapEscrowShare(shares[i]!, frozen.recipients.get(holder.id)!, {
          escrowId: frozen.header.escrowId, holderId: holder.id, x: shares[i]![32]!, headerHash: frozen.hash,
        }));
      }
      const items = keys.map(item => {
        const metadata = frozen.header.paths.find(path => identity(path) === identity(item))!;
        const aad = Buffer.from(JSON.stringify(['tinycloud/escrow/path-key', 1, frozen.hash,
          frozen.header.escrowId, frozen.header.appId, metadata.path, metadata.purpose, metadata.version,
          metadata.transform, metadata.sourcePublicKey, metadata.signatureChain]));
        const iv = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', contentKey, iv); cipher.setAAD(aad);
        const bytes = Buffer.concat([iv, cipher.update(item.key), cipher.final(), cipher.getAuthTag()]);
        return { path: metadata.path, purpose: metadata.purpose, version: metadata.version,
          ciphertext: bytes.toString('base64url'), checksum: createHash('sha256').update(bytes).digest('hex') };
      });
      return { dryRun: false as const, header: frozen.header, headerHash: frozen.hash, wrappers, items };
    } finally {
      contentKey.fill(0);
      for (const share of shares) share.fill(0);
    }
  });
}
