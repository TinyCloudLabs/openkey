import { createHash, createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';
import { deriveRecoveryTargetPolicy, freezeRecoveryDescriptor, freezeEscrowHeader, recoverEscrowPaths, encodeRecordManifest,
  type RecoveryDescriptor, type EscrowHeader, type EscrowCiphertextItem, type EscrowPathKey } from '@openkey/tee';
import { withFencedOpenKeySnapshot, readOpenKeySnapshotRows, type EscrowSqlDatabase } from './escrow-snapshot';
import { buildOpenKeyInventory, type EscrowInventoryRow } from './escrow-inventory';
import { validateOpenKeySnapshot } from './escrow-validate';
import { openKeyDbSnapshotHash } from './escrow-db-encoding';
import type { EscrowMeasurement } from './escrow-measurement';

export interface RecoveryDrillRuntime {
  isInTee(): Promise<boolean>;
  measurement(): Promise<EscrowMeasurement>;
  derivePath(path: string): Promise<{ key: Uint8Array; derivedPublicKey: string; sourcePublicKey: string; signatureChain: string[] }>;
}
const identity = (p: { path: string; purpose: string; version: number }) => JSON.stringify([p.path, p.purpose, p.version]);

function reseal(row: EscrowInventoryRow, oldKey: Uint8Array, newKey: Uint8Array): string {
  const blob = Buffer.from(row.blob, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', oldKey, blob.subarray(0, 12));
  decipher.setAuthTag(blob.subarray(12, 28));
  const partial = decipher.update(blob.subarray(28));
  let plaintext: Buffer | undefined;
  try {
    plaintext = Buffer.concat([partial, decipher.final()]);
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', newKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64');
  } finally { partial.fill(0); plaintext?.fill(0); }
}

/** Local isolated copies only; no production route or database discovery. */
export async function restoreOpenKeyDrill(options: {
  enabled?: boolean; database: EscrowSqlDatabase; runtime: RecoveryDrillRuntime;
  descriptor: RecoveryDescriptor; header: EscrowHeader; items: readonly EscrowCiphertextItem[]; shares: readonly Uint8Array[];
}): Promise<{ completed: number; descriptorHash: string; escrowId: string }> {
  if (options.enabled !== true || await options.runtime.isInTee() !== true) throw new Error('Restore drill disabled');
  const frozen = await freezeRecoveryDescriptor(options.descriptor);
  const d = frozen.descriptor;
  if (Date.parse(d.expiresAt) <= Date.now() || Date.parse(d.createdAt) > Date.now() + 300000) throw new Error('Restore descriptor expired');
  const header = structuredClone(options.header), items = structuredClone(options.items);
  if ((await freezeEscrowHeader(header)).hash !== d.exportHeaderHash) throw new Error('Restore header mismatch');
  const measurement = await options.runtime.measurement();
  if (measurement.appId !== d.targetAppId || measurement.composeHash !== d.targetComposeHash || measurement.imageDigest !== d.targetImageDigest
    || measurement.codeHash !== d.targetCodeHash || measurement.bootReference !== d.bootReference) throw new Error('Restore target changed');
  const target = await deriveRecoveryTargetPolicy(options.runtime, d);
  if (target.newPolicyId !== d.newPolicyId) throw new Error('Restore target policy changed');
  return withFencedOpenKeySnapshot(options.database, async snapshot => {
    const receipts = await snapshot.tx.$queryRawUnsafe<{ headerHash: string; descriptorHash: string; newPolicyId: string; targetAppId: string; targetComposeHash: string; completedRecords: number }[]>('SELECT * FROM "escrow_restore_receipt" WHERE "escrowId" = $1', header.escrowId);
    if (receipts.length) {
      const receipt = receipts[0]!;
      if (receipt.headerHash !== d.exportHeaderHash || receipt.descriptorHash !== frozen.descriptorHash || receipt.newPolicyId !== d.newPolicyId
        || receipt.targetAppId !== d.targetAppId || receipt.targetComposeHash !== d.targetComposeHash) throw new Error('Restore receipt mismatch');
      return { completed: receipt.completedRecords, descriptorHash: frozen.descriptorHash, escrowId: header.escrowId };
    }
    if (snapshot.ciphertextSnapshotHash !== header.dbSnapshotHash) throw new Error('Restore snapshot mismatch');
    const manifest = encodeRecordManifest(snapshot.inventory.records.map(row => ({ table: row.table, rowId: row.id, owner: row.owner, path: row.path,
      purpose: row.purpose, version: row.version, transform: row.transform, expectedIdentity: row.expectedIdentity, ciphertextChecksum: row.ciphertextChecksum })), header.paths);
    if (createHash('sha256').update(manifest).digest('hex') !== header.recordManifestHash) throw new Error('Restore manifest mismatch');
    let completed = 0;
    await recoverEscrowPaths({ enabled: true, isInTee: () => options.runtime.isInTee(), header, expectedHeaderHash: d.exportHeaderHash, items, shares: options.shares,
      validate: async keys => validateOpenKeySnapshot(snapshot.inventory.records, snapshot.inventory.paths, keys),
      importAndReseal: async oldKeys => {
        const fresh = new Map<string, Uint8Array>(), material: EscrowPathKey[] = [];
        try {
          for (const old of oldKeys) {
            if (!fresh.has(old.path)) {
              const derived = await options.runtime.derivePath(old.path);
              fresh.set(old.path, derived.key);
              if (derived.sourcePublicKey !== target.targetPolicyEvidence.sourcePublicKey) throw new Error('Restore target source changed');
            }
            const key = fresh.get(old.path)!;
            if (key.length !== 32 || timingSafeEqual(key, old.key)) throw new Error('Restore requires a new sealing policy');
            material.push({ path: old.path, purpose: old.purpose, version: old.version, key });
          }
          const oldById = new Map(oldKeys.map(key => [identity(key), key.key]));
          const newById = new Map(material.map(key => [identity(key), key.key]));
          const updated = structuredClone(snapshot.rows);
          const ethereum = new Map(updated.ethereum.map(row => [row.id, row]));
          const nostr = new Map(updated.nostr.map(row => [row.id, row]));
          const legacy = new Map(updated.legacy.map(row => [row.id, row]));
          for (const row of snapshot.inventory.records) {
            const sealed = reseal(row, oldById.get(identity(row))!, newById.get(identity(row))!);
            let count: number;
            if (row.table === 'ethereum_keys') {
              count = await snapshot.tx.$executeRawUnsafe('UPDATE "ethereum_keys" SET "sealedBlob" = $1 WHERE id = $2', sealed, row.id);
              ethereum.get(row.id)!.sealedBlob = sealed;
            } else if (row.table === 'nostr_keys') {
              count = await snapshot.tx.$executeRawUnsafe('UPDATE "nostr_keys" SET "sealedSecret" = $1 WHERE id = $2', sealed, row.id);
              nostr.get(row.id)!.sealedSecret = sealed;
            } else {
              count = await snapshot.tx.$executeRawUnsafe('UPDATE "user_encryption_key" SET "sealedPrivateKey" = $1 WHERE id = $2', sealed, row.id);
              legacy.get(row.id)!.sealedPrivateKey = sealed;
            }
            if (count !== 1) throw new Error('Restore row mismatch');
            completed++;
          }
          const actual = await readOpenKeySnapshotRows(snapshot.tx);
          if (openKeyDbSnapshotHash(actual) !== openKeyDbSnapshotHash(updated)) throw new Error('Restore write verification failed');
          const rewritten = buildOpenKeyInventory(actual);
          validateOpenKeySnapshot(rewritten.records, rewritten.paths, material);
          if (Date.parse(d.expiresAt) <= Date.now()) throw new Error('Restore descriptor expired');
          await snapshot.tx.$executeRawUnsafe('INSERT INTO "escrow_restore_receipt" ("escrowId", "headerHash", "descriptorHash", "newPolicyId", "targetAppId", "targetComposeHash", "completedRecords") VALUES ($1,$2,$3,$4,$5,$6,$7)', header.escrowId, d.exportHeaderHash, frozen.descriptorHash, d.newPolicyId, d.targetAppId, d.targetComposeHash, completed);
          return true;
        } finally { for (const key of fresh.values()) key.fill(0); }
      },
    });
    return { completed, descriptorHash: frozen.descriptorHash, escrowId: header.escrowId };
  }, async tx => {
    const place = await tx.$queryRawUnsafe<{ database: string; address: string | null }[]>('SELECT current_database() AS database, inet_server_addr()::text AS address');
    if (place.length !== 1 || !place[0]!.database.endsWith('_escrow_drill') || ![null, '127.0.0.1', '::1'].includes(place[0]!.address)) throw new Error('Restore requires local drill database');
  }, true);
}
