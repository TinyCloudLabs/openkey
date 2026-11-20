// TC-3554: boot wiring for the one-time legacy re-seal (see legacy-reseal.ts).
//
// Off unless the compose says OPENKEY_LEGACY_RESEAL=enabled (a literal, so the compose hash attests it).
// On, it needs the sidecar pins (legacyRootPinsFromEnv: exactly one transport, here the sidecar) and
// OPENKEY_LEGACY_CANARY_ADDRESS: the address of an internal test account whose managed key was sealed
// before the move. The canary row is found by that address with the API's own DATABASE_URL, and its
// unsealed private key must derive exactly that address: an anchor that does not come from Phala.
import type { Hex } from 'viem';
import type { PrismaClient } from '@openkey/db';
import {
  createSidecarTransport,
  getAddressFromPrivateKey,
  legacyRootPinsFromEnv,
  loadLegacyRoot,
  nostrPubkeyFromSecret,
  unseal,
  type TeeClient,
} from '@openkey/tee';
import { logLegacyReseal, logLegacyResealProgress, logLegacyResealQuarantined } from '../log';
import {
  LegacyResealError,
  resealLegacyRows,
  type ResealLegacy,
  type ResealRow,
  type ResealStore,
  type ResealSummary,
} from './legacy-reseal';
import { resolveSealingContext } from './key-sealing';

/** One progress line per this many rows, so an unknown row count cannot flood the log. */
const PROGRESS_EVERY = 25;

export const LEGACY_RESEAL_ENV = {
  enable: 'OPENKEY_LEGACY_RESEAL',
  canaryAddress: 'OPENKEY_LEGACY_CANARY_ADDRESS',
} as const;

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function addressMatches(address: string): (plaintext: string) => boolean {
  return (plaintext) => getAddressFromPrivateKey(plaintext as Hex).toLowerCase() === address.toLowerCase();
}

/** Prisma-backed stores: one per table that holds key material sealed under a GetKey path. */
export function prismaResealStores(prisma: PrismaClient): ResealStore[] {
  return [
    {
      async rows() {
        const keys = await prisma.ethereumKey.findMany({
          where: { sealedBlob: { not: null } },
          select: { id: true, userId: true, address: true, sealedBlob: true, sealingContext: true },
          orderBy: { id: 'asc' },
        });
        return keys.map((key): ResealRow => ({
          source: 'ethereum_key', id: key.id, userId: key.userId, sealingContext: key.sealingContext,
          sealed: key.sealedBlob!, matches: addressMatches(key.address),
        }));
      },
      async swap(row, sealed) {
        const result = await prisma.ethereumKey.updateMany({ where: { id: row.id, sealedBlob: row.sealed }, data: { sealedBlob: sealed } });
        return result.count === 1;
      },
    },
    {
      async rows() {
        const keys = await prisma.nostrKey.findMany({
          select: { id: true, userId: true, pubkeyHex: true, sealedSecret: true, sealingContext: true },
          orderBy: { id: 'asc' },
        });
        return keys.map((key): ResealRow => ({
          source: 'nostr_key', id: key.id, userId: key.userId, sealingContext: key.sealingContext,
          sealed: key.sealedSecret, matches: (plaintext) => nostrPubkeyFromSecret(plaintext) === key.pubkeyHex,
        }));
      },
      async swap(row, sealed) {
        const result = await prisma.nostrKey.updateMany({ where: { id: row.id, sealedSecret: row.sealed }, data: { sealedSecret: sealed } });
        return result.count === 1;
      },
    },
    {
      async rows() {
        const keys = await prisma.reviewerCleanup.findMany({
          where: { sealedBlob: { not: null } },
          select: { id: true, ownerUserId: true, address: true, sealedBlob: true, sealingContext: true },
          orderBy: { id: 'asc' },
        });
        return keys.map((key): ResealRow => ({
          source: 'reviewer_cleanup', id: key.id, userId: key.ownerUserId, sealingContext: key.sealingContext,
          sealed: key.sealedBlob!, matches: addressMatches(key.address),
        }));
      },
      async swap(row, sealed) {
        const result = await prisma.reviewerCleanup.updateMany({ where: { id: row.id, sealedBlob: row.sealed }, data: { sealedBlob: sealed } });
        return result.count === 1;
      },
    },
  ];
}

/**
 * Loads the epoch-0 keys through the sidecar. The canary row is read now (so a re-run sees its current
 * ciphertext), must unseal under the sidecar key, and its private key must derive the pinned address.
 * `load` is loadLegacyRoot; a test passes a fake.
 */
export function legacyOpener(
  prisma: PrismaClient,
  env: Record<string, string | undefined>,
  canaryAddress: string,
  load: typeof loadLegacyRoot = loadLegacyRoot,
): () => Promise<ResealLegacy> {
  return async () => {
    const pins = legacyRootPinsFromEnv(env);
    if (pins.transport.kind !== 'sidecar') throw new LegacyResealError('reseal_config');
    const row = await prisma.ethereumKey.findFirst({
      where: { address: { equals: canaryAddress, mode: 'insensitive' }, keyType: 'MANAGED', sealedBlob: { not: null } },
      select: { userId: true, sealedBlob: true, sealingContext: true },
    });
    if (!row?.sealedBlob) throw new LegacyResealError('reseal_canary_missing');
    const path = resolveSealingContext({ userId: row.userId, sealingContext: row.sealingContext });
    const root = await load({
      config: pins.config,
      sidecar: createSidecarTransport({ socketPath: pins.transport.socketPath }),
      canaries: [{ path, sealed: row.sealedBlob }],
    });
    const key = await root.legacyKey(path);
    try {
      const privateKey = await unseal(row.sealedBlob, key);
      if (!addressMatches(canaryAddress)(privateKey)) throw new LegacyResealError('reseal_canary_mismatch');
    } catch (error) {
      if (error instanceof LegacyResealError) throw error;
      throw new LegacyResealError('reseal_canary_mismatch');
    } finally {
      key.fill(0);
    }
    return { legacyKey: (p) => root.legacyKey(p) };
  };
}

/**
 * Runs before the API serves. Resolves 'off' when not enabled, otherwise the summary once every row is
 * current. Throws on any failure: the caller must not catch it, so the process ends and nothing listens.
 */
export async function resealLegacyAtBoot(
  prisma: PrismaClient,
  tee: TeeClient,
  env: Record<string, string | undefined> = process.env,
): Promise<'off' | ResealSummary> {
  const flag = env[LEGACY_RESEAL_ENV.enable];
  if (flag === undefined || flag === '') return 'off';
  if (flag !== 'enabled') throw new LegacyResealError('reseal_config');

  const canaryAddress = env[LEGACY_RESEAL_ENV.canaryAddress];
  if (!canaryAddress || !ADDRESS.test(canaryAddress)) throw new LegacyResealError('reseal_config');

  const canaryRow = await prisma.ethereumKey.findFirst({
    where: { address: { equals: canaryAddress, mode: 'insensitive' }, keyType: 'MANAGED', sealedBlob: { not: null } },
    select: { id: true },
  });
  if (!canaryRow) throw new LegacyResealError('reseal_canary_missing');

  const summary = await resealLegacyRows({
    stores: prismaResealStores(prisma),
    tee,
    openLegacy: legacyOpener(prisma, env, canaryAddress),
    canary: { source: 'ethereum_key', id: canaryRow.id },
    onProgress: (progress) => {
      if (progress.done % PROGRESS_EVERY === 0 || progress.done === progress.pending) logLegacyResealProgress(progress);
    },
  });
  for (const row of summary.quarantined) logLegacyResealQuarantined(row);
  logLegacyReseal({
    total: summary.total,
    migrated: summary.migrated,
    alreadyCurrent: summary.alreadyCurrent,
    quarantined: summary.quarantined.length,
  });
  return summary;
}
