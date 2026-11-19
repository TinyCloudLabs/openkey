import type { PrismaClient } from '@openkey/db';
import { sealingKid } from '@openkey/tee';
import type { KeyResealKind, KeyResealRepository, KeyResealRow } from './key-reseal';

const ethereumSelect = { id: true, userId: true, address: true, sealingContext: true, sealedBlob: true } as const;
const nostrSelect = { id: true, userId: true, pubkeyHex: true, sealingContext: true, sealedSecret: true } as const;

type EthereumRecord = { id: string; userId: string | null; address: string; sealingContext: string | null; sealedBlob: string | null };
type NostrRecord = { id: string; userId: string; pubkeyHex: string; sealingContext: string; sealedSecret: string };

function ethereumRow(row: EthereumRecord): KeyResealRow {
  if (row.sealedBlob === null) throw new Error('Invalid maintenance row');
  return { kind: 'ethereum', id: row.id, userId: row.userId, identity: row.address, sealingContext: row.sealingContext, blob: row.sealedBlob };
}

function nostrRow(row: NostrRecord): KeyResealRow {
  return { kind: 'nostr', id: row.id, userId: row.userId, identity: row.pubkeyHex, sealingContext: row.sealingContext, blob: row.sealedSecret };
}

/** No client is created here; the operator explicitly supplies the database. */
export class PrismaKeyResealRepository implements KeyResealRepository {
  constructor(private readonly prisma: Pick<PrismaClient, 'ethereumKey' | 'nostrKey'>) {}

  async page(kind: KeyResealKind, afterId: string | null, take: number): Promise<KeyResealRow[]> {
    const id = afterId === null ? {} : { id: { gt: afterId } };
    if (kind === 'ethereum') {
      const rows = await this.prisma.ethereumKey.findMany({
        where: { ...id, keyType: 'MANAGED', sealedBlob: { not: null } },
        orderBy: { id: 'asc' }, take, select: ethereumSelect,
      });
      return rows.map(ethereumRow);
    }
    const rows = await this.prisma.nostrKey.findMany({
      where: id, orderBy: { id: 'asc' }, take, select: nostrSelect,
    });
    return rows.map(nostrRow);
  }

  async get(kind: KeyResealKind, id: string): Promise<KeyResealRow | null> {
    if (kind === 'ethereum') {
      const row = await this.prisma.ethereumKey.findFirst({
        where: { id, keyType: 'MANAGED', sealedBlob: { not: null } }, select: ethereumSelect,
      });
      return row === null ? null : ethereumRow(row);
    }
    const row = await this.prisma.nostrKey.findUnique({ where: { id }, select: nostrSelect });
    return row === null ? null : nostrRow(row);
  }

  async compareAndSwap(previous: KeyResealRow, blob: string): Promise<number> {
    if (previous.kind === 'ethereum') {
      const result = await this.prisma.ethereumKey.updateMany({
        where: {
          id: previous.id, keyType: 'MANAGED', sealedBlob: previous.blob,
          address: previous.identity, userId: previous.userId, sealingContext: previous.sealingContext,
        },
        data: { sealedBlob: blob },
      });
      return result.count;
    }
    if (previous.userId === null || previous.sealingContext === null) throw new Error('Invalid maintenance row');
    const result = await this.prisma.nostrKey.updateMany({
      where: {
        id: previous.id, sealedSecret: previous.blob, pubkeyHex: previous.identity,
        userId: previous.userId, sealingContext: previous.sealingContext,
      },
      data: { sealedSecret: blob },
    });
    return result.count;
  }

  /** No generation column exists: inspect every envelope in a fresh keyset pass. */
  async remaining(oldKid: number): Promise<number> {
    let count = 0;
    for (const kind of ['ethereum', 'nostr'] as const) {
      let afterId: string | null = null;
      while (true) {
        const rows = await this.page(kind, afterId, 100);
        if (rows.length === 0) break;
        for (const row of rows) if (sealingKid(row.blob) === oldKid) count++;
        afterId = rows[rows.length - 1]!.id;
      }
    }
    return count;
  }
}
