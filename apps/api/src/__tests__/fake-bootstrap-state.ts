// In-memory stand-in for the Prisma calls the TinyCloud bootstrap and its background sweep make on
// `tinycloud_bootstrap_state`. It evaluates the `where` forms those calls use: scalars, null, Date
// equality, `in`, `not`, `lt`/`lte`/`gt`/`gte`, `AND`/`OR`, relation `is` (user, key) and the
// `{ increment }` update. A compare-and-set (`updateMany`) therefore matches exactly the rows
// the real database would match, and a test can change a row between a read and a claim.

import type { PrismaClient } from '@openkey/db';

export type FakeUser = {
  id: string;
  autoSignEnabled: boolean;
};

export type FakeKey = {
  id: string;
  userId: string | null;
  address: string;
  keyType: 'MANAGED' | 'EXTERNAL';
  archivedAt: Date | null;
  sealedBlob: string | null;
  sealingContext: string | null;
};

export type FakeBootstrapRow = {
  id: string;
  userId: string;
  keyId: string;
  address: string;
  chainId: number;
  tinycloudHost: string;
  bootstrapVersion: string;
  status: string;
  attemptId: string | null;
  lockExpiresAt: Date | null;
  checkedAt: Date;
  completedAt: Date | null;
  failureCode: string | null;
  failureReason: string | null;
  sweepAttempts: number;
};

export type NewBootstrapRow = Pick<
  FakeBootstrapRow,
  'keyId' | 'userId' | 'address' | 'chainId' | 'tinycloudHost' | 'bootstrapVersion' | 'status' | 'checkedAt'
> &
  Partial<FakeBootstrapRow>;

type Where = Record<string, any>;

type Tables = {
  users: Map<string, FakeUser>;
  keys: Map<string, FakeKey>;
};

function time(value: unknown): number | undefined {
  if (value instanceof Date) return value.getTime();
  return typeof value === 'number' ? value : undefined;
}

function matchesField(actual: unknown, condition: unknown): boolean {
  if (condition === null) return actual === null || actual === undefined;
  if (condition instanceof Date) return time(actual) === condition.getTime();
  if (typeof condition !== 'object') return actual === condition;
  return Object.entries(condition).every(([operator, argument]) => {
    if (operator === 'in') return Array.isArray(argument) && argument.some((value) => actual === value);
    if (operator === 'not') {
      return argument === null ? actual !== null && actual !== undefined : actual !== argument;
    }
    const left = time(actual);
    const right = time(argument);
    if (left === undefined || right === undefined) return false;
    switch (operator) {
      case 'lt': return left < right;
      case 'lte': return left <= right;
      case 'gt': return left > right;
      case 'gte': return left >= right;
      default: throw new Error(`fake bootstrap store: unsupported operator ${operator}`);
    }
  });
}

function matchesWhere(row: Record<string, unknown>, where: Where, tables: Tables): boolean {
  return Object.entries(where).every(([field, condition]) => {
    if (condition === undefined) return true;
    if (field === 'AND') return condition.every((part: Where) => matchesWhere(row, part, tables));
    if (field === 'OR') return condition.some((part: Where) => matchesWhere(row, part, tables));
    if (field === 'user' || field === 'key') {
      const related = field === 'user' ? tables.users.get(String(row.userId)) : tables.keys.get(String(row.keyId));
      return related !== undefined && matchesWhere(related, condition.is, tables);
    }
    return matchesField(row[field], condition);
  });
}

function applyData(row: Record<string, unknown>, data: Where): void {
  for (const [field, value] of Object.entries(data)) {
    if (value !== null && typeof value === 'object' && 'increment' in value) {
      const current = row[field];
      row[field] = (typeof current === 'number' ? current : 0) + value.increment;
    } else {
      row[field] = value;
    }
  }
}

export type FakeBootstrapStore = {
  /** Pass as `prisma`: the bootstrap and the sweep only call the methods implemented here. */
  prisma: PrismaClient;
  rows: FakeBootstrapRow[];
  users: Map<string, FakeUser>;
  keys: Map<string, FakeKey>;
  addRow: (row: NewBootstrapRow) => FakeBootstrapRow;
  /**
   * Runs after `findMany` has produced its copies and before any claim. Setting a row here models a
   * concurrent writer that lands between the candidate read and the compare-and-set.
   */
  hooks: { onFindMany?: (found: Array<FakeBootstrapRow & { key: FakeKey }>) => void };
};

export function createFakeBootstrapStore(seed: { users?: FakeUser[]; keys?: FakeKey[] } = {}): FakeBootstrapStore {
  const tables: Tables = {
    users: new Map((seed.users ?? []).map((user) => [user.id, user])),
    keys: new Map((seed.keys ?? []).map((key) => [key.id, key])),
  };
  const rows: FakeBootstrapRow[] = [];
  const hooks: FakeBootstrapStore['hooks'] = {};
  let sequence = 0;

  const addRow = (partial: NewBootstrapRow): FakeBootstrapRow => {
    const row: FakeBootstrapRow = {
      id: `state_${++sequence}`,
      attemptId: null,
      lockExpiresAt: null,
      completedAt: null,
      failureCode: null,
      failureReason: null,
      sweepAttempts: 0,
      ...partial,
    };
    rows.push(row);
    return row;
  };

  const prisma = {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => {
        const user = tables.users.get(where.id);
        return user ? { autoSignEnabled: user.autoSignEnabled } : null;
      },
    },
    tinyCloudBootstrapState: {
      findUnique: async ({ where }: { where: { keyId_chainId_tinycloudHost_bootstrapVersion: Where } }) => {
        const key = where.keyId_chainId_tinycloudHost_bootstrapVersion;
        const row = rows.find((candidate) =>
          candidate.keyId === key.keyId && candidate.chainId === key.chainId
          && candidate.tinycloudHost === key.tinycloudHost && candidate.bootstrapVersion === key.bootstrapVersion);
        return row ? structuredClone(row) : null;
      },
      create: async ({ data }: { data: Where }) => {
        const duplicate = rows.some((candidate) =>
          candidate.keyId === data.keyId && candidate.chainId === data.chainId
          && candidate.tinycloudHost === data.tinycloudHost && candidate.bootstrapVersion === data.bootstrapVersion);
        if (duplicate) throw new Error('Unique constraint failed on tinycloud_bootstrap_state');
        return structuredClone(addRow(data as NewBootstrapRow));
      },
      findMany: async ({ where, orderBy, take }: { where: Where; orderBy?: { checkedAt?: 'asc' | 'desc' }; take?: number }) => {
        let found = rows.filter((row) => matchesWhere(row, where, tables));
        if (orderBy?.checkedAt) {
          const direction = orderBy.checkedAt === 'desc' ? -1 : 1;
          found = [...found].sort((a, b) => direction * (a.checkedAt.getTime() - b.checkedAt.getTime()));
        }
        if (take !== undefined) found = found.slice(0, take);
        // Copies, as Prisma returns them: a caller that nulls `row.key.sealedBlob` must not change the store.
        const out = found.map((row) => {
          const key = tables.keys.get(row.keyId);
          if (!key) throw new Error(`fake store: no key for ${row.keyId}`);
          return { ...structuredClone(row), key: structuredClone(key) };
        });
        hooks.onFindMany?.(out);
        return out;
      },
      updateMany: async ({ where, data }: { where: Where; data: Where }) => {
        const matched = rows.filter((row) => matchesWhere(row, where, tables));
        for (const row of matched) applyData(row, data);
        return { count: matched.length };
      },
    },
  };

  return { prisma: prisma as unknown as PrismaClient, rows, users: tables.users, keys: tables.keys, addRow, hooks };
}
