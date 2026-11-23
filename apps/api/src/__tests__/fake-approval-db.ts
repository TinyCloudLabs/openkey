// TC-4082: an in-memory stand-in for the three tables the approval passkey reads and writes (`user`, `passkey`,
// `verification`), enough for the real `createApprovalPasskeyChallenge` / `verifyApprovalPasskey` to run against it.
// The query shapes are exactly the ones `approval-passkey.ts` issues; anything else throws, so a new query shows up.

type Row = Record<string, unknown>;
type Where = Record<string, unknown>;

function matches(row: Row, where: Where): boolean {
  return Object.entries(where).every(([field, condition]) => {
    const value = row[field];
    if (condition === null || typeof condition !== 'object' || condition instanceof Date) return value === condition;
    const op = condition as { startsWith?: string; lte?: Date; gt?: Date; in?: unknown[] };
    if (op.startsWith !== undefined) return typeof value === 'string' && value.startsWith(op.startsWith);
    if (op.lte !== undefined) return value instanceof Date && value.getTime() <= op.lte.getTime();
    if (op.gt !== undefined) return value instanceof Date && value.getTime() > op.gt.getTime();
    if (op.in !== undefined) return op.in.includes(value);
    throw new Error(`fake approval db: unsupported condition on ${field}`);
  });
}

export interface FakeApprovalDb {
  /** Shaped like the `user`, `passkey` and `verification` delegates and `$transaction` of the Prisma client. */
  db: object;
  passkeys: unknown[];
  verifications: unknown[];
}

export function createFakeApprovalDb(userMode: 'NEVER' | 'SENSITIVE' | 'ALWAYS' = 'NEVER'): FakeApprovalDb {
  const passkeys: Row[] = [];
  const verifications: Row[] = [];
  let created = 0;
  const db = {
    user: { findUnique: async () => ({ passkeyApprovalMode: userMode }) },
    passkey: {
      count: async ({ where }: { where: Where }) => passkeys.filter((row) => matches(row, where)).length,
      findMany: async ({ where }: { where: Where }) => passkeys.filter((row) => matches(row, where)),
      findFirst: async ({ where }: { where: Where }) => passkeys.find((row) => matches(row, where)) ?? null,
      create: async ({ data }: { data: Row }) => {
        passkeys.push({ ...data });
        return data;
      },
      update: async ({ where, data }: { where: { id: string }; data: Row }) => {
        Object.assign(passkeys.find((row) => row.id === where.id)!, data);
        return {};
      },
    },
    verification: {
      create: async ({ data }: { data: Row }) => {
        verifications.push({ ...data, createdAt: ++created });
        return data;
      },
      findFirst: async ({ where }: { where: Where }) => verifications.find((row) => matches(row, where)) ?? null,
      findMany: async ({ where, skip = 0 }: { where: Where; skip?: number }) =>
        verifications.filter((row) => matches(row, where)).sort((a, b) => (b.createdAt as number) - (a.createdAt as number)).slice(skip),
      deleteMany: async ({ where }: { where: Where }) => {
        const doomed = verifications.filter((row) => matches(row, where));
        for (const row of doomed) verifications.splice(verifications.indexOf(row), 1);
        return { count: doomed.length };
      },
    },
    $transaction: async <T>(run: (tx: unknown) => Promise<T>) => run(db),
  };
  return { db, passkeys, verifications };
}
