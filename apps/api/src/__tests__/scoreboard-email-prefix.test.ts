import { expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({ $queryRaw: async () => [] }) }),
});

const { QA_EMAIL_PREFIXES, countAppUsers, countProtocolUsers, exclusionsFromEnv } = await import(
  '../routes/scoreboard-metrics?tcemailprefix' as string
);

type Row = { userId: string; email: string; createdAt?: Date; day?: Date; clientId?: string };
type Where = {
  userId?: { notIn?: string[] };
  clientId?: { notIn?: string[] };
  user?: { NOT?: Array<{ email: { startsWith: string; mode: string } }> };
  createdAt?: { gte: Date };
  day?: { gte: Date };
};

// Evaluates the Prisma where-clauses the metrics code issues, including `user.NOT[].email.startsWith`
// with `mode: 'insensitive'`.
function table(rows: Row[]) {
  return {
    async findMany({ where }: { where: Where }) {
      const seen = new Set<string>();
      for (const row of rows) {
        if (where.userId?.notIn?.includes(row.userId)) continue;
        if (row.clientId !== undefined && where.clientId?.notIn?.includes(row.clientId)) continue;
        const email = row.email.toLowerCase();
        if ((where.user?.NOT ?? []).some((clause) => email.startsWith(clause.email.startsWith.toLowerCase()))) continue;
        if (where.createdAt && !(row.createdAt! >= where.createdAt.gte)) continue;
        if (where.day && !(row.day! >= where.day.gte)) continue;
        seen.add(row.userId);
      }
      return [...seen].map((userId) => ({ userId }));
    },
  };
}

const now = new Date('2026-10-19T12:00:00Z');
const daysAgo = (n: number) => new Date(now.getTime() - n * 86_400_000);
const SMOKE = 'qa-sm-smoke-3fa91c0b72de@inbox.example';

function database(parts: Partial<Record<'access' | 'refresh' | 'consent' | 'signIn', Row[]>>, keyRows: Array<{ userId: string; email: string; address: string }> = []) {
  return {
    async $queryRaw(_q: TemplateStringsArray, ...values: unknown[]) {
      const wanted = new Set(values[0] as string[]);
      return keyRows.filter((k) => wanted.has(k.address.toLowerCase())).map((k) => ({ userId: k.userId, email: k.email }));
    },
    oauthAccessToken: table(parts.access ?? []),
    oauthRefreshToken: table(parts.refresh ?? []),
    oauthConsent: table(parts.consent ?? []),
    appSignInDay: table(parts.signIn ?? []),
  };
}

test('the secret-manager smoke address prefix is excluded with no configuration', () => {
  expect(QA_EMAIL_PREFIXES).toContain('qa-sm-smoke-');
  expect([...exclusionsFromEnv({}).emailPrefixes]).toEqual(['qa-sm-smoke-']);
});

test('SCOREBOARD_EXCLUDE_EMAIL_PREFIXES adds prefixes, lowercased and trimmed, beside the built-in one', () => {
  expect([...exclusionsFromEnv({ SCOREBOARD_EXCLUDE_EMAIL_PREFIXES: ' QA-Other- , ,agent-' }).emailPrefixes].sort())
    .toEqual(['agent-', 'qa-other-', 'qa-sm-smoke-']);
});

test('app users: accounts whose email starts with an excluded prefix are removed from total and active, in every source, whatever the case', async () => {
  const db = database({
    access: [{ userId: 'smoke1', email: SMOKE, clientId: 'c1', createdAt: daysAgo(1) }, { userId: 'real', email: 'ana@example.com', clientId: 'c1', createdAt: daysAgo(1) }],
    refresh: [{ userId: 'smoke2', email: SMOKE.toUpperCase(), clientId: 'c1', createdAt: daysAgo(2) }],
    consent: [{ userId: 'smoke3', email: SMOKE, clientId: 'c1', createdAt: daysAgo(3) }],
    signIn: [{ userId: 'smoke4', email: SMOKE, day: daysAgo(1) }, { userId: 'real2', email: 'bo@example.com', day: daysAgo(1) }],
  });
  expect(await countAppUsers(db, exclusionsFromEnv({}), now)).toEqual({ total: 2, active7d: 2 });
  // Without the prefix rule the same data counts the smoke accounts.
  expect(await countAppUsers(db, { userIds: new Set(), clientIds: new Set() }, now)).toEqual({ total: 6, active7d: 6 });
});

test('a real address that merely contains the prefix, or starts like it, is kept', async () => {
  const db = database({
    signIn: [
      { userId: 'a', email: 'sam-qa-sm-smoke-fan@example.com', day: daysAgo(1) },
      { userId: 'b', email: 'qa-sm@example.com', day: daysAgo(1) },
    ],
  });
  expect(await countAppUsers(db, exclusionsFromEnv({}), now)).toEqual({ total: 2, active7d: 2 });
});

test('protocol users: smoke accounts are removed from the count, other exclusions still apply', async () => {
  const keys = [
    { userId: 'real', email: 'ana@example.com', address: '0x0000000000000000000000000000000000000001' },
    { userId: 'smoke', email: SMOKE, address: '0x0000000000000000000000000000000000000002' },
    { userId: 'smoke', email: SMOKE, address: '0x0000000000000000000000000000000000000003' },
    { userId: 'team', email: 'team@example.com', address: '0x0000000000000000000000000000000000000004' },
  ];
  const addresses = keys.map((k) => k.address);
  const db = database({}, keys);
  expect(await countProtocolUsers(db, addresses, exclusionsFromEnv({}))).toBe(2);
  expect(await countProtocolUsers(db, addresses, exclusionsFromEnv({ SCOREBOARD_EXCLUDE_USER_IDS: 'team' }))).toBe(1);
});
