import { expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({}) }),
});

const { classifyAccount, collectUserMetrics, createInternalMetricsRouter, parseDisposableDomains, DISPOSABLE_MAIL_DOMAINS, MAX_REQUEST_DISPOSABLE_DOMAINS, USER_BUCKETS } = await import(
  '../routes/internal-metrics?tc2356-users' as string
);

const now = new Date('2026-11-13T12:00:00.000Z');
const hoursAgo = (hours: number) => new Date(now.getTime() - hours * 3_600_000);
const daysAgo = (days: number) => hoursAgo(days * 24);

type Account = {
  id: string;
  email: string;
  createdAt?: Date;
  lastSession?: Date;
  key?: boolean;
  /** Wallet addresses of this account's ethereum_keys rows (any casing). */
  addresses?: string[];
};
type Token = { userId: string; clientId: string; at: Date };

const WALLET_A = '0xAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaaAAaa';
const WALLET_B = '0xbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBBbbBB';

function fakeDatabase(
  accounts: Account[],
  options: { botUserIds?: string[]; tokens?: Token[]; clients?: Array<{ clientId: string; name: string }> } = {},
) {
  const walletQueries: unknown[][] = [];
  const botQueries: unknown[][] = [];
  const tokens = options.tokens ?? [];
  const database = {
    user: {
      count: async () => accounts.length,
      findMany: async () => accounts.map((a) => ({ id: a.id, email: a.email, createdAt: a.createdAt ?? daysAgo(100) })),
    },
    session: {
      groupBy: async () => accounts
        .filter((a) => a.lastSession)
        .map((a) => ({ userId: a.id, _max: { updatedAt: a.lastSession! } })),
    },
    ethereumKey: {
      count: async () => 0,
      findMany: async () => accounts.filter((a) => a.key || a.addresses?.length).map((a) => ({ userId: a.id })),
    },
    oauthAccessToken: {
      // Distinct (clientId, userId) pairs with a token created since `where.createdAt.gte`.
      findMany: async ({ where }: { where: { createdAt: { gte: Date } } }) => {
        const seen = new Map<string, { clientId: string; userId: string }>();
        for (const t of tokens) {
          if (t.at >= where.createdAt.gte) seen.set(`${t.clientId}|${t.userId}`, { clientId: t.clientId, userId: t.userId });
        }
        return [...seen.values()];
      },
    },
    oauthClient: { findMany: async () => options.clients ?? [] },
    tinyCloudManageKeySigningDecision: { count: async () => 0, groupBy: async () => [] },
    tinyCloudManageKeyAppPreference: { count: async () => 0 },
    async $queryRaw(query: TemplateStringsArray, ...values: unknown[]) {
      if (query.join('').includes('ethereum_keys')) {
        walletQueries.push(values);
        const wanted = new Set(values[0] as string[]);
        return accounts
          .filter((a) => a.addresses?.some((address) => wanted.has(address.toLowerCase())))
          .map((a) => ({ userId: a.id }));
      }
      botQueries.push(values);
      return (options.botUserIds ?? []).map((userId) => ({ userId }));
    },
  };
  return { database, walletQueries, botQueries };
}

const session = daysAgo(2);

// One account per bucket. Several also match later rules (for example the team
// domain addresses start with qa/agent, the plus address contains "test"), so a
// wrong order would move them.
const accounts: Account[] = [
  { id: 'u-wallet', email: 'someone@gmail.com', lastSession: session, addresses: [WALLET_A] },
  { id: 'u-wallet-2nd-key', email: 'qa@tinycloud.xyz', lastSession: session, addresses: ['0x1111111111111111111111111111111111111111', WALLET_B] },
  // QA/smoke accounts: tcqa- and the older qa- prefix, any casing. They also match later rules
  // (team domain, disposable domain, agent-name, test-like), so a wrong order would move them.
  { id: 'u-qa-tc', email: 'tcqa-smoke1@tinycloud.xyz', lastSession: session },
  { id: 'u-qa-old', email: 'qa-share-1@gmail.com', lastSession: session },
  { id: 'u-qa-upper', email: 'TCQA-Upper@mailinator.com', lastSession: session },
  { id: 'u-team', email: 'qa@tinycloud.xyz', lastSession: session },
  { id: 'u-team-case', email: 'Someone@TinyCloudLabs.com', lastSession: session },
  { id: 'u-agent', email: 'agent@gmail.com', lastSession: session },
  { id: 'u-agent-digit', email: 'qa2@gmail.com', lastSession: session },
  { id: 'u-disposable', email: 'testing-person@mailinator.com', lastSession: session }, // also test-like: the domain bucket wins
  { id: 'u-throwaway', email: 'jo@corp.invalid', lastSession: session },
  { id: 'u-subdomain', email: 'jane@mail.example.com', lastSession: session },
  { id: 'u-plus', email: 'jane+test@gmail.com', lastSession: session },
  { id: 'u-testlike', email: 'mydemo@gmail.com', lastSession: session },
  { id: 'u-never', email: 'ghost@gmail.com' },
  { id: 'u-never-listed', email: 'ghost2@gmail.com' },
  { id: 'u-explicit', email: 'teammate.personal@gmail.com', lastSession: session },
  { id: 'u-bot', email: 'scraper@gmail.com', lastSession: session },
  { id: 'u-real-session', email: 'alice@gmail.com', lastSession: session },
  { id: 'u-real-key', email: 'bob@proton.me', key: true },
];

const env = { SCOREBOARD_EXCLUDE_USER_IDS: 'u-explicit,u-never-listed', SCOREBOARD_EXCLUDE_ADDRESSES: `${WALLET_A.toLowerCase()},${WALLET_B}` };

test('each account lands in exactly one bucket, in precedence order', async () => {
  const { database } = fakeDatabase(accounts, { botUserIds: ['u-bot'] });
  const result = await collectUserMetrics(database, env, now);
  expect(result.buckets).toEqual({
    team_by_wallet: 2, // second one also has a team-domain email, wallet wins
    qa_prefix: 3,
    internal_team_domain: 2,
    disposable_mail_domain: 1,
    internal_agent_or_qa: 2,
    test_or_throwaway_domain: 2,
    plus_addressed: 1,
    test_like_name: 1,
    never_completed_signup: 2, // listed in env, but never_completed_signup is checked first
    explicit_exclusions: 1,
    bot_like: 1,
  });
  expect(result.total).toBe(accounts.length);
  expect(result.real).toBe(2);
  const bucketed = Object.values(result.buckets as Record<string, number>).reduce((sum, n) => sum + n, 0);
  expect(bucketed + result.real).toBe(result.total);
  expect(Object.keys(result.buckets)).toEqual([...USER_BUCKETS]);
  expect(USER_BUCKETS[0]).toBe('team_by_wallet');
});

test('classifyAccount: earlier rules win over later ones', () => {
  const facts = { teamByWallet: false, hasSession: true, hasKey: false, botLike: true };
  const classify = (email: string, excluded: string[] = [], over: Partial<typeof facts> = {}) =>
    classifyAccount({ id: 'x', email, ...facts, ...over }, new Set(excluded));
  expect(classify('qa+1@openkey.so', ['x'], { teamByWallet: true })).toBe('team_by_wallet');
  expect(classify('tcqa-1@gmail.com', ['x'], { teamByWallet: true })).toBe('team_by_wallet'); // wallet first
  expect(classify('tcqa-1@openkey.so')).toBe('qa_prefix');
  expect(classify('tcqa-1@mailinator.com')).toBe('qa_prefix');
  expect(classify('qa-1@gmail.com', ['x'])).toBe('qa_prefix'); // before agent-name, explicit, bot
  expect(classify('TcQa-1+x@gmail.com')).toBe('qa_prefix');
  // Only a prefix followed by the dash counts.
  expect(classify('tcqa1@gmail.com')).toBe('test_like_name');
  expect(classify('xqa-1@gmail.com')).toBe('test_like_name');
  expect(classify('person.tcqa-1@gmail.com')).toBe('test_like_name');
  expect(classify('qa@gmail.com')).toBe('internal_agent_or_qa');
  expect(classify('qa+1@openkey.so')).toBe('internal_team_domain');
  expect(classify('qa+1@mailinator.com', ['x'])).toBe('disposable_mail_domain'); // before agent-name, plus, explicit, bot
  expect(classify('test+1@gmail.com')).toBe('internal_agent_or_qa');
  expect(classify('person+1@example.org')).toBe('test_or_throwaway_domain');
  expect(classify('person+demo@gmail.com')).toBe('plus_addressed');
  expect(classify('demo.person@gmail.com')).toBe('test_like_name');
  expect(classify('person@gmail.com', ['x'])).toBe('explicit_exclusions');
  expect(classify('person@gmail.com')).toBe('bot_like');
  expect(classify('person@gmail.com', ['x'], { hasSession: false, hasKey: false })).toBe('never_completed_signup');
  expect(classify('person@gmail.com', [], { hasSession: false, hasKey: true, botLike: false })).toBe('real');
  // Agent-name rule needs a boundary: "alexander" is not "alex".
  expect(classify('alexander@gmail.com')).toBe('bot_like');
});

test('disposable_mail_domain: built-in providers, subdomains, families and QA mail catchers', () => {
  const classify = (email: string) =>
    classifyAccount({ id: 'x', email, teamByWallet: false, hasSession: true, hasKey: false, botLike: false }, new Set());
  for (const domain of [
    'mailinator.com', 'MAILINATOR.COM', 'foo.mailinator.com',
    'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.de', 'guerrillamailblock.com', 'sharklasers.com', 'grr.la',
    'mail.tm', 'in.mail.tm', 'x.mail.gw', 'mail.gw', 'fldubai.com', 'maxxspace.com', 'pokemail.net', 'spam4.me',
    'mailinator2.com', 'binkmail.com',
    'maildrop.cc', '10minutemail.com', '10minutemail.net', 'yopmail.com', 'yopmail.fr', 'temp-mail.org', 'tempmail.net',
    'trashmail.com', 'trashmail.de', 'getnada.com',
    'mailpit.local', 'mailhog.example.org', 'mail.mailcatcher',
  ]) {
    expect(classify(`user1@${domain}`), domain).toBe('disposable_mail_domain');
  }
  // Look-alikes and real providers are not matched.
  for (const domain of ['gmail.com', 'notmailinator.com', 'mailinator.com.au.example', 'fldubai.com.evil.io', 'proton.me', 'maxxspace.co']) {
    expect(classify(`user1@${domain}`), domain).not.toBe('disposable_mail_domain');
  }
});

// Guards against escaping mistakes in the patterns (for example a doubled backslash that
// compiles but never matches): real-looking addresses, not just domain strings.
test('every built-in disposable domain matches a real-looking address, and ordinary providers do not', async () => {
  const classify = (email: string) =>
    classifyAccount({ id: 'x', email, teamByWallet: false, hasSession: true, hasKey: false, botLike: false }, new Set());

  // The ones that matter most today, as addresses.
  for (const email of [
    'qa123@mailinator.com', 'x@fldubai.com', 'y@maxxspace.com', 'z@guerrillamailblock.com', 'a@foo.mailinator.com',
    'a@guerrillamail.com', 'b@sharklasers.com', 'c@grr.la', 'd@pokemail.net', 'e@spam4.me',
    'f@mail.tm', 'g@mail.gw', 'h@in.mail.tm', 'i@x.y.maxxspace.com', 'J.Doe+tag@FLDUBAI.COM',
  ]) {
    expect(classify(email), email).toBe('disposable_mail_domain');
  }

  // Every entry of the built-in list, itself and as a subdomain; look-alikes stay out.
  expect(DISPOSABLE_MAIL_DOMAINS).toEqual(expect.arrayContaining(['maxxspace.com', 'fldubai.com', 'guerrillamailblock.com', 'mailinator.com']));
  for (const domain of DISPOSABLE_MAIL_DOMAINS as string[]) {
    expect(classify(`user1@${domain}`), domain).toBe('disposable_mail_domain');
    expect(classify(`user1@sub.${domain}`), `sub.${domain}`).toBe('disposable_mail_domain');
    expect(classify(`user1@not${domain}`), `not${domain}`).not.toBe('disposable_mail_domain');
    expect(classify(`user1@${domain}.evil.io`), `${domain}.evil.io`).not.toBe('disposable_mail_domain');
  }

  // One address per pattern family.
  for (const domain of ['guerrillamail.biz', 'guerrillamail.info', 'mailinator2.com', '10minutemail.net', 'yopmail.fr', 'tempmail.io', 'temp-mail.org', 'trashmail.com', 'mailpit.local', 'mailhog.test']) {
    expect(classify(`user1@${domain}`), domain).toBe('disposable_mail_domain');
  }

  // Ordinary providers are not disposable.
  for (const domain of ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'proton.me', 'tinycloud.xyz']) {
    expect(classify(`user1@${domain}`), domain).not.toBe('disposable_mail_domain');
  }

  // End to end through the metrics query: whole-address counts.
  const people: Account[] = [
    ...['qa123@mailinator.com', 'x@fldubai.com', 'y@maxxspace.com', 'z@guerrillamailblock.com', 'a@foo.mailinator.com'].map((email, i) => ({ id: `d${i}`, email, lastSession: session })),
    { id: 'g', email: 'person@gmail.com', lastSession: session },
    { id: 'o', email: 'person@outlook.com', lastSession: session },
  ];
  const result = await collectUserMetrics(fakeDatabase(people).database, {}, now);
  expect(result.buckets.disposable_mail_domain).toBe(5);
  expect(result.real).toBe(2);
});

test('SCOREBOARD_DISPOSABLE_DOMAINS extends the built-in list: trimmed, case-insensitive, @ and *. prefixes, subdomains, invalid entries ignored', async () => {
  const people: Account[] = [
    { id: 'a', email: 'p1@newrotation.mailco.io', lastSession: session },
    { id: 'b', email: 'p2@Second-Domain.net', lastSession: session },
    { id: 'c', email: 'p3@sub.third.org', lastSession: session },
    { id: 'd', email: 'p4@gmail.com', lastSession: session },
    { id: 'e', email: 'p5@mailinator.com', lastSession: session }, // built-in still applies
  ];
  const before = await collectUserMetrics(fakeDatabase(people).database, {}, now);
  expect(before.buckets.disposable_mail_domain).toBe(1);
  expect(before.real).toBe(4);

  const extended = await collectUserMetrics(fakeDatabase(people).database, {
    SCOREBOARD_DISPOSABLE_DOMAINS: ' newrotation.mailco.io , @second-domain.NET,*.third.org,,not a domain,gmail,',
  }, now);
  expect(extended.buckets.disposable_mail_domain).toBe(4);
  expect(extended.real).toBe(1); // only the gmail.com account; the bare word "gmail" is not a domain and was ignored
  for (const unset of [{}, { SCOREBOARD_DISPOSABLE_DOMAINS: '' }, { SCOREBOARD_DISPOSABLE_DOMAINS: ' , ' }]) {
    expect((await collectUserMetrics(fakeDatabase(people).database, unset, now)).buckets.disposable_mail_domain).toBe(1);
  }
});

test('a real-data shaped split (1,601 accounts) lands in the expected buckets', async () => {
  const many: Account[] = [];
  const add = (count: number, domain: (i: number) => string, prefix: string) => {
    for (let i = 0; i < count; i += 1) many.push({ id: `${prefix}${i}`, email: `user${prefix}${i}@${domain(i)}`, lastSession: session });
  };
  add(823, () => 'mailinator.com', 'm');
  add(471, () => 'fldubai.com', 'f'); // mail.tm's current domain
  add(174, () => 'maxxspace.com', 'x');
  const guerrilla = ['guerrillamail.com', 'guerrillamailblock.com', 'sharklasers.com', 'guerrillamail.net'];
  add(67, (i) => guerrilla[i % guerrilla.length]!, 'g');
  add(8, () => 'tinycloud.xyz', 't');
  add(58, () => 'gmail.com', 'r');
  const result = await collectUserMetrics(fakeDatabase(many).database, {}, now);
  expect(result.total).toBe(1601);
  expect(result.buckets.disposable_mail_domain).toBe(823 + 471 + 174 + 67);
  expect(result.buckets.internal_team_domain).toBe(8);
  expect(result.real).toBe(58);
  const bucketed = Object.values(result.buckets as Record<string, number>).reduce((sum, n) => sum + n, 0);
  expect(bucketed + result.real).toBe(1601);
});

test('wallet exclusion: lowercase compare, every key of the person drops out, invalid entries are ignored', async () => {
  const people: Account[] = [
    { id: 'multi', email: 'p1@gmail.com', lastSession: session, addresses: ['0x1111111111111111111111111111111111111111', WALLET_A] },
    { id: 'single', email: 'p2@gmail.com', lastSession: session, addresses: [WALLET_B] },
    { id: 'other', email: 'p3@gmail.com', lastSession: session, addresses: ['0x2222222222222222222222222222222222222222'] },
  ];
  const { database, walletQueries } = fakeDatabase(people);
  const result = await collectUserMetrics(database, {
    // mixed case, whitespace, duplicate, a too-short value and a non-address string
    SCOREBOARD_EXCLUDE_ADDRESSES: ` ${WALLET_A.toUpperCase().replace('0X', '0x')} , ${WALLET_A.toLowerCase()},0x1234,not-an-address,,${WALLET_B}`,
  }, now);
  expect(walletQueries).toHaveLength(1);
  expect(walletQueries[0]![0]).toEqual([WALLET_A.toLowerCase(), WALLET_B.toLowerCase()]);
  expect(result.buckets.team_by_wallet).toBe(2);
  expect(result.real).toBe(1);
});

test('env lists: ids are trimmed, unknown ids are harmless, empty or unset env excludes nobody and skips the wallet query', async () => {
  const people: Account[] = [
    { id: 'a', email: 'alice@gmail.com', lastSession: session, addresses: [WALLET_A] },
    { id: 'b', email: 'bob@gmail.com', lastSession: session },
    { id: 'c', email: 'carol@gmail.com', lastSession: session },
  ];
  const listed = fakeDatabase(people);
  const result = await collectUserMetrics(listed.database, { SCOREBOARD_EXCLUDE_USER_IDS: ' b , ,c,,no-such-user ' }, now);
  expect(result.buckets.explicit_exclusions).toBe(2);
  expect(result.buckets.team_by_wallet).toBe(0);
  expect(result.real).toBe(1);
  expect(listed.walletQueries).toHaveLength(0);
  for (const e of [
    { SCOREBOARD_EXCLUDE_USER_IDS: '', SCOREBOARD_EXCLUDE_ADDRESSES: '' },
    { SCOREBOARD_EXCLUDE_USER_IDS: ' , ', SCOREBOARD_EXCLUDE_ADDRESSES: ' , ' },
    {},
  ]) {
    const fresh = fakeDatabase(people);
    const empty = await collectUserMetrics(fresh.database, e, now);
    expect(empty.buckets.explicit_exclusions).toBe(0);
    expect(empty.buckets.team_by_wallet).toBe(0);
    expect(empty.real).toBe(3);
    expect(fresh.walletQueries).toHaveLength(0);
  }
});

test('bot_like: the query counts >=50 sessions in one day over the last 30 days, and bots leave REAL', async () => {
  const people: Account[] = [
    { id: 'bot', email: 'scraper@gmail.com', createdAt: daysAgo(1), lastSession: hoursAgo(1) },
    { id: 'human', email: 'alice@gmail.com', createdAt: daysAgo(1), lastSession: hoursAgo(1) },
  ];
  const { database, botQueries } = fakeDatabase(people, { botUserIds: ['bot'] });
  const result = await collectUserMetrics(database, {}, now);
  expect(botQueries).toHaveLength(1);
  const [since, threshold] = botQueries[0] as [Date, number];
  expect(since.toISOString()).toBe(daysAgo(30).toISOString());
  expect(threshold).toBe(50);
  expect(result.buckets.bot_like).toBe(1);
  expect(result).toMatchObject({ real: 1, realActive: { d1: 1, d7: 1, d30: 1 }, realNew7d: 1 });
});

test('REAL activity windows and new-7d use only real accounts', async () => {
  const people: Account[] = [
    { id: 'r1', email: 'a1@gmail.com', createdAt: daysAgo(6), lastSession: hoursAgo(12) },
    { id: 'r7', email: 'a7@gmail.com', createdAt: daysAgo(8), lastSession: daysAgo(3) },
    { id: 'r30', email: 'a30@gmail.com', createdAt: daysAgo(50), lastSession: daysAgo(20) },
    { id: 'r-old', email: 'a-old@gmail.com', createdAt: daysAgo(50), lastSession: daysAgo(40) },
    { id: 'r-key', email: 'a-key@gmail.com', createdAt: daysAgo(2), key: true },
    // Internal account that is new and active: counted in no REAL figure.
    { id: 'team', email: 'x@tinycloud.xyz', createdAt: daysAgo(1), lastSession: hoursAgo(1) },
  ];
  const { database } = fakeDatabase(people);
  const result = await collectUserMetrics(database, {}, now);
  expect(result.real).toBe(5);
  expect(result.realActive).toEqual({ d1: 1, d7: 2, d30: 3 });
  expect(result.realNew7d).toBe(2);
});

test('per-app real users: distinct real accounts per client display name, 7d and 30d, excluded accounts never counted', async () => {
  const people: Account[] = [
    { id: 'r1', email: 'a1@gmail.com', lastSession: session },
    { id: 'r2', email: 'a2@gmail.com', lastSession: session },
    { id: 'r3', email: 'a3@gmail.com', lastSession: session },
    { id: 'team', email: 'x@tinycloud.xyz', lastSession: session },
    { id: 'wallet', email: 'w@gmail.com', lastSession: session, addresses: [WALLET_A] },
  ];
  const tokens: Token[] = [
    { userId: 'r1', clientId: 'c-chat', at: hoursAgo(2) },
    { userId: 'r1', clientId: 'c-chat', at: daysAgo(3) }, // same account twice: one
    { userId: 'r2', clientId: 'c-chat', at: daysAgo(20) }, // 30d only
    { userId: 'r2', clientId: 'c-chat-staging', at: daysAgo(2) }, // same display name, other client: merged
    { userId: 'r3', clientId: 'c-notes', at: daysAgo(40) }, // outside 30d
    { userId: 'r1', clientId: 'c-gone', at: daysAgo(1) }, // client row deleted
    { userId: 'team', clientId: 'c-chat', at: hoursAgo(1) },
    { userId: 'wallet', clientId: 'c-notes', at: hoursAgo(1) },
  ];
  const clients = [
    { clientId: 'c-chat', name: 'TinyChat' },
    { clientId: 'c-chat-staging', name: 'TinyChat' },
    { clientId: 'c-notes', name: 'Notes' },
  ];
  const { database } = fakeDatabase(people, { tokens, clients });
  const result = await collectUserMetrics(database, { SCOREBOARD_EXCLUDE_ADDRESSES: WALLET_A }, now);
  expect(result.apps).toEqual([
    { name: 'TinyChat', real7d: 2, real30d: 2 },
    { name: 'unknown client', real7d: 1, real30d: 1 },
  ]);
});

test('empty database yields zeros', async () => {
  const { database } = fakeDatabase([]);
  const result = await collectUserMetrics(database, {}, now);
  expect(result).toEqual({
    total: 0,
    buckets: Object.fromEntries(USER_BUCKETS.map((bucket: string) => [bucket, 0])),
    real: 0,
    realActive: { d1: 0, d7: 0, d30: 0 },
    realNew7d: 0,
    apps: [],
    unclassifiedDomains: [],
  });
});

test('the response carries counts and app names only: no emails, ids, addresses or per-user data', async () => {
  const tokens: Token[] = [{ userId: 'u-real-session', clientId: 'c1', at: hoursAgo(1) }];
  const { database } = fakeDatabase(accounts, { botUserIds: ['u-bot'], tokens, clients: [{ clientId: 'c1', name: 'TinyChat' }] });
  const result = await collectUserMetrics(database, env, now);
  expect(result.apps).toEqual([{ name: 'TinyChat', real7d: 1, real30d: 1 }]);
  const serialized = JSON.stringify(result);
  for (const account of accounts) {
    expect(serialized).not.toContain(account.id);
    expect(serialized).not.toContain(account.email);
    expect(serialized).not.toContain(account.email.split('@')[1]!.toLowerCase());
    for (const address of account.addresses ?? []) expect(serialized.toLowerCase()).not.toContain(address.toLowerCase());
  }
  expect(serialized).not.toContain('c1');
  expect(serialized).not.toContain('@');
  expect(serialized).not.toContain('0x');
  expect(Object.keys(result)).toEqual(['total', 'buckets', 'real', 'realActive', 'realNew7d', 'apps', 'unclassifiedDomains']);
  const numbers: unknown[] = [];
  const walk = (value: unknown, key?: string) => {
    if (Array.isArray(value)) value.forEach((v) => walk(v));
    else if (value && typeof value === 'object') Object.entries(value).forEach(([k, v]) => walk(v, k));
    else if (key !== 'name' && key !== 'domain') numbers.push(value);
  };
  walk(result);
  expect(numbers.every((value) => Number.isInteger(value))).toBe(true);
});

test('parseDisposableDomains: lowercase hostnames, at most 5,000, anything else is rejected', () => {
  expect(parseDisposableDomains({})).toEqual([]);
  expect(parseDisposableDomains({ disposableDomains: [] })).toEqual([]);
  expect(parseDisposableDomains({ disposableDomains: ['a.example', 'x-y.mail.tm', 'a1.b2.c3.io'] })).toEqual(['a.example', 'x-y.mail.tm', 'a1.b2.c3.io']);
  const bigOk = Array.from({ length: MAX_REQUEST_DISPOSABLE_DOMAINS }, (_, i) => `d${i}.mailco.io`);
  expect(parseDisposableDomains({ disposableDomains: bigOk })).toHaveLength(5000);
  expect(parseDisposableDomains({ disposableDomains: [...bigOk, 'one-more.io'] })).toBeNull();
  const bads: unknown[] = [
    null, [], 'x', 5,
    { disposableDomains: 'a.io' },
    { disposableDomains: { 0: 'a.io' } },
    { disposableDomains: [5] },
    { disposableDomains: [null] },
    { disposableDomains: ['A.IO'] }, // must be lowercase
    { disposableDomains: ['a.io', 'Mail.TM'] },
    { disposableDomains: [''] },
    { disposableDomains: ['localhost'] }, // not a dotted hostname
    { disposableDomains: ['a b.io'] },
    { disposableDomains: ['a_b.io'] },
    { disposableDomains: ['-a.io'] },
    { disposableDomains: ['a.io.'] },
    { disposableDomains: ['http://a.io'] },
    { disposableDomains: ['a.io/x'] },
    { disposableDomains: ['a.io:8080'] },
    { disposableDomains: ['*.a.io'] },
    { disposableDomains: ['user@a.io'] },
    { disposableDomains: [`${'a'.repeat(250)}.io`] }, // over 253 characters
  ];
  for (const bad of bads) expect(parseDisposableDomains(bad), JSON.stringify(bad)?.slice(0, 80)).toBeNull();
});

test('the disposable list is the union of the built-ins, SCOREBOARD_DISPOSABLE_DOMAINS and the request list', async () => {
  const people: Account[] = [
    { id: 'builtin', email: 'p1@fldubai.com', lastSession: session },
    { id: 'env', email: 'p2@from-env.mailco.io', lastSession: session },
    { id: 'request', email: 'p3@sub.from-request.mailco.io', lastSession: session }, // subdomain of a listed domain
    { id: 'none', email: 'p4@acme.io', lastSession: session },
  ];
  const env = { SCOREBOARD_DISPOSABLE_DOMAINS: 'from-env.mailco.io' };
  const alone = await collectUserMetrics(fakeDatabase(people).database, {}, now);
  expect(alone.buckets.disposable_mail_domain).toBe(1);
  const withEnv = await collectUserMetrics(fakeDatabase(people).database, env, now);
  expect(withEnv.buckets.disposable_mail_domain).toBe(2);
  const merged = await collectUserMetrics(fakeDatabase(people).database, env, now, ['from-request.mailco.io']);
  expect(merged.buckets.disposable_mail_domain).toBe(3);
  expect(merged.real).toBe(1);
  // The request list alone does not need the env, and does not leak into the next call.
  const requestOnly = await collectUserMetrics(fakeDatabase(people).database, {}, now, ['from-request.mailco.io']);
  expect(requestOnly.buckets.disposable_mail_domain).toBe(2);
  expect((await collectUserMetrics(fakeDatabase(people).database, {}, now)).buckets.disposable_mail_domain).toBe(1);
});

test('unclassifiedDomains: >=5 accounts, in no list, not a major webmail; domain and count only', async () => {
  const many: Account[] = [];
  const add = (count: number, domain: string, prefix: string, extra: Partial<Account> = {}) => {
    for (let i = 0; i < count; i += 1) many.push({ id: `${prefix}${i}`, email: `user${prefix}${i}@${domain}`, lastSession: session, ...extra });
  };
  add(9, 'newdisposable.mailco.io', 'a'); // reported
  add(5, 'acme.io', 'b'); // exactly the threshold: reported
  add(4, 'small.io', 'c'); // below
  add(30, 'gmail.com', 'd'); // major webmail
  add(8, 'yahoo.co.uk', 'e'); // webmail family
  add(7, 'hotmail.fr', 'f');
  add(6, 'proton.me', 'g');
  add(6, 'mailinator.com', 'h'); // disposable
  add(6, 'tinycloud.xyz', 'i'); // ours
  add(6, 'corp.example.com', 'j'); // reserved/test domain
  add(6, 'walleted.io', 'k', { addresses: [WALLET_A] }); // team by wallet: not counted
  add(7, 'Mixed-Case.IO', 'l'); // lower-cased
  const result = await collectUserMetrics(fakeDatabase(many).database, { SCOREBOARD_EXCLUDE_ADDRESSES: WALLET_A }, now);
  expect(result.unclassifiedDomains).toEqual([
    { domain: 'newdisposable.mailco.io', accounts: 9 },
    { domain: 'mixed-case.io', accounts: 7 },
    { domain: 'acme.io', accounts: 5 },
  ]);
  // Once the domain is in a list (env or request) it stops being reported.
  const listed = await collectUserMetrics(fakeDatabase(many).database, { SCOREBOARD_DISPOSABLE_DOMAINS: 'acme.io', SCOREBOARD_EXCLUDE_ADDRESSES: WALLET_A }, now, ['newdisposable.mailco.io']);
  expect(listed.unclassifiedDomains).toEqual([{ domain: 'mixed-case.io', accounts: 7 }]);
  expect(listed.buckets.disposable_mail_domain).toBe(6 + 5 + 9);
  // Counts and domains only.
  expect(JSON.stringify(result.unclassifiedDomains)).not.toContain('@');
  expect(JSON.stringify(result.unclassifiedDomains)).not.toContain('user');
});

test('unclassifiedDomains is capped at the 200 biggest domains', async () => {
  const many: Account[] = [];
  for (let d = 0; d < 230; d += 1) {
    for (let i = 0; i < 5 + (d % 7); i += 1) many.push({ id: `${d}-${i}`, email: `p${d}x${i}@site${d}.io`, lastSession: session });
  }
  const result = await collectUserMetrics(fakeDatabase(many).database, {}, now);
  expect(result.unclassifiedDomains).toHaveLength(200);
  const counts = result.unclassifiedDomains.map((entry: { accounts: number }) => entry.accounts);
  expect(counts).toEqual([...counts].sort((a, b) => b - a));
});

test('POST / carries the maintained list behind the same token gate; GET stays body-less', async () => {
  const people: Account[] = [
    { id: 'a', email: 'p1@rotated.mailco.io', lastSession: session },
    { id: 'b', email: 'p2@gmail.com', lastSession: session },
  ];
  const { database } = fakeDatabase(people);
  const router = createInternalMetricsRouter(() => database);
  const saved = process.env.INTERNAL_METRICS_TOKEN;
  const post = (body: string | undefined, headers: Record<string, string> = {}) =>
    router.request('/', { method: 'POST', body, headers: { authorization: 'Bearer test-metrics-token', 'content-type': 'application/json', ...headers } });
  try {
    delete process.env.INTERNAL_METRICS_TOKEN;
    expect((await post('{}')).status).toBe(503);
    process.env.INTERNAL_METRICS_TOKEN = 'test-metrics-token';
    expect((await router.request('/', { method: 'POST', body: '{}' })).status).toBe(401);
    expect((await post('{}', { authorization: 'Bearer wrong' })).status).toBe(401);
    // A bad body is refused only after the token check, so it is not an oracle for unauthenticated callers.
    expect((await router.request('/', { method: 'POST', body: 'not json' })).status).toBe(401);

    const plain = await (await router.request('/', { headers: { authorization: 'Bearer test-metrics-token' } })).json();
    expect(plain.users.buckets.disposable_mail_domain).toBe(0);
    expect(plain.users.real).toBe(2);

    const merged = await post(JSON.stringify({ disposableDomains: ['rotated.mailco.io'] }));
    expect(merged.status).toBe(200);
    const body = await merged.json();
    expect(body.users.buckets.disposable_mail_domain).toBe(1);
    expect(body.users.real).toBe(1);
    expect(JSON.stringify(body)).not.toContain('rotated.mailco.io'); // the list is never echoed
    expect(body.accounts).toEqual(plain.accounts);

    // Empty body behaves like GET; the list is not remembered between requests.
    const empty = await (await post(undefined)).json();
    expect(empty.users.buckets.disposable_mail_domain).toBe(0);
    expect((await (await post('{}')).json()).users.real).toBe(2);

    for (const bad of ['not json', '[]', '"x"', '{"disposableDomains":"a.io"}', '{"disposableDomains":["BAD.IO"]}', '{"disposableDomains":["a b.io"]}']) {
      const refused = await post(bad);
      expect(refused.status, bad).toBe(400);
      expect(await refused.json()).toEqual({ error: 'Invalid disposableDomains' });
    }
    const tooMany = Array.from({ length: MAX_REQUEST_DISPOSABLE_DOMAINS + 1 }, (_, i) => `d${i}.mailco.io`);
    expect((await post(JSON.stringify({ disposableDomains: tooMany }))).status).toBe(400);
    expect((await post('{}', { 'content-length': '1000001' })).status).toBe(413);
    expect((await post(JSON.stringify({ disposableDomains: [], pad: 'x'.repeat(1_000_001) }))).status).toBe(413);
  } finally {
    if (saved === undefined) delete process.env.INTERNAL_METRICS_TOKEN;
    else process.env.INTERNAL_METRICS_TOKEN = saved;
  }
});

test('GET / keeps its token gate and adds the users block next to the existing counts', async () => {
  const { database } = fakeDatabase(accounts, { botUserIds: ['u-bot'] });
  const router = createInternalMetricsRouter(() => database);
  const saved = {
    token: process.env.INTERNAL_METRICS_TOKEN,
    ids: process.env.SCOREBOARD_EXCLUDE_USER_IDS,
    addresses: process.env.SCOREBOARD_EXCLUDE_ADDRESSES,
  };
  try {
    delete process.env.INTERNAL_METRICS_TOKEN;
    expect((await router.request('/')).status).toBe(503);
    process.env.INTERNAL_METRICS_TOKEN = 'test-metrics-token';
    expect((await router.request('/')).status).toBe(401);
    expect((await router.request('/', { headers: { authorization: 'Bearer wrong' } })).status).toBe(401);

    process.env.SCOREBOARD_EXCLUDE_USER_IDS = env.SCOREBOARD_EXCLUDE_USER_IDS;
    process.env.SCOREBOARD_EXCLUDE_ADDRESSES = env.SCOREBOARD_EXCLUDE_ADDRESSES;
    const response = await router.request('/', { headers: { authorization: 'Bearer test-metrics-token' } });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.accounts).toEqual({ total: accounts.length, new24h: accounts.length });
    expect(body.keys).toBeDefined();
    expect(body.users.total).toBe(accounts.length);
    expect(body.users.buckets.team_by_wallet).toBe(2);
    expect(body.users.buckets.explicit_exclusions).toBe(1);
    expect(body.users.real).toBe(2);
    expect(JSON.stringify(body)).not.toContain('u-explicit');
    expect(JSON.stringify(body).toLowerCase()).not.toContain(WALLET_A.toLowerCase());
  } finally {
    for (const [key, value] of [
      ['INTERNAL_METRICS_TOKEN', saved.token],
      ['SCOREBOARD_EXCLUDE_USER_IDS', saved.ids],
      ['SCOREBOARD_EXCLUDE_ADDRESSES', saved.addresses],
    ] as const) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('a failing users query returns users: null and leaves the existing counts intact', async () => {
  const { database } = fakeDatabase(accounts);
  database.session.groupBy = async () => { throw new Error('boom'); };
  const router = createInternalMetricsRouter(() => database);
  const savedToken = process.env.INTERNAL_METRICS_TOKEN;
  try {
    process.env.INTERNAL_METRICS_TOKEN = 'test-metrics-token';
    const response = await router.request('/', { headers: { authorization: 'Bearer test-metrics-token' } });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.users).toBeNull();
    expect(body.accounts.total).toBe(accounts.length);
  } finally {
    if (savedToken === undefined) delete process.env.INTERNAL_METRICS_TOKEN;
    else process.env.INTERNAL_METRICS_TOKEN = savedToken;
  }
});
