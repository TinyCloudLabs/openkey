import { timingSafeEqual } from 'crypto';
import { Hono } from 'hono';
import { getPrisma } from '@openkey/db';
import { getAccountOriginRefusals, logError } from '../log';

type MetricsCounter = { count(options?: Record<string, unknown>): Promise<number> };
type RenewalGroup = { clientId: string; _count: { _all: number }; _max: { createdAt: Date | null } };
type RenewalGrouping = { groupBy(options: Record<string, unknown>): Promise<RenewalGroup[]> };
type UserRow = { id: string; email: string; createdAt: Date };
type SessionActivity = { userId: string; _max: { updatedAt: Date | null } };
type ClientUser = { clientId: string; userId: string };
export type MetricsDatabase = {
  user: MetricsCounter & { findMany(options: Record<string, unknown>): Promise<UserRow[]> };
  ethereumKey: MetricsCounter & { findMany(options: Record<string, unknown>): Promise<Array<{ userId: string | null }>> };
  session: { groupBy(options: Record<string, unknown>): Promise<SessionActivity[]> };
  oauthAccessToken: { findMany(options: Record<string, unknown>): Promise<ClientUser[]> };
  oauthClient: { findMany(options: Record<string, unknown>): Promise<Array<{ clientId: string; name: string }>> };
  tinyCloudManageKeySigningDecision: MetricsCounter & RenewalGrouping;
  tinyCloudManageKeyAppPreference: MetricsCounter;
  $queryRaw<T>(query: TemplateStringsArray, ...values: unknown[]): Promise<T>;
};

const DAY_MS = 24 * 60 * 60 * 1000;
// bot_like: this many sessions created on one UTC day, within the last 30 days.
const BOT_SESSIONS_PER_DAY = 50;

// Account bucket rules (TC-2356). Patterns are not secret. Buckets are
// exclusive and checked in this order; an account lands in the first match.
// Team accounts are excluded by wallet: SCOREBOARD_EXCLUDE_ADDRESSES (EVM
// addresses, compared lowercase) maps through ethereum_keys.address to a user,
// so every key of that person drops out. SCOREBOARD_EXCLUDE_USER_IDS (user
// ids) is the second per-person list. Both come only from env, never from code.
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
// Our team domains, and any subdomain of them (QA mail uses qa-mail.tinycloud.xyz).
const INTERNAL_TEAM_DOMAIN = /(^|\.)(tinycloud\.xyz|tinycloudlabs\.[a-z]+|gbafa\.com|openkey\.so|spruceid\.com)$/;
const INTERNAL_AGENT_OR_QA_NAME =
  /^(qa|agent|bot|probe|canary|smoke|e2e|test|ci|julie|courier|orchard|holden|naomi|amos|alex|bobbie|clarissa|fred|miller|avasarala)([^a-z]|$)/;
const TEST_OR_THROWAWAY_DOMAIN = /(^|\.)(example\.[a-z]+|test|invalid|localhost)$/;
// Disposable mail providers. Three sources are merged: this built-in list, the
// SCOREBOARD_DISPOSABLE_DOMAINS env list, and `disposableDomains` in the body of an
// authorised POST (the internal Worker sends the maintained list with each poll;
// request-scoped, never stored here). Rotating providers (mail.tm) change domain, so the
// built-in list is only the floor. Entries match the domain itself and any subdomain.
export const DISPOSABLE_MAIL_DOMAINS = [
  // Mailinator and its well-known alias domains.
  'mailinator.com', 'binkmail.com', 'bobmail.info', 'chammy.info', 'devnullmail.com', 'letthemeatspam.com',
  'mailinater.com', 'reallymymail.com', 'safetymail.info', 'sogetthis.com', 'spamhereplease.com',
  'streetwisemail.com', 'suremail.info', 'thisisnotmyrealemail.com', 'tradermail.info', 'veryrealemail.com',
  'zippymail.info',
  // Guerrilla Mail family (guerrillamail.<tld> is also matched by the family pattern below).
  'guerrillamailblock.com', 'sharklasers.com', 'grr.la', 'pokemail.net', 'spam4.me',
  'maildrop.cc', 'getnada.com', 'nada.email', 'throwawaymail.com', 'dispostable.com',
  // mail.tm and its sister mail.gw (their MX hosts, such as in.mail.tm, are subdomains), plus the
  // mail.tm domains in use today: fldubai.com and maxxspace.com (both ours, mail.tm). mail.tm
  // rotates domains: the Worker adds every domain they publish, and the env list covers the rest.
  'mail.tm', 'mail.gw', 'fldubai.com', 'maxxspace.com',
];
// Provider families with many TLDs or domains, and QA mail catchers (Mailpit, MailHog, MailCatcher).
const DISPOSABLE_MAIL_FAMILIES =
  /(^|\.)(mailinator[a-z0-9]*\.[a-z]+|guerrillamail[a-z]*\.[a-z]+|10minutemail\.[a-z]+|yopmail\.[a-z]+|tempmail\.[a-z]+|temp-mail\.[a-z]+|trashmail\.[a-z]+|(mailpit|mailhog|mailcatcher)(\.[a-z0-9-]+)*)$/;
// Major webmail providers are never reported as unclassified domains.
const MAJOR_WEBMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com',
  'rocketmail.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'aol.com',
  'gmx.com', 'gmx.net', 'gmx.de', 'web.de', 'mail.com', 'zoho.com', 'fastmail.com', 'fastmail.fm', 'hey.com',
  'tutanota.com', 'tuta.io', 'tutamail.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'rambler.ru', 'qq.com', '163.com',
  '126.com', 'yeah.net', 'sina.com', 'naver.com', 'daum.net', 'hanmail.net', 'duck.com', 'hushmail.com',
  'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'btinternet.com', 'bigpond.com', 'orange.fr',
  'free.fr', 'laposte.net', 'sfr.fr', 't-online.de', 'libero.it', 'seznam.cz', 'wp.pl', 'o2.pl', 'interia.pl',
  'rediffmail.com',
]);
const MAJOR_WEBMAIL_FAMILIES = /^(yahoo|hotmail|outlook|live|gmx|yandex)\.[a-z]+(\.[a-z]+)?$/;
/** A POSTed or env disposable entry applies only if it matches at least this many accounts (else it is ignored). */
const MIN_ACCOUNTS_FOR_LIST_ENTRY = 5;
// Per-app figures: names are chosen by whoever registers an OAuth client, so they are truncated,
// an app is listed by name only with at least this many real users, at most this many are
// listed, and everything else is summed (distinct users) into one "other apps" row.
const APP_NAME_MAX_LENGTH = 60;
const APP_MIN_REAL_USERS = 5;
const APPS_MAX_LISTED = 50;
const OTHER_APPS_NAME = 'other apps';
/** Domains with at least this many accounts, in no list, are reported for a decision. */
const UNCLASSIFIED_MIN_ACCOUNTS = 5;
const UNCLASSIFIED_MAX_REPORTED = 200;
/** `disposableDomains` limits of the POST body. */
export const MAX_REQUEST_DISPOSABLE_DOMAINS = 5000;
const MAX_REQUEST_BODY_BYTES = 1_000_000;
const MAX_DOMAIN_LENGTH = 253;
// A dotted hostname: labels of 1-63 letters, digits or inner hyphens.
const DOMAIN_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const TEST_LIKE_NAME = /(test|qa|probe|canary|smoke|e2e|bot|agent|demo|dummy|fake)/;
// Our QA/smoke accounts: `tcqa-` or `tcqa+` (Cloudflare routing forces our own QA mail to
// `tcqa+...@qa-mail.tinycloud.xyz`), plus the older `qa-` prefix (Share's smoke accounts).
// Checked before plus_addressed and the domain buckets.
const QA_PREFIX = /^(tcqa[-+]|qa-)/;

export const USER_BUCKETS = [
  'team_by_wallet',
  'qa_prefix',
  'internal_team_domain',
  'disposable_mail_domain',
  'internal_agent_or_qa',
  'test_or_throwaway_domain',
  'plus_addressed',
  'test_like_name',
  'never_completed_signup',
  'explicit_exclusions',
  'bot_like',
] as const;
export type UserBucket = (typeof USER_BUCKETS)[number] | 'real';

export type AccountFacts = {
  id: string;
  email: string;
  teamByWallet: boolean;
  hasSession: boolean;
  hasKey: boolean;
  botLike: boolean;
};

/** Real accounts that got an OAuth access token in the window, by the client's display name. */
export type AppUsers = { name: string; real7d: number; real30d: number };

/** An email domain with several accounts that no list covers: a candidate for the disposable list. */
export type UnclassifiedDomain = { domain: string; accounts: number };

export type UserMetrics = {
  total: number;
  buckets: Record<(typeof USER_BUCKETS)[number], number>;
  real: number;
  realActive: { d1: number; d7: number; d30: number };
  realNew7d: number;
  apps: AppUsers[];
  /** Domains with at least 5 accounts, in no list and not a major webmail; biggest first. */
  unclassifiedDomains: UnclassifiedDomain[];
};

const BUILTIN_DISPOSABLE = new Set(DISPOSABLE_MAIL_DOMAINS);

function isDisposableDomain(domain: string, extra: ReadonlySet<string>): boolean {
  if (DISPOSABLE_MAIL_FAMILIES.test(domain)) return true;
  // Walk the domain and its parents: an entry matches itself and every subdomain.
  for (let d = domain; d; ) {
    if (BUILTIN_DISPOSABLE.has(d) || extra.has(d)) return true;
    const dot = d.indexOf('.');
    if (dot < 0) break;
    d = d.slice(dot + 1);
  }
  return false;
}

function isMajorWebmail(domain: string): boolean {
  return MAJOR_WEBMAIL_DOMAINS.has(domain) || MAJOR_WEBMAIL_FAMILIES.test(domain);
}

/**
 * A list entry that must never mark mail disposable: a major webmail domain or one of our
 * team domains, a subdomain of either, or a two-level country suffix (`co.uk` would swallow
 * `yahoo.co.uk`). Request and env lists drop such entries, so a poisoned feed cannot turn
 * gmail.com or our own domains into "disposable".
 */
function isProtectedEntry(entry: string): boolean {
  for (let d = entry; d; ) {
    if (isMajorWebmail(d) || INTERNAL_TEAM_DOMAIN.test(d)) return true;
    const dot = d.indexOf('.');
    if (dot < 0) break;
    d = d.slice(dot + 1);
  }
  return /^(co|com|org|net|ne|or|ac|gov|edu)\.[a-z]{2}$/.test(entry);
}

/**
 * Validates the `disposableDomains` of a POST body: an array of at most 5,000 lowercase
 * hostnames. Returns the list, or null if the field is malformed. Absent means no extras.
 */
export function parseDisposableDomains(body: unknown): string[] | null {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null;
  if (!('disposableDomains' in body) || body.disposableDomains === undefined) return [];
  const domains = body.disposableDomains;
  if (!Array.isArray(domains) || domains.length > MAX_REQUEST_DISPOSABLE_DOMAINS) return null;
  const valid: string[] = [];
  for (const domain of domains) {
    if (typeof domain !== 'string' || domain.length > MAX_DOMAIN_LENGTH || !DOMAIN_PATTERN.test(domain)) return null;
    valid.push(domain);
  }
  return valid;
}

/**
 * The request body as text, read as a stream and abandoned once it exceeds `maxBytes`
 * (a chunked body has no Content-Length to check up front). Null when too large.
 */
async function readCappedText(request: Request, maxBytes: number): Promise<string | null> {
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export function classifyAccount(
  account: AccountFacts,
  excludedUserIds: ReadonlySet<string>,
  extraDisposableDomains: ReadonlySet<string> = new Set(),
): UserBucket {
  if (account.teamByWallet) return 'team_by_wallet';
  const [local = '', domain = ''] = account.email.split('@');
  const lowerLocal = local.toLowerCase();
  if (QA_PREFIX.test(lowerLocal)) return 'qa_prefix';
  const lowerDomain = domain.toLowerCase();
  if (INTERNAL_TEAM_DOMAIN.test(lowerDomain)) return 'internal_team_domain';
  if (isDisposableDomain(lowerDomain, extraDisposableDomains)) return 'disposable_mail_domain';
  if (INTERNAL_AGENT_OR_QA_NAME.test(lowerLocal)) return 'internal_agent_or_qa';
  if (TEST_OR_THROWAWAY_DOMAIN.test(lowerDomain)) return 'test_or_throwaway_domain';
  if (local.includes('+')) return 'plus_addressed';
  if (TEST_LIKE_NAME.test(lowerLocal)) return 'test_like_name';
  if (!account.hasSession && !account.hasKey) return 'never_completed_signup';
  if (excludedUserIds.has(account.id)) return 'explicit_exclusions';
  if (account.botLike) return 'bot_like';
  return 'real';
}

/** Counts only. Emails, addresses and ids are read in memory and never returned or logged. */
export async function collectUserMetrics(
  database: MetricsDatabase,
  env: Record<string, string | undefined> = process.env,
  now = new Date(),
  requestDisposableDomains: readonly string[] = [],
): Promise<UserMetrics> {
  const list = (value: string | undefined) => (value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
  const excluded = new Set(list(env.SCOREBOARD_EXCLUDE_USER_IDS));
  // Request and env lists add to the built-ins, but can never cover a protected domain. An
  // entry only takes effect once it matches enough accounts (see extraDisposable below).
  const requestedDisposable = new Set(
    [
      ...requestDisposableDomains,
      ...list(env.SCOREBOARD_DISPOSABLE_DOMAINS)
        .map((d) => d.toLowerCase().replace(/^@/, '').replace(/^\*\./, ''))
        .filter((d) => DOMAIN_PATTERN.test(d)),
    ].filter((d) => !isProtectedEntry(d)),
  );
  const addresses = [...new Set(list(env.SCOREBOARD_EXCLUDE_ADDRESSES).map((a) => a.toLowerCase()))]
    .filter((a) => ADDRESS_PATTERN.test(a));
  const since7d = new Date(now.getTime() - 7 * DAY_MS);
  const since30d = new Date(now.getTime() - 30 * DAY_MS);
  const tokenUsers = (since: Date) => database.oauthAccessToken.findMany({
    where: { createdAt: { gte: since } }, distinct: ['clientId', 'userId'], select: { clientId: true, userId: true },
  });
  const [users, sessions, keyOwners, botRows, teamRows, tokens7d, tokens30d, clients] = await Promise.all([
    database.user.findMany({ select: { id: true, email: true, createdAt: true } }),
    database.session.groupBy({ by: ['userId'], _max: { updatedAt: true } }),
    database.ethereumKey.findMany({ where: { userId: { not: null } }, distinct: ['userId'], select: { userId: true } }),
    database.$queryRaw<Array<{ userId: string }>>`
      SELECT DISTINCT "userId" FROM (
        SELECT "userId" FROM session
        WHERE "createdAt" >= ${since30d}
        GROUP BY "userId", date_trunc('day', "createdAt")
        HAVING count(*) >= ${BOT_SESSIONS_PER_DAY}
      ) bots`,
    addresses.length === 0
      ? Promise.resolve([] as Array<{ userId: string }>)
      : database.$queryRaw<Array<{ userId: string }>>`
          SELECT DISTINCT "userId" FROM ethereum_keys
          WHERE "userId" IS NOT NULL AND lower(address) = ANY(${addresses})`,
    tokenUsers(since7d),
    tokenUsers(since30d),
    database.oauthClient.findMany({ select: { clientId: true, name: true } }),
  ]);
  const lastActive = new Map(sessions.map((row) => [row.userId, row._max.updatedAt]));
  const hasKey = new Set(keyOwners.map((row) => row.userId));
  const botLike = new Set(botRows.map((row) => row.userId));
  const teamByWallet = new Set(teamRows.map((row) => row.userId));

  // A POSTed or env entry that matches fewer than 5 accounts is ignored. Otherwise a token
  // holder could add a domain and watch the real count drop to learn how many accounts sit at
  // it, below the 5-account floor that unclassifiedDomains keeps.
  const entryAccounts = new Map<string, number>();
  if (requestedDisposable.size > 0) {
    for (const user of users) {
      for (let d = (user.email.split('@')[1] ?? '').toLowerCase(); d; ) {
        if (requestedDisposable.has(d)) entryAccounts.set(d, (entryAccounts.get(d) ?? 0) + 1);
        const dot = d.indexOf('.');
        if (dot < 0) break;
        d = d.slice(dot + 1);
      }
    }
  }
  const extraDisposable = new Set([...requestedDisposable].filter((d) => (entryAccounts.get(d) ?? 0) >= MIN_ACCOUNTS_FOR_LIST_ENTRY));

  const buckets = Object.fromEntries(USER_BUCKETS.map((bucket) => [bucket, 0])) as UserMetrics['buckets'];
  const realUsers = new Set<string>();
  const realActive = { d1: 0, d7: 0, d30: 0 };
  let real = 0;
  let realNew7d = 0;
  const domainAccounts = new Map<string, number>();
  for (const user of users) {
    const bucket = classifyAccount({
      id: user.id,
      email: user.email,
      teamByWallet: teamByWallet.has(user.id),
      hasSession: lastActive.has(user.id),
      hasKey: hasKey.has(user.id),
      botLike: botLike.has(user.id),
    }, excluded, extraDisposable);
    // Candidates for the disposable list: domains no rule recognises (not ours, not
    // disposable, not reserved/test, not a major webmail). Counted per domain only.
    if (bucket !== 'team_by_wallet' && bucket !== 'qa_prefix' && bucket !== 'internal_team_domain'
        && bucket !== 'disposable_mail_domain' && bucket !== 'test_or_throwaway_domain') {
      const domain = (user.email.split('@')[1] ?? '').toLowerCase();
      if (DOMAIN_PATTERN.test(domain) && !isMajorWebmail(domain)) {
        domainAccounts.set(domain, (domainAccounts.get(domain) ?? 0) + 1);
      }
    }
    if (bucket !== 'real') {
      buckets[bucket] += 1;
      continue;
    }
    real += 1;
    realUsers.add(user.id);
    if (user.createdAt.getTime() >= since7d.getTime()) realNew7d += 1;
    const last = lastActive.get(user.id)?.getTime();
    if (last === undefined) continue;
    if (last >= now.getTime() - DAY_MS) realActive.d1 += 1;
    if (last >= since7d.getTime()) realActive.d7 += 1;
    if (last >= since30d.getTime()) realActive.d30 += 1;
  }

  // Per app: distinct real users with an access token in the window, grouped by the client's
  // display name (clients sharing a name are one app; a token whose client row is gone counts
  // under "unknown client"). Names come from whoever registered the client, so they are cleaned
  // and truncated; only apps with at least 5 real users are listed by name (top 50 by 30-day
  // users); every other app is summed, as distinct users, into one "other apps" row.
  const cleanName = (raw: string) => {
    const name = raw.replace(/\s+/g, ' ').trim().slice(0, APP_NAME_MAX_LENGTH).trim() || 'unnamed app';
    return name === OTHER_APPS_NAME ? `${name} (app)` : name;
  };
  const nameOf = new Map(clients.map((client) => [client.clientId, cleanName(client.name)]));
  const perApp = new Map<string, { d7: Set<string>; d30: Set<string> }>();
  const addTokens = (rows: ClientUser[], window: 'd7' | 'd30') => {
    for (const { clientId, userId } of rows) {
      if (!realUsers.has(userId)) continue;
      const name = nameOf.get(clientId) ?? 'unknown client';
      const entry = perApp.get(name) ?? { d7: new Set<string>(), d30: new Set<string>() };
      entry[window].add(userId);
      perApp.set(name, entry);
    }
  };
  addTokens(tokens30d, 'd30');
  addTokens(tokens7d, 'd7');
  const ranked = [...perApp]
    .map(([name, sets]) => ({ name, d7: sets.d7, d30: sets.d30 }))
    .sort((a, b) => b.d30.size - a.d30.size || b.d7.size - a.d7.size || a.name.localeCompare(b.name));
  const listed = ranked.filter((app) => app.d30.size >= APP_MIN_REAL_USERS).slice(0, APPS_MAX_LISTED);
  const apps = listed.map((app) => ({ name: app.name, real7d: app.d7.size, real30d: app.d30.size }));
  const otherD7 = new Set<string>();
  const otherD30 = new Set<string>();
  for (const app of ranked) {
    if (listed.includes(app)) continue;
    app.d7.forEach((id) => otherD7.add(id));
    app.d30.forEach((id) => otherD30.add(id));
  }
  if (otherD30.size > 0 || otherD7.size > 0) apps.push({ name: OTHER_APPS_NAME, real7d: otherD7.size, real30d: otherD30.size });
  const unclassifiedDomains = [...domainAccounts]
    .filter(([, accounts]) => accounts >= UNCLASSIFIED_MIN_ACCOUNTS)
    .map(([domain, accounts]) => ({ domain, accounts }))
    .sort((a, b) => b.accounts - a.accounts || a.domain.localeCompare(b.domain))
    .slice(0, UNCLASSIFIED_MAX_REPORTED);
  return { total: users.length, buckets, real, realActive, realNew7d, apps, unclassifiedDomains };
}

function authorized(authHeader: string | undefined): boolean {
  const token = process.env.INTERNAL_METRICS_TOKEN;
  if (!token) return false;
  if (!authHeader?.startsWith('Bearer ')) return false;

  const provided = authHeader.slice(7);
  const expectedBytes = Buffer.from(token);
  const providedBytes = Buffer.from(provided);
  if (expectedBytes.length !== providedBytes.length) return false;
  return timingSafeEqual(expectedBytes, providedBytes);
}

export async function collectInternalMetrics(database: MetricsDatabase, now = new Date()) {
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const [
    totalAccounts, newAccounts24h, totalKeys, activeKeys, newKeys24h,
    eligibleCanonicalUsers, missingCanonicalUsers, canonicalKeys,
    signingDecisions24h, signingAllows24h, signingDenials24h,
    enabledAppGrants, disabledAppGrants,
  ] = await Promise.all([
    database.user.count(),
    database.user.count({ where: { createdAt: { gte: since } } }),
    database.ethereumKey.count(),
    database.ethereumKey.count({ where: { archivedAt: null } }),
    database.ethereumKey.count({ where: { createdAt: { gte: since }, archivedAt: null } }),
    database.user.count({ where: { ethereumKeys: { some: { keyType: 'MANAGED', archivedAt: null } } } }),
    database.user.count({ where: {
      ethereumKeys: { some: { keyType: 'MANAGED', archivedAt: null } },
      NOT: { ethereumKeys: { some: { keyType: 'MANAGED', archivedAt: null, isCanonicalTinyCloud: true } } },
    } }),
    database.ethereumKey.count({ where: { keyType: 'MANAGED', archivedAt: null, isCanonicalTinyCloud: true } }),
    database.tinyCloudManageKeySigningDecision.count({ where: { createdAt: { gte: since } } }),
    database.tinyCloudManageKeySigningDecision.count({ where: { createdAt: { gte: since }, allowed: true } }),
    database.tinyCloudManageKeySigningDecision.count({ where: { createdAt: { gte: since }, allowed: false } }),
    database.tinyCloudManageKeyAppPreference.count({ where: { enabled: true, status: 'ENABLED' } }),
    database.tinyCloudManageKeyAppPreference.count({ where: { OR: [{ enabled: false }, { status: 'DISABLED' }] } }),
  ]);

  return {
    generatedAt: now.toISOString(),
    accounts: { total: totalAccounts, new24h: newAccounts24h },
    keys: { total: totalKeys, active: activeKeys, new24h: newKeys24h },
    tinyCloudManageKey: {
      canonicalResolution: {
        eligibleUsers: eligibleCanonicalUsers,
        canonicalKeys,
        missingCanonicalUsers,
      },
      appGrants: { enabled: enabledAppGrants, disabled: disabledAppGrants },
      signingDecisions24h: {
        total: signingDecisions24h,
        allowed: signingAllows24h,
        denied: signingDenials24h,
      },
    },
    // Process-local counts reset on restart and never include Origin values.
    originRefusals: getAccountOriginRefusals(),
  };
}

export async function collectNativeRenewalMetrics(database: MetricsDatabase, now = new Date()) {
  const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const since7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const where = { allowed: true, reason: { in: ['native_renew', 'native_renew_recovered'] } };
  const [dayGroups, weekGroups] = await Promise.all([
    database.tinyCloudManageKeySigningDecision.groupBy({
      by: ['clientId'], where: { ...where, createdAt: { gte: since24h } },
      _count: { _all: true }, _max: { createdAt: true },
    }),
    database.tinyCloudManageKeySigningDecision.groupBy({
      by: ['clientId'], where: { ...where, createdAt: { gte: since7d } },
      _count: { _all: true }, _max: { createdAt: true },
    }),
  ]);
  return {
    windowHours: [24, 168],
    clients: weekGroups.map((week) => ({
      clientId: week.clientId,
      renewals24h: dayGroups.find((day) => day.clientId === week.clientId)?._count._all ?? 0,
      renewals7d: week._count._all,
      lastRenewalAt: week._max.createdAt
        ? new Date(Math.floor(week._max.createdAt.getTime() / 3_600_000) * 3_600_000).toISOString()
        : null,
    })),
  };
}

export function createInternalMetricsRouter(getDatabase: () => MetricsDatabase) {
  const router = new Hono();

  router.get('/native-renewals', async (c) => {
    if (!process.env.INTERNAL_METRICS_TOKEN) return c.json({ error: 'Internal metrics are not configured' }, 503);
    if (!authorized(c.req.header('Authorization'))) return c.json({ error: 'Unauthorized' }, 401);
    c.header('Cache-Control', 'no-store');
    return c.json(await collectNativeRenewalMetrics(getDatabase()));
  });

  // GET and POST share one gate and one response. POST may carry `{ "disposableDomains": [...] }`:
  // the maintained list the internal Worker keeps, merged for this request only (never stored here).
  const respond = async (extraDisposableDomains: string[]) => {
    const database = getDatabase();
    const metrics = await collectInternalMetrics(database);
    // A failed users query must not take the existing counts down with it: the
    // consumer keeps its last good users block when this is null.
    const users = await collectUserMetrics(database, process.env, new Date(), extraDisposableDomains).catch((error) => {
      logError('error', 'api_error', error);
      return null;
    });
    return { ...metrics, users };
  };

  router.get('/', async (c) => {
    if (!process.env.INTERNAL_METRICS_TOKEN) {
      return c.json({ error: 'Internal metrics are not configured' }, 503);
    }

    if (!authorized(c.req.header('Authorization'))) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    return c.json(await respond([]));
  });

  router.post('/', async (c) => {
    if (!process.env.INTERNAL_METRICS_TOKEN) {
      return c.json({ error: 'Internal metrics are not configured' }, 503);
    }
    if (!authorized(c.req.header('Authorization'))) {
      return c.json({ error: 'Unauthorized' }, 401);
    }
    const declared = Number(c.req.header('Content-Length'));
    if (Number.isFinite(declared) && declared > MAX_REQUEST_BODY_BYTES) return c.json({ error: 'Payload too large' }, 413);
    const text = await readCappedText(c.req.raw, MAX_REQUEST_BODY_BYTES);
    if (text === null) return c.json({ error: 'Payload too large' }, 413);
    let body: unknown = {};
    if (text.trim() !== '') {
      try { body = JSON.parse(text); } catch { return c.json({ error: 'Invalid disposableDomains' }, 400); }
    }
    const disposableDomains = parseDisposableDomains(body);
    if (disposableDomains === null) return c.json({ error: 'Invalid disposableDomains' }, 400);
    c.header('Cache-Control', 'no-store');
    return c.json(await respond(disposableDomains));
  });

  return router;
}

export const internalMetricsRouter = createInternalMetricsRouter(
  () => getPrisma() as unknown as MetricsDatabase,
);
