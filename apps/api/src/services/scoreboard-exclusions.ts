export const SCOREBOARD_EXCLUSION_CRITERIA = 'Excludes team, QA, agent/service and throwaway-mailbox accounts on the shared test-identity list (v1). Entries marked unsure are kept.';

type Account = { id: string; email: string; ethereumKeys: { address: string }[] };
type Rules = {
  userIds: Set<string>;
  emails: Set<string>;
  domains: Set<string>;
  addresses: Set<string>;
  keyDids: Set<string>;
};
export type ExclusionDatabase = {
  user: {
    findMany(args: { select: { id: true; email: true; ethereumKeys: { select: { address: true } } } }): Promise<Account[]>;
  };
  $queryRaw<T>(query: TemplateStringsArray, ...values: unknown[]): Promise<T>;
};

export function parseExclusions(raw: string | undefined): Rules {
  const rules: Rules = { userIds: new Set(), emails: new Set(), domains: new Set(), addresses: new Set(), keyDids: new Set() };
  try {
    const entries: unknown = JSON.parse(raw?.trim() || '[]');
    if (!Array.isArray(entries)) throw new Error();
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') throw new Error();
      if (['status', 'confidence', 'decision'].some((column) =>
        typeof entry[column] === 'string' && entry[column].trim().toLowerCase() === 'unsure')) continue;
      if (typeof entry.value !== 'string' || !entry.value.trim()) throw new Error();
      const value = entry.value.trim();
      switch (entry.kind) {
        case 'user_id': rules.userIds.add(value); break;
        case 'email':
          if (!/^[^@\s]+@[^@\s]+$/.test(value)) throw new Error();
          rules.emails.add(value.toLowerCase());
          break;
        case 'email_domain':
          if (!/^[a-z0-9]+(?:[.-][a-z0-9-]+)*\.[a-z]{2,}$/i.test(value)) throw new Error();
          rules.domains.add(value.toLowerCase());
          break;
        case 'evm_address':
          if (!/^0x[0-9a-f]{40}$/i.test(value)) throw new Error();
          rules.addresses.add(value.toLowerCase());
          break;
        case 'did': {
          const pkh = /^did:pkh:eip155:\d+:(0x[0-9a-f]{40})$/i.exec(value);
          if (pkh) rules.addresses.add(pkh[1]!.toLowerCase());
          else if (/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(value)) rules.keyDids.add(value);
          else throw new Error();
          break;
        }
        default: throw new Error();
      }
    }
  } catch {
    throw new Error('Invalid scoreboard exclusions');
  }
  return rules;
}

export function excludedAccountIds(accounts: readonly Account[], rules: Rules, mappedKeyUsers?: ReadonlySet<string>): Set<string> {
  const excluded = new Set<string>();
  for (const account of accounts) {
    const email = account.email.toLowerCase();
    if (rules.userIds.has(account.id) || mappedKeyUsers?.has(account.id)
      || rules.emails.has(email) || rules.domains.has(email.slice(email.lastIndexOf('@') + 1))
      || account.ethereumKeys.some((key) => rules.addresses.has(key.address.toLowerCase()))) {
      excluded.add(account.id);
    }
  }
  return excluded;
}

export async function resolveScoreboardExclusions(
  database: ExclusionDatabase,
  env: Record<string, string | undefined> = process.env,
): Promise<{ userIds: ReadonlySet<string>; clientIds: ReadonlySet<string> }> {
  // The legacy env remains available for old releases; this resolver never falls back to it. Details: TC-1480
  const rules = parseExclusions(env.SCOREBOARD_EXCLUSIONS);
  const clientIds = new Set((env.SCOREBOARD_EXCLUDE_CLIENT_IDS ?? '').split(',').map((value) => value.trim()).filter(Boolean));
  if (![rules.userIds, rules.emails, rules.domains, rules.addresses, rules.keyDids].some((values) => values.size)) {
    return { userIds: new Set(), clientIds };
  }
  // No archivedAt filter: archived account keys still identify their account. Details: TC-1480
  const accounts = await database.user.findMany({ select: { id: true, email: true, ethereumKeys: { select: { address: true } } } });
  let mappedKeyUsers = new Set<string>();
  if (rules.keyDids.size) {
    const dids = [...rules.keyDids];
    const rows = await database.$queryRaw<{ userId: string }[]>`
      SELECT "approvedByUserId" AS "userId" FROM device_authorization
        WHERE "sessionDid" = ANY(${dids}) AND "approvedByUserId" IS NOT NULL
      UNION SELECT "approvedByUserId" AS "userId" FROM approval_request
        WHERE issuer = ANY(${dids}) AND "approvedByUserId" IS NOT NULL
      UNION SELECT "userId" FROM tinycloud_native_request
        WHERE "sessionDid" = ANY(${dids}) AND "userId" IS NOT NULL
      UNION SELECT "userId" FROM tinycloud_native_grant WHERE "sessionDid" = ANY(${dids})`;
    mappedKeyUsers = new Set(rows.map((row) => row.userId));
  }
  return { userIds: excludedAccountIds(accounts, rules, mappedKeyUsers), clientIds };
}
