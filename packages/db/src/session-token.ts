import { createHash } from 'node:crypto';

// `session.token` holds a SHA-256 digest of the session token, never the token. The token has about 190 bits of
// entropy, so an unkeyed hash is enough; the label keeps these digests apart from every other SHA-256 in the database.
// A token is only usable with a signature made under BETTER_AUTH_SECRET, so a stolen row opens nothing.
const SESSION_TOKEN_LABEL = 'openkey-session-token\0';

export function sessionTokenDigest(token: string): string {
  return createHash('sha256').update(SESSION_TOKEN_LABEL + token).digest('hex');
}

// Raw SQL must never filter or select `session.token`: only this extension knows the column holds a digest.
// session-token-raw-sql.test (apps/api) fails when non-test code mentions the session table and its token in raw SQL.

type Obj = Record<string, unknown>;
type Digests = Map<string, string>;

const isObject = (value: unknown): value is Obj => typeof value === 'object' && value !== null && !Array.isArray(value);

function unsupported(what: string): never {
  throw new Error(`Unsupported session token ${what}`);
}

function tokenValue(value: unknown, digests: Digests): string {
  if (typeof value !== 'string' || value === '') return unsupported('filter: not a non-empty string');
  const digest = sessionTokenDigest(value);
  digests.set(digest, value);
  return digest;
}

function tokenList(value: unknown, digests: Digests): string[] {
  if (!Array.isArray(value)) return unsupported('filter: not a list');
  return value.map((entry) => tokenValue(entry, digests));
}

function tokenFilter(filter: unknown, digests: Digests): unknown {
  if (typeof filter === 'string' || filter === undefined || filter === null) return tokenValue(filter, digests);
  if (!isObject(filter)) return unsupported('filter: not a string or an operator object');
  const hashed: Obj = {};
  for (const [operator, operand] of Object.entries(filter)) {
    if (operator === 'equals') hashed.equals = tokenValue(operand, digests);
    else if (operator === 'in') hashed.in = tokenList(operand, digests);
    else if (operator === 'notIn') hashed.notIn = tokenList(operand, digests);
    else if (operator === 'not') hashed.not = isObject(operand) ? tokenFilter(operand, digests) : tokenValue(operand, digests);
    else unsupported(`filter operator: ${operator}`);
  }
  if (Object.keys(hashed).length === 0) return unsupported('filter: no operator');
  return hashed;
}

function hashWhere(where: unknown, digests: Digests): unknown {
  if (Array.isArray(where)) return where.map((entry) => hashWhere(entry, digests));
  if (!isObject(where)) return where;
  const hashed: Obj = {};
  for (const [key, value] of Object.entries(where)) {
    if (key === 'AND' || key === 'OR' || key === 'NOT') hashed[key] = hashWhere(value, digests);
    else if (key === 'token') hashed[key] = tokenFilter(value, digests);
    else hashed[key] = value;
  }
  return hashed;
}

function hashData(data: unknown, digests: Digests): unknown {
  if (Array.isArray(data)) return data.map((entry) => hashData(entry, digests));
  if (!isObject(data) || data.token === undefined) return data;
  const token = data.token;
  if (isObject(token) && Object.keys(token).length === 1 && 'set' in token) {
    return { ...data, token: { set: tokenValue(token.set, digests) } };
  }
  return { ...data, token: tokenValue(token, digests) };
}

// A row whose token is a digest this call produced gets the raw token back (sign-in signs the created row's token into
// the cookie; refresh signs the updated row's). Any other row has no token the caller could know, so the field is removed.
function restoreRows(result: unknown, digests: Digests): unknown {
  if (Array.isArray(result)) {
    for (const row of result) restoreRows(row, digests);
    return result;
  }
  if (isObject(result) && 'token' in result) {
    const raw = typeof result.token === 'string' ? digests.get(result.token) : undefined;
    if (raw === undefined) delete result.token;
    else result.token = raw;
  }
  return result;
}

type Operation = { operation: string; args: Obj | undefined; query: (args: unknown) => Promise<unknown> };

async function sessionOperation({ args, query }: Operation): Promise<unknown> {
  const digests: Digests = new Map();
  const next: Obj = { ...args };
  for (const key of ['where', 'cursor']) {
    if (key in next) next[key] = hashWhere(next[key], digests);
  }
  // upsert carries `create` and `update`; create, update and createMany carry `data`.
  for (const key of ['data', 'create', 'update']) {
    if (key in next) next[key] = hashData(next[key], digests);
  }
  return restoreRows(await query(next), digests);
}

function mentionsToken(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(mentionsToken);
  if (!isObject(value)) return false;
  return Object.entries(value).some(([key, entry]) => key === 'token' || mentionsToken(entry));
}

function filtersSessionToken(where: unknown): boolean {
  if (Array.isArray(where)) return where.some(filtersSessionToken);
  if (!isObject(where)) return false;
  return Object.entries(where).some(([key, entry]) => (key === 'sessions' ? mentionsToken(entry) : filtersSessionToken(entry)));
}

function stripNestedTokens(result: unknown): unknown {
  if (Array.isArray(result)) {
    for (const row of result) stripNestedTokens(row);
    return result;
  }
  if (isObject(result) && Array.isArray(result.sessions)) {
    for (const row of result.sessions) if (isObject(row)) delete row.token;
  }
  return result;
}

// The `user` model reaches sessions through `sessions`. A nested write would store a token that is not a digest, and a
// nested filter on the token would never match, so both throw. Nested session rows read through `include` lose `token`.
async function userOperation({ args, query }: Operation): Promise<unknown> {
  for (const key of ['data', 'create', 'update']) {
    const data = args?.[key];
    for (const entry of Array.isArray(data) ? data : [data]) {
      if (isObject(entry) && 'sessions' in entry) unsupported('write: nested session write');
    }
  }
  if (filtersSessionToken(args?.where)) unsupported('filter: nested session filter');
  return stripNestedTokens(await query(args));
}

export function withSessionTokenDigests<Client extends { $extends: (extension: never) => unknown }>(client: Client): Client {
  const extension = {
    query: {
      session: { $allOperations: sessionOperation },
      user: { $allOperations: userOperation },
    },
  };
  return client.$extends(extension as never) as Client;
}
