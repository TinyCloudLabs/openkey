import { expect, test } from 'bun:test';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

// `session.token` holds a digest that only the @openkey/db extension (packages/db/src/session-token.ts) knows how to
// write and filter. Raw SQL bypasses it, so non-test code must not name the session table together with its token column.
const root = resolve(import.meta.dir, '../../../..');
const RAW_CALL = /\$(?:queryRaw|executeRaw)(?:Unsafe)?\b/g;

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) return name === '__tests__' || name === 'generated' || name === 'node_modules' ? [] : sourceFiles(path);
    return /\.ts$/.test(name) && !/\.test\.ts$/.test(name) ? [path] : [];
  });
}

/** The first string or template literal after each raw SQL call. */
function rawSqlLiterals(source: string): string[] {
  const literals: string[] = [];
  for (const match of source.matchAll(RAW_CALL)) {
    let index = match.index! + match[0].length;
    while (index < source.length && !'`\'"'.includes(source[index]!)) index += 1;
    const quote = source[index];
    if (quote === undefined) continue;
    let end = index + 1;
    while (end < source.length && source[end] !== quote) end += source[end] === '\\' ? 2 : 1;
    literals.push(source.slice(index + 1, end));
  }
  return literals;
}

/** The session table named in the SQL together with a token column that is not another table's alias.column. */
function readsSessionToken(sql: string): boolean {
  const namesSession = /\b(?:from|join|update|into)\s+"?session"?(?![\w.])/i.test(sql);
  const namesToken = /(?<![\w.])"?token"?\b/.test(sql) || /\bs\.token\b|"?session"?\."?token\b/i.test(sql);
  return namesSession && namesToken;
}

test('no non-test raw SQL names the session table with its token column', () => {
  const offenders: string[] = [];
  for (const directory of ['apps/api/src', 'packages/db/src']) {
    for (const file of sourceFiles(join(root, directory))) {
      for (const literal of rawSqlLiterals(readFileSync(file, 'utf8'))) {
        if (readsSessionToken(literal)) offenders.push(file.slice(root.length + 1));
      }
    }
  }
  expect(offenders).toEqual([]);
});

test('the scan sees the SQL a future query would write', () => {
  const lock = 'await tx.$queryRaw`SELECT id FROM "session" WHERE id = ${id} FOR UPDATE`;';
  const byToken = 'await tx.$queryRaw`SELECT id FROM "session" WHERE token = ${token}`;';
  const unsafe = "await db.$executeRawUnsafe('DELETE FROM session WHERE \"token\" = $1', token);";
  const joined = 'await db.$queryRaw<Row[]>`UPDATE session s SET "updatedAt" = now() WHERE s.token = ${token}`;';
  const refreshToken = 'await db.$queryRaw`SELECT 1 FROM oauth_refresh_token r JOIN session s ON s.id = r."sessionId" WHERE r.token = ${hash}`;';
  expect(rawSqlLiterals(lock).some(readsSessionToken)).toBe(false);
  expect(rawSqlLiterals(refreshToken).some(readsSessionToken)).toBe(false);
  for (const source of [byToken, unsafe, joined]) expect(rawSqlLiterals(source).some(readsSessionToken)).toBe(true);
});
