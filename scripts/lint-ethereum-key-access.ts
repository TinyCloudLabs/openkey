// TC-1518 K1 T1 guard: every `ethereumKey` call in apps/api must be scoped to
// personal keys (or primary keys, which spread the personal scope), so an
// organization key (custody ORG, userId null) can never reach a personal-key
// route. A call is accepted when its argument list contains one of the scope
// markers below. Any other call fails unless it is allowlisted with a reason.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

export type AccessViolation = { file: string; line: number; method: string; args: string };
export type AllowEntry = { file: string; includes: string; reason: string };

const ACCESS = /\.ethereumKey\s*\.\s*(\w+)\s*\(/g;
const SCOPE_MARKERS = [/\bpersonalKeyWhere\s*\(/, /\bprimaryKeyWhere\s*\(/, /\bcustody\s*:/];

// Intentional unscoped sites. `includes` is a whitespace-normalised snippet of the
// call's arguments, or '*' to allow every call in the file.
export const ALLOWLIST: AllowEntry[] = [
  {
    file: 'routes/keys.ts',
    includes: 'where: { address: body.address }',
    reason: 'global existence check on a candidate address before linking; an ORG row must also block re-linking an address',
  },
  {
    file: 'routes/internal-metrics.ts',
    includes: '*',
    reason: 'global admin metric aggregates over all keys (count only); returns no user data',
  },
];

function balancedArgs(source: string, openIndex: number): string {
  let depth = 0;
  let quote: string | null = null;
  for (let i = openIndex; i < source.length; i++) {
    const ch = source[i];
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch;
    else if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) return source.slice(openIndex + 1, i);
    }
  }
  throw new Error(`unbalanced call starting at offset ${openIndex}`);
}

function lineOf(source: string, offset: number): number {
  return source.slice(0, offset).split('\n').length;
}

function isAllowed(file: string, normalizedArgs: string, allow: AllowEntry[]): boolean {
  return allow.some(
    (entry) => entry.file === file && (entry.includes === '*' || normalizedArgs.includes(entry.includes)),
  );
}

export function findUnscopedEthereumKeyAccess(
  file: string,
  source: string,
  allow: AllowEntry[] = ALLOWLIST,
): AccessViolation[] {
  const violations: AccessViolation[] = [];
  for (const match of source.matchAll(ACCESS)) {
    const openIndex = (match.index ?? 0) + match[0].length - 1;
    const args = balancedArgs(source, openIndex);
    if (SCOPE_MARKERS.some((marker) => marker.test(args))) continue;
    const normalized = args.replace(/\s+/g, ' ').trim();
    if (isAllowed(file, normalized, allow)) continue;
    violations.push({
      file,
      line: lineOf(source, match.index ?? 0),
      method: match[1],
      args: normalized.slice(0, 140),
    });
  }
  return violations;
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return name === '__tests__' ? [] : sourceFiles(full);
    return name.endsWith('.ts') && !name.endsWith('.test.ts') && !name.endsWith('.d.ts') ? [full] : [];
  });
}

if (import.meta.main) {
  const root = resolve(import.meta.dir, '../apps/api/src');
  const violations = sourceFiles(root).flatMap((full) =>
    findUnscopedEthereumKeyAccess(relative(root, full), readFileSync(full, 'utf8')),
  );
  if (violations.length > 0) {
    for (const v of violations) {
      console.error(`${v.file}:${v.line} ethereumKey.${v.method}(${v.args}) is not personal- or primary-scoped`);
    }
    console.error(`${violations.length} unscoped ethereumKey access(es); scope them or allowlist with a reason`);
    process.exit(1);
  }
  console.log('ethereumKey access lint: all calls scoped or allowlisted');
}
