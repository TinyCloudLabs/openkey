import { describe, expect, test } from 'bun:test';
import { findUnscopedEthereumKeyAccess, type AllowEntry } from './lint-ethereum-key-access';

const FILE = 'routes/example.ts';

describe('ethereumKey access lint', () => {
  test('accepts a call scoped with personalKeyWhere', () => {
    const source = `await prisma.ethereumKey.findMany({ where: { ...personalKeyWhere(userId), archivedAt: null } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toEqual([]);
  });

  test('accepts a multi-line call scoped with primaryKeyWhere', () => {
    const source = `await tx.ethereumKey.findFirst({
      where: {
        ...primaryKeyWhere(user.id),
      },
    });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toEqual([]);
  });

  test('accepts a call with an explicit custody filter', () => {
    const source = `await db.ethereumKey.count({ where: { custody: 'PERSONAL' } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toEqual([]);
  });

  test('flags an unscoped lookup by id, with its line and method', () => {
    const source = `const ok = 1;
const key = await prisma.ethereumKey.findFirst({ where: { id: keyId } });`;
    const violations = findUnscopedEthereumKeyAccess(FILE, source, []);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ file: FILE, line: 2, method: 'findFirst' });
  });

  test('flags an unscoped write, not only reads', () => {
    const source = `await prisma.ethereumKey.updateMany({ where: { address }, data: { archivedAt: new Date() } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, []).map((v) => v.method)).toEqual(['updateMany']);
  });

  test('does not stop at a bracket inside a string before the scope marker', () => {
    const scoped = `findMany({ where: { note: ')', OR: [f(x)], ...personalKeyWhere(u) } })`;
    expect(findUnscopedEthereumKeyAccess(FILE, `prisma.ethereumKey.${scoped}`, [])).toEqual([]);
  });

  test('a balanced nested call without a scope marker is still flagged', () => {
    const unscoped = `prisma.ethereumKey.findMany({ where: { note: ')', OR: [f(x)] } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, unscoped, [])).toHaveLength(1);
  });

  test('ignores other models that share a method name', () => {
    const source = `await prisma.ethereumKeyBackup.findMany({ where: { id } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toEqual([]);
  });

  test('an allowlist snippet exempts only the matching call in its file', () => {
    const allow: AllowEntry[] = [{ file: FILE, includes: 'where: { address: body.address }', reason: 'test' }];
    const allowed = `prisma.ethereumKey.findUnique({
      where: { address: body.address },
    });`;
    const other = `prisma.ethereumKey.findUnique({ where: { address: otherAddress } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, allowed, allow)).toEqual([]);
    expect(findUnscopedEthereumKeyAccess(FILE, other, allow)).toHaveLength(1);
    expect(findUnscopedEthereumKeyAccess('routes/elsewhere.ts', allowed, allow)).toHaveLength(1);
  });

  test("a '*' allowlist entry exempts every call in its file only", () => {
    const allow: AllowEntry[] = [{ file: FILE, includes: '*', reason: 'test' }];
    const source = `prisma.ethereumKey.count();
prisma.ethereumKey.findMany({ where: { id } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, allow)).toEqual([]);
    expect(findUnscopedEthereumKeyAccess('routes/elsewhere.ts', source, allow)).toHaveLength(2);
  });
});
