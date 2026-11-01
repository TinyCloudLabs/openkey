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

  // TC-1518 invariant: an ORG key never reaches a personal path. The scope marker is the PERSONAL filter inside
  // the `where` (or the PERSONAL value a create writes), never any `custody:`.
  test("an explicit custody: 'ORG' filter is not a personal scope", () => {
    const source = `await prisma.ethereumKey.findMany({ where: { custody: 'ORG' } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toHaveLength(1);
  });

  test('a PERSONAL custody written only in data does not scope the where of an update', () => {
    const source = `await prisma.ethereumKey.updateMany({ where: { id }, data: { custody: 'PERSONAL' } });`;
    expect(findUnscopedEthereumKeyAccess(FILE, source, []).map((v) => v.method)).toEqual(['updateMany']);
  });

  test('a create is scoped by writing PERSONAL custody in its data', () => {
    expect(findUnscopedEthereumKeyAccess(FILE, `await prisma.ethereumKey.create({ data: { userId, custody: 'PERSONAL', address } });`, [])).toEqual([]);
    expect(findUnscopedEthereumKeyAccess(FILE, `await prisma.ethereumKey.create({ data: { userId, address } });`, [])).toHaveLength(1);
    expect(findUnscopedEthereumKeyAccess(FILE, `await prisma.ethereumKey.create({ data: { custody: 'ORG', address } });`, [])).toHaveLength(1);
  });

  test('a PERSONAL custody filter in the where scopes a read, with either quote style', () => {
    expect(findUnscopedEthereumKeyAccess(FILE, `prisma.ethereumKey.findFirst({ where: { id, custody: "PERSONAL" } })`, [])).toEqual([]);
    expect(findUnscopedEthereumKeyAccess(FILE, `prisma.ethereumKey.findFirst({ where: { id, custody: 'PERSONAL' } })`, [])).toEqual([]);
  });

  describe('a relation filter through `key` (another model reading a key it can reach)', () => {
    test('is flagged without a PERSONAL custody filter', () => {
      const source = `const rows = await prisma.tinyCloudBootstrapState.findMany({
        where: { key: { is: { keyType: 'MANAGED', archivedAt: null } } },
        select: { key: { select: { sealedBlob: true } } },
      });`;
      const violations = findUnscopedEthereumKeyAccess(FILE, source, []);
      expect(violations).toHaveLength(1);
      expect(violations[0]).toMatchObject({ file: FILE, line: 2, method: 'key.is' });
    });

    test("is flagged with custody: 'ORG'", () => {
      const source = `prisma.tinyCloudBootstrapState.findMany({ where: { key: { is: { custody: 'ORG' } } } });`;
      expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toHaveLength(1);
    });

    test('is accepted with the PERSONAL custody filter', () => {
      const source = `prisma.tinyCloudBootstrapState.updateMany({ where: { key: { is: { custody: 'PERSONAL', keyType: 'MANAGED' } } }, data: {} });`;
      expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toEqual([]);
    });

    test('a select of key columns, or a plain data object named key, is not a filter', () => {
      const source = `prisma.tinyCloudBootstrapState.findMany({ select: { key: { select: { id: true } } } });
      await ensure({ key: { id: row.key.id, keyType: row.key.keyType } });`;
      expect(findUnscopedEthereumKeyAccess(FILE, source, [])).toEqual([]);
    });

    test('an allowlist entry exempts it like any other access', () => {
      const source = `prisma.keyGrant.findMany({ where: { key: { is: { custody: 'ORG' } } } });`;
      const allow: AllowEntry[] = [{ file: FILE, includes: "key: { is: { custody: 'ORG' } }", reason: 'test' }];
      expect(findUnscopedEthereumKeyAccess(FILE, source, allow)).toEqual([]);
    });
  });
});
