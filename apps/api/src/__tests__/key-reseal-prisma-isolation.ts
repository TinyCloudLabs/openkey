// Only the isolated Prisma acceptance child preloads this test-scoped marker.
Object.defineProperty(globalThis, Symbol.for('openkey.test.key-reseal-prisma-isolated'), { value: true });
