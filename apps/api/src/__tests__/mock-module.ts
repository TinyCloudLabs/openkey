import { afterAll, mock } from 'bun:test';
import { readFileSync } from 'node:fs';

// bun's `mock.module()` replaces a module for the whole `bun test` process,
// and `mock.restore()` does not undo it (TC-928). A bare mock leaks into every
// later file: exports the factory left out disappear ("Export named 'seal' not
// found"), and the stand-ins stay in place for files that expect the real
// module. These helpers scope a mock to the calling test file.
//
// Call them at the top level of a test file, before importing the code under
// test. Factories run lazily, like `mock.module()` factories. Relative
// specifiers resolve from this directory, the same as from a test file beside
// it.
//
// Code under test that captures a mocked value when it loads (for example a
// route's module-level `createPrismaClient()`) keeps it for good. Import such
// modules with a file-specific query string (`'../routes/keys?my-test' as
// string`): every file then gets its own instance, bound to its own mocks.

type Exports = Record<string, any>;

/**
 * Mock modules whose real code loads safely in a unit test. Each factory
 * returns only the exports it overrides; every other real export is kept. The
 * real exports go back once the file finishes.
 */
export async function mockModules(factories: Record<string, (actual: Exports) => Exports>): Promise<void> {
  const actuals: Record<string, Exports> = {};
  for (const specifier of Object.keys(factories)) {
    // Copy: once mocked, bun rewrites the live namespace object in place.
    actuals[specifier] = { ...(await import(specifier)) };
  }
  for (const [specifier, factory] of Object.entries(factories)) {
    const actual = actuals[specifier]!;
    mock.module(specifier, () => ({ ...actual, ...factory(actual) }));
  }
  afterAll(() => {
    for (const [specifier, actual] of Object.entries(actuals)) {
      mock.module(specifier, () => actual);
    }
  });
}

/**
 * Replace modules whose real code cannot load in a unit test without its
 * services: the session middleware loads Better Auth, and module-level
 * `createPrismaClient()` calls open the default database. Exports a factory
 * leaves out, and every export once the file finishes, become stand-ins that
 * throw when used. A file that relies on one of these modules without
 * replacing it then fails the same way in the aggregate run as on its own.
 */
export function replaceModules(factories: Record<string, () => Exports>): void {
  for (const [specifier, factory] of Object.entries(factories)) {
    mock.module(specifier, () => ({ ...unavailableExports(specifier), ...factory() }));
  }
  afterAll(() => {
    for (const specifier of Object.keys(factories)) {
      mock.module(specifier, () => unavailableExports(specifier));
    }
  });
}

function unavailableExports(specifier: string): Exports {
  const path = Bun.resolveSync(specifier, import.meta.dir);
  const { exports } = new Bun.Transpiler({ loader: 'ts' }).scan(readFileSync(path, 'utf8'));
  return Object.fromEntries(exports.map((name) => [name, () => {
    throw new Error(`${specifier} cannot load in a unit test; replace it with replaceModules() in this test file`);
  }]));
}
