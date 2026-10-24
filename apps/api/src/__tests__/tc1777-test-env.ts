// Points HOME and every tool home at a private temp directory for the whole
// test file that imports this module, and checks it before anything runs.
// Import it first in a test file.

import { afterAll } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';

const TOOL_HOMES = [
  'HOME',
  'COURIER_HOME',
  'BUN_INSTALL_CACHE_DIR',
  'XDG_CONFIG_HOME',
  'XDG_DATA_HOME',
  'XDG_CACHE_HOME',
  'TINYCLOUD_HOME',
] as const;

const saved = new Map<string, string | undefined>(TOOL_HOMES.map((name) => [name, process.env[name]]));
export const TC1777_TEST_HOME = mkdtempSync('/var/tmp/tc1777.');
for (const name of TOOL_HOMES) process.env[name] = TC1777_TEST_HOME;

for (const name of TOOL_HOMES) {
  if (process.env[name] !== TC1777_TEST_HOME || !TC1777_TEST_HOME.startsWith('/var/tmp/tc1777.')) {
    throw new Error(`${name} is not the test home`);
  }
}

afterAll(() => {
  for (const [name, value] of saved) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(TC1777_TEST_HOME, { recursive: true, force: true });
});
