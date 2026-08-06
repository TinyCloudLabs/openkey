import { describe, expect, test } from 'bun:test';

const productionRoots = [
  'apps/api/src',
  'apps/web/src',
  'packages/sdk/src',
  'packages/sdk-react-native/src',
  'packages/cli/src',
  'scripts',
  '.github/workflows',
];

const deletedSurface = [
  /managed-accounts/i,
  /tenant-accounts/i,
  /management-credentials/i,
  /personal-managed-accounts/i,
  /OpenKeyManagementClient/,
  /managedAccount\b/,
  /keyCustody\b/,
  /ejectRequest\b/,
  /organizationServerCredential\b/,
  /MANAGED_ACCOUNT/,
  /TENANT_MANAGED/,
];

describe('TC-488 deleted-surface caller inventory', () => {
  test('finds no production-like caller of removed organization custody surfaces', async () => {
    const matches: string[] = [];
    for (const root of productionRoots) {
      for await (const relativePath of new Bun.Glob('**/*.{ts,svelte,yml,yaml}').scan(root)) {
        const path = `${root}/${relativePath}`;
        if (
          path.includes('/__tests__/')
          || path.includes('.test.')
          || path.endsWith('verify-tc-488-cutover.ts')
          || path.endsWith('report-tc-492-canonical-cutover.ts')
          || path.endsWith('tc-492-tenant-custody-digest.ts')
          || path.endsWith('tc-492-production-cutover.yml')
        ) continue;
        const source = await Bun.file(path).text();
        if (deletedSurface.some((pattern) => pattern.test(source))) matches.push(path);
      }
    }
    expect(matches).toEqual([]);
  });
});
