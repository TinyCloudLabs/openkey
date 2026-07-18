import { describe, expect, test } from 'bun:test';

const routeSources = [
  'apps/api/src/routes/keys.ts',
  'apps/api/src/routes/delegate.ts',
  'apps/api/src/routes/secrets.ts',
  'apps/api/src/routes/account.ts',
  'apps/api/src/auth.ts',
];

describe('personal-key query contract', () => {
  test('every personal-key route scopes its EthereumKey reads and mutations by keyPurpose', async () => {
    for (const path of routeSources) {
      const source = await Bun.file(path).text();
      expect(source).toContain("keyPurpose: 'PERSONAL'");
    }
  });

  test('account deletion cannot delete managed-account keys through a broad user filter', async () => {
    const source = await Bun.file('apps/api/src/routes/account.ts').text();
    expect(source).toMatch(/ethereumKey\.deleteMany\(\{\s*where:\s*\{[\s\S]*?keyPurpose:\s*'PERSONAL'/);
    expect(source).toContain("MANAGED_ACCOUNTS_BLOCK_DELETION");
  });
});
