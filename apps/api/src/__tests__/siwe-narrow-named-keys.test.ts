import { afterAll, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { prepareSession, parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import { narrowSiwePreservingImmutable } from '../services/siwe-narrow';

const home = mkdtempSync('/var/tmp/tc1783-test-home.');
process.env.HOME = home;
process.env.TC_HOME = home;
process.env.BUN_INSTALL_CACHE_DIR = home;
if (!process.env.HOME.startsWith('/var/tmp/tc1783-test-home.')) throw new Error('isolated test home required');
afterAll(() => rmSync(home, { recursive: true, force: true }));

const address = '0xFCAd0B19bB29D4674531d6f115237E16AfCE377c';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const secrets = `tinycloud:pkh:eip155:1:${address}:secrets`;
const bare = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;
const folder = `${bare}/qa/`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const primary = {
  kv: { '': ['tinycloud.kv/put', 'tinycloud.kv/get', 'tinycloud.kv/del', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
  sql: { '': ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema', 'tinycloud.sql/admin', 'tinycloud.sql/export'] },
  duckdb: { '': ['tinycloud.duckdb/read', 'tinycloud.duckdb/write', 'tinycloud.duckdb/admin', 'tinycloud.duckdb/describe', 'tinycloud.duckdb/export', 'tinycloud.duckdb/import', 'tinycloud.duckdb/execute'] },
  capabilities: { '': ['tinycloud.capabilities/read'] },
  hooks: { '': ['tinycloud.hooks/subscribe', 'tinycloud.hooks/register', 'tinycloud.hooks/list', 'tinycloud.hooks/unregister'] },
};
const siwe = prepareSession({
  address, chainId: 1, domain: 'openkey.so', spaceId: space, jwk,
  issuedAt: new Date().toISOString(), expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
  abilities: primary,
  spaceAbilities: { [space]: primary, [secrets]: { kv: { 'vault/secrets/': ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] } } },
  rawAbilities: {
    [bare]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create'],
    [folder]: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'],
  },
}).siwe as string;
const entries = parseRecapFromSiwe(siwe) as Array<{ service: string; space: string; path: string; actions: string[] }>;
const input = {
  originalSiwe: siwe, address, chainId: 1, domain: 'openkey.so', spaceId: space, jwk,
  issuedAt: siwe.match(/^Issued At: (.+)$/m)![1]!,
  expirationTime: siwe.match(/^Expiration Time: (.+)$/m)![1]!,
};

// The CLI's default request has several unselected services, so Preview must
// regenerate the selected ReCap while retaining both raw encryption rows.
test('previews the CLI default request with bare default and named qa keys selected', () => {
  const selected = entries.filter((entry) =>
    entry.service === 'capabilities' || entry.service === 'encryption' || entry.service === 'kv',
  );
  const narrowed = narrowSiwePreservingImmutable({ ...input, narrowedEntries: selected });
  expect(narrowed.ok, narrowed.ok ? '' : narrowed.code).toBe(true);
  if (!narrowed.ok) return;
  const actual = parseRecapFromSiwe(narrowed.siwe) as typeof entries;
  expect(actual).toEqual(selected);
  expect(actual.find((entry) => entry.path === bare)?.actions).toEqual(['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create']);
  expect(actual.find((entry) => entry.path === folder)?.actions).toEqual(['tinycloud.encryption/decrypt', 'tinycloud.encryption/key.create']);
});

test('previews a request with only the bare network retained', () => {
  const selected = entries.filter((entry) => entry.service !== 'encryption' || entry.path === bare);
  const narrowed = narrowSiwePreservingImmutable({ ...input, narrowedEntries: selected });
  expect(narrowed.ok, narrowed.ok ? '' : narrowed.code).toBe(true);
  if (!narrowed.ok) return;
  expect((parseRecapFromSiwe(narrowed.siwe) as typeof entries).find((entry) => entry.path === folder)).toBeUndefined();
});
