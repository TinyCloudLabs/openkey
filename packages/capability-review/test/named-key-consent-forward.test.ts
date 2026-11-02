import { afterAll, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { buildStatement, buildStatements, type CapabilityGrant } from '../src/index.js';

const home = mkdtempSync('/var/tmp/tc1783ff-test.');
for (const name of ['HOME', 'COURIER_HOME', 'TC_HOME', 'XDG_CONFIG_HOME', 'BUN_INSTALL_CACHE_DIR']) process.env[name] = home;
if (process.env.HOME !== home || !home.startsWith('/var/tmp/tc1783ff-test.')) throw new Error('isolated test home required');
afterAll(() => rmSync(home, { recursive: true, force: true }));

const owner = 'did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const base = `urn:tinycloud:encryption:${owner}:default`;

function grant(resource: string, abilities: string[], ownedBySelf: boolean | null): CapabilityGrant {
  return {
    id: `tinycloud.encryption\0${resource}\0`, family: 'encryption-decrypt', severity: 'sensitive',
    service: 'tinycloud.encryption', space: resource, path: '', owner: null, ownedBySelf,
    displayLabel: '', metadataLabel: null, resourceService: null,
    actions: abilities.map((ability) => ({
      id: `tinycloud.encryption\0${resource}\0\0${ability}`, ability, verb: ability.split('/')[1]!,
      required: false, selected: true, editable: true, caveats: [{}],
    })),
  };
}

const create = 'tinycloud.encryption/key.create';
const decrypt = 'tinycloud.encryption/decrypt';

test('self-owned exact keys retain the account wording', () => {
  const rows = buildStatements(grant(`${base}/qa/x`, [create, decrypt], true));
  expect(rows.map((row) => row.primaryText)).toEqual([
    'Create your encryption key default/qa/x',
    'Decrypt data with your key default/qa/x',
  ]);
});

test('a foreign exact key uses literal abilities rather than signer ownership wording', () => {
  const rows = buildStatements(grant(`${base}/qa/x`, [create, decrypt], false));
  expect(rows.map((row) => row.primaryText)).toEqual([
    "Create another user's keys",
    "Decrypt another user's data",
  ]);
});

test('a foreign or unidentified prefix does not claim that its keys belong to the signer', () => {
  for (const ownedBySelf of [false, null]) {
    for (const network of ['default', 'vault']) {
      const resource = `urn:tinycloud:encryption:${owner}:${network}/qa/`;
      expect(buildStatements(grant(resource, [create, decrypt], ownedBySelf)).map((row) => row.primaryText)).toEqual([
        ownedBySelf === false ? "Create another user's keys" : 'Create keys',
        ownedBySelf === false ? "Decrypt another user's data" : 'Decrypt data',
      ]);
    }
  }
});

test('self-owned folder decrypt states that keys created later are included', () => {
  expect(buildStatement(grant(`${base}/qa/`, [decrypt], true)).primaryText).toBe(
    'Decrypt data locked with your keys in `qa/`',
  );
});

test('failing encryption URN fallback is marked as already escaped', () => {
  const row = buildStatement(grant(`${base}/qa/\u202ex`, [decrypt], true));
  expect(row.primaryText).toBe('Unknown action: tinycloud.encryption/decrypt');
  expect(row.literalEscaped).toBe(true);
});
