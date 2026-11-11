// TC-2234: the share key OpenKey generates for one invitation reads as that, without its id.
import { expect, test } from 'bun:test';
import { buildStatements, type CapabilityGrant } from '../src/index.js';

const owner = 'did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const id = '0123456789abcdef0123456789abcdef';
const create = 'tinycloud.encryption/key.create';
const decrypt = 'tinycloud.encryption/decrypt';

function grant(resource: string, abilities: string[]): CapabilityGrant {
  return {
    id: `tinycloud.encryption\0${resource}\0`, family: 'encryption-decrypt', severity: 'sensitive',
    service: 'tinycloud.encryption', space: resource, path: '', owner: null, ownedBySelf: true,
    displayLabel: '', metadataLabel: null, resourceService: null,
    actions: abilities.map((ability) => ({
      id: `tinycloud.encryption\0${resource}\0\0${ability}`, ability, verb: ability.split('/')[1]!,
      required: false, selected: true, editable: true, caveats: [{}],
    })),
  };
}

test('the invitation key reads as one key for this invitation, and never shows its id', () => {
  const rows = buildStatements(grant(`urn:tinycloud:encryption:${owner}:default/share/${id}`, [create, decrypt]));
  expect(rows.map((row) => row.primaryText)).toEqual([
    'Create an encryption key for this invitation only',
    'Open this shared file',
  ]);
  for (const row of rows) expect(row.primaryText).not.toContain(id);
});

test.each([
  ['an id that is not 32 lowercase hex', `default/share/${id.toUpperCase()}`],
  ['a nested key', `default/share/${id}/x`],
  ['another network', `vault/share/${id}`],
])('a key create on %s keeps its own sentence', (_name, tail) => {
  const [row] = buildStatements(grant(`urn:tinycloud:encryption:${owner}:${tail}`, [create]));
  expect(row!.primaryText).not.toBe('Create an encryption key for this invitation only');
});
