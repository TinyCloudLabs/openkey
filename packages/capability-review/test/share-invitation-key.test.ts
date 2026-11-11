// TC-2234: the share key OpenKey generates for one invitation reads as that, without its id.
import { expect, test } from 'bun:test';
import { buildShareInvitationSummaryStatements, buildStatements, buildSummaryStatements, shareInvitationActionLabel, type CapabilityGrant } from '../src/index.js';

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

test.each([
  ['session', 'Read Project notes messages with this invitation\'s key'],
  ['file', 'Unlock Project notes with this invitation\'s key'],
] as const)('on a %s invitation the key decrypt row names the subject', (subjectKind, unlock) => {
  const rows = buildShareInvitationSummaryStatements(
    [grant(`urn:tinycloud:encryption:${owner}:default/share/${id}`, [create, decrypt])],
    { subjectKind, subjectName: 'Project notes' },
  );
  expect(rows.map((row) => row.primaryText).sort()).toEqual(['Create an encryption key for this invitation only', unlock]);
});

test.each([
  ['another owner', () => ({ ...grant(`urn:tinycloud:encryption:${owner}:default/share/${id}`, [decrypt]), ownedBySelf: false })],
  ['a key that is not an invitation key', () => grant(`urn:tinycloud:encryption:${owner}:default/share/abc123`, [decrypt])],
  ['a second grant beside the key', () => [grant(`urn:tinycloud:encryption:${owner}:default/share/${id}`, [decrypt]), grant(`urn:tinycloud:encryption:${owner}:default/share/abc123`, [decrypt])]],
] as const)('with %s the rows stay the ordinary ones', (_name, make) => {
  const made = make();
  const grants = Array.isArray(made) ? made : [made];
  expect(buildShareInvitationSummaryStatements(grants, { subjectKind: 'session', subjectName: 'Project notes' }))
    .toEqual(buildSummaryStatements(grants));
});

test('the edit view labels the invitation key actions the way the summary does, and nothing else', () => {
  const key = grant(`urn:tinycloud:encryption:${owner}:default/share/${id}`, [create, decrypt]);
  const invitation = { subjectKind: 'session', subjectName: 'Project notes' } as const;
  expect(shareInvitationActionLabel(key, decrypt, invitation)).toBe('Read Project notes messages with this invitation\'s key');
  expect(shareInvitationActionLabel(key, create, invitation)).toBe('Create an encryption key for this invitation only');
  expect(shareInvitationActionLabel(key, 'tinycloud.encryption/key.block', invitation)).toBeNull();
  expect(shareInvitationActionLabel(grant(`urn:tinycloud:encryption:${owner}:default/share/abc123`, [decrypt]), decrypt, invitation)).toBeNull();
});
