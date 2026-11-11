// @ts-expect-error bun:test is a runtime-only module
import { expect, test } from 'bun:test';
import { defaultSelection, parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { preparedMatchesSelection, reviewSelectionToActionKeys } from './delegate-review-selection';

const address = '0x1111111111111111111111111111111111111111';
const spaces = ['account', 'applications'].map(name => `tinycloud:pkh:eip155:1:${address}:${name}`);
const ability = 'tinycloud.kv/get';
const permissions = spaces.map(space => {
  const key = `tinycloud.kv\0${space}\0same/path/`;
  return { key, actions: [{ key: `${key}\0${ability}`, ability, required: false }] };
});
const message = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'URI: https://cli.tinycloud.xyz', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
  'Issued At: 2026-11-05T00:00:00.000Z', 'Expiration Time: 2026-11-06T00:00:00.000Z',
  'Resources:', `- ${makeRecapResource(Object.fromEntries(spaces.map(space => [`${space}/kv/same/path/`, { [ability]: [{}] }]))) }`,
].join('\n');

for (const removedSpace of spaces) {
  test(`removing an identical path/ability from ${removedSpace} preserves only the other space`, () => {
    const model = parseCapabilityReview({ message, signer: { label: 'QA fixture', address }, editable: true } as never);
    expect(model.permissions).toHaveLength(2);
    const selection = defaultSelection(model);
    const removed = model.permissions.find(grant => grant.space === removedSpace)!;
    selection.delete(removed.actions[0]!.id);
    const expected = permissions.filter(permission => !permission.key.includes(removedSpace)).map(permission => permission.actions[0]!.key);
    expect(reviewSelectionToActionKeys(model, permissions, selection)).toEqual(expected);
    expect(preparedMatchesSelection(model, permissions, selection, expected)).toBe(true);
    const wrongSpace = permissions.filter(permission => permission.key.includes(removedSpace)).map(permission => permission.actions[0]!.key);
    expect(preparedMatchesSelection(model, permissions, selection, wrongSpace)).toBe(false);
    selection.add(removed.actions[0]!.id);
    expect(new Set(reviewSelectionToActionKeys(model, permissions, selection))).toEqual(new Set(permissions.map(permission => permission.actions[0]!.key)));
  });
}
