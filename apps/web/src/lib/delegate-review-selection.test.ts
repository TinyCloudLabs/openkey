// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { actionId, parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { preparedMatchesSelection, reviewSelectionToActionKeys, type ServerPermissionOption } from './delegate-review-selection';

// TC-598: a CLI secret request signs its decrypt grant as a top-level
// encryption network. capability-review reports that resource as the grant's
// space; /api/delegate/prepare reports it as space `encryption` with the URN
// as path. The consent page must still map each review toggle to its server
// action key.

const address = '0x1111111111111111111111111111111111111111';
const space = `tinycloud:pkh:eip155:1:${address}:secrets`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const KV_GET = 'tinycloud.kv/get';
const CAPS_READ = 'tinycloud.capabilities/read';

const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:',
  address,
  '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1',
  'Chain ID: 1',
  'Nonce: abcdef123456',
  'Issued At: 2026-10-03T00:00:00.000Z',
  'Expiration Time: 2026-10-03T01:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({
    [`${space}/capabilities`]: { [CAPS_READ]: [{}] },
    [`${space}/kv/vault/secrets/TC_FWD_TOKEN`]: { [KV_GET]: [{}] },
    [network]: { [DECRYPT]: [{}] },
  })}`,
].join('\n');

// The /prepare `permissions` options for the same SIWE.
const serverKey = (service: string, keySpace: string, path: string) => `${service}\0${keySpace}\0${path}`;
const capsKey = serverKey('tinycloud.capabilities', space, '');
const kvKey = serverKey('tinycloud.kv', space, 'vault/secrets/TC_FWD_TOKEN');
const decryptKey = serverKey('tinycloud.encryption', 'encryption', network);
const serverPermissions: ServerPermissionOption[] = [
  { key: capsKey, actions: [{ key: `${capsKey}\0${CAPS_READ}`, ability: CAPS_READ, required: true }] },
  { key: kvKey, actions: [{ key: `${kvKey}\0${KV_GET}`, ability: KV_GET, required: false }] },
  { key: decryptKey, actions: [{ key: `${decryptKey}\0${DECRYPT}`, ability: DECRYPT, required: false }] },
];

const model = parseCapabilityReview({ message: siwe, signer: { label: 'Key 0', address } } as never);
const reviewActionId = (ability: string) => {
  const action = model.permissions.flatMap((grant) => grant.actions).find((candidate) => candidate.ability === ability);
  if (!action) throw new Error(`no review action for ${ability}`);
  return action.id;
};

describe('reviewSelectionToActionKeys — raw encryption network', () => {
  test('capability-review keys the network as a top-level resource', () => {
    expect(reviewActionId(DECRYPT)).toBe(actionId('tinycloud.encryption', network, '', DECRYPT));
  });

  test('keeps decrypt when the owner unchecks another grant', () => {
    const keys = reviewSelectionToActionKeys(model, serverPermissions, new Set([reviewActionId(DECRYPT)]));
    expect(keys.sort()).toEqual([`${capsKey}\0${CAPS_READ}`, `${decryptKey}\0${DECRYPT}`].sort());
  });

  test('drops decrypt when the owner unchecks it', () => {
    const keys = reviewSelectionToActionKeys(model, serverPermissions, new Set([reviewActionId(KV_GET)]));
    expect(keys.sort()).toEqual([`${capsKey}\0${CAPS_READ}`, `${kvKey}\0${KV_GET}`].sort());
  });
});

describe('preparedMatchesSelection', () => {
  const allKeys = serverPermissions.flatMap((permission) => permission.actions.map((action) => action.key));
  const allReview = new Set(model.permissions.flatMap((grant) => grant.actions.map((action) => action.id)));
  const withoutDecrypt = new Set([...allReview].filter((id) => id !== reviewActionId(DECRYPT)));

  test('matches when the prepared SIWE grants the visible selection', () => {
    expect(preparedMatchesSelection(model, serverPermissions, allReview, allKeys)).toBe(true);
    const narrowedKeys = allKeys.filter((key) => !key.endsWith(`\0${DECRYPT}`));
    expect(preparedMatchesSelection(model, serverPermissions, withoutDecrypt, narrowedKeys)).toBe(true);
  });

  test('does not match after a failed narrowing left the broader SIWE prepared', () => {
    expect(preparedMatchesSelection(model, serverPermissions, withoutDecrypt, allKeys)).toBe(false);
  });
});
