import { expect, test } from 'bun:test';
import { listAllDeletionSpaces, type OwnerSpacePage } from './account-deletion-list';
const host = { hostId: 'registered-node', url: 'https://node.example.test' };
const owner = 'did:pkh:eip155:1:synthetic';
const page: OwnerSpacePage = { version: 1, hostId: host.hostId, ownerDid: owner, spaces: ['tinycloud:synthetic:a'], nextCursor: null, lastPage: true };

test('enumeration follows every host-bound page to an explicit terminal page', async () => {
  const cursors: (string | null)[] = [];
  const result = await listAllDeletionSpaces(host, owner, async (url, body) => {
    expect(url).toBe('https://node.example.test/space/list');
    cursors.push(body.cursor);
    return body.cursor === null ? { ...page, lastPage: false, nextCursor: 'opaque' } : { ...page, spaces: ['tinycloud:synthetic:b'] };
  });
  expect(cursors).toEqual([null, 'opaque']);
  expect(result).toEqual(['tinycloud:synthetic:a', 'tinycloud:synthetic:b']);
});

test('unknown host, owner, terminal state and cursor omissions fail closed', async () => {
  for (const invalid of [
    { ...page, hostId: 'other' }, { ...page, ownerDid: 'other' },
    { ...page, lastPage: undefined }, { ...page, lastPage: false },
    { ...page, nextCursor: 'unexpected' },
  ]) await expect(listAllDeletionSpaces(host, owner, async () => invalid as OwnerSpacePage)).rejects.toThrow();
  await expect(listAllDeletionSpaces(host, owner, async () => ({ ...page, spaces: [], lastPage: false, nextCursor: 'repeated' }))).rejects.toThrow();
  await expect(listAllDeletionSpaces({ ...host, url: 'http://node.example.test' }, owner, async () => page)).rejects.toThrow();
});
