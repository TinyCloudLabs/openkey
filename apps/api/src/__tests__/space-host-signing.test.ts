// The one decision every signing route makes for a message that hosts a space: refusesThirdPartySpaceHost.

import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { generateHostSIWEMessage, prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { originProvisionAuthority, UNATTRIBUTED_PROVISION_AUTHORITY } from '../services/provision-authority';
import { refusesThirdPartySpaceHost } from '../services/space-host-signing';
import type { PrismaLike } from '../services/tinycloud-bootstrap';

const owner = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const other = privateKeyToAccount('0x1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const key = { id: 'key_1', address: owner };
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const HOST = 'tinycloud.space/host';

const spaceId = (name: string, address = owner, chainId = 1) => `tinycloud:pkh:eip155:${chainId}:${address}:${name}`;
const hostMessage = (name: string, address = owner) => generateHostSIWEMessage({
  address: owner, chainId: 1, domain: 'app.example.test', issuedAt: new Date().toISOString(), spaceId: spaceId(name, address), peerId: PEER,
});
/** A host message whose ReCap names every space in `spaces` (the statement is rewritten to what the recap parser checks). */
function hostMessageFor(spaces: string[]) {
  const att = Object.fromEntries(spaces.map((space) => [`${space}/space`, { [HOST]: [{}] }]));
  const lines = Object.keys(att).sort().map((resource, i) => `(${i + 1}) 'tinycloud.space': 'host' for '${resource}'.`);
  return hostMessage('public')
    .replace(/I further authorize[^\n]*/, `I further authorize the stated URI to perform the following actions on my behalf: ${lines.join(' ')}`)
    .replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`);
}
const noSpaceAbility = () => prepareSession({
  address: owner, chainId: 1, domain: 'app.example.test', issuedAt: new Date().toISOString(),
  expirationTime: new Date(Date.now() + 3_600_000).toISOString(), spaceId: spaceId('applications'),
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  abilities: { kv: { 'data/': ['tinycloud.kv/get', 'tinycloud.kv/put'] } },
} as never).siwe;

type Row = { status: string } | null | 'throws';
function prismaWith(row: Row) {
  const findUnique = mock(async () => {
    if (row === 'throws') throw new Error('database unavailable');
    return row;
  });
  return { prisma: { tinyCloudBootstrapState: { findUnique } } as unknown as PrismaLike, findUnique };
}
const thirdParty = [originProvisionAuthority('https://app.example.test')];
const firstParty = [originProvisionAuthority('https://tinycloud.chat')];
const refuses = (row: Row, message: string, authorities = thirdParty) =>
  refusesThirdPartySpaceHost({ prisma: prismaWith(row).prisma, message, key, authorities });

const savedHost = process.env.TINYCLOUD_BOOTSTRAP_HOST;
beforeEach(() => { delete process.env.TINYCLOUD_BOOTSTRAP_HOST; });
afterEach(() => {
  if (savedHost === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  else process.env.TINYCLOUD_BOOTSTRAP_HOST = savedHost;
});

describe('refusesThirdPartySpaceHost, for the owner\'s own `default` space', () => {
  test('signs when the primary space has a complete bootstrap row', async () => {
    expect(await refuses({ status: 'complete' }, hostMessage('default'))).toBe(false);
  });

  test('refuses when the owner has no bootstrap row', async () => {
    expect(await refuses(null, hostMessage('default'))).toBe(true);
  });

  test('refuses for a pending row', async () => {
    expect(await refuses({ status: 'pending' }, hostMessage('default'))).toBe(true);
  });

  test('refuses for an in-progress row', async () => {
    expect(await refuses({ status: 'in_progress' }, hostMessage('default'))).toBe(true);
  });

  test('refuses for a failed row', async () => {
    expect(await refuses({ status: 'failed' }, hostMessage('default'))).toBe(true);
  });

  test('refuses when the row read throws', async () => {
    expect(await refuses('throws', hostMessage('default'))).toBe(true);
  });

  test('refuses when the bootstrap host is not trusted, even with a complete row', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_HOST = 'https://untrusted.example.test';
    expect(await refuses({ status: 'complete' }, hostMessage('default'))).toBe(true);
  });

  test('reads the row of the key and the chain the target names, and writes nothing', async () => {
    const { prisma, findUnique } = prismaWith({ status: 'complete' });
    await refusesThirdPartySpaceHost({ prisma, message: hostMessage('default'), key, authorities: thirdParty });

    expect(findUnique).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(findUnique.mock.calls[0])).toContain('"keyId":"key_1"');
    expect(JSON.stringify(findUnique.mock.calls[0])).toContain('"chainId":1');
    expect(Object.keys(prisma.tinyCloudBootstrapState)).toEqual(['findUnique']);
  });
});

describe('refusesThirdPartySpaceHost, for the owner\'s own non-default space', () => {
  test('signs when the primary space has a complete bootstrap row', async () => {
    expect(await refuses({ status: 'complete' }, hostMessage('public'))).toBe(false);
  });

  test('refuses when the owner has no complete bootstrap row', async () => {
    expect(await refuses(null, hostMessage('public'))).toBe(true);
  });
});

describe('refusesThirdPartySpaceHost, for another owner\'s space', () => {
  test('refuses `default` although the key owner\'s primary space is complete', async () => {
    expect(await refuses({ status: 'complete' }, hostMessage('default', other))).toBe(true);
  });

  test('refuses a non-default space although the key owner\'s primary space is complete', async () => {
    expect(await refuses({ status: 'complete' }, hostMessage('public', other))).toBe(true);
  });

  test('refuses targets that mix the owner\'s `default` with another owner\'s space', async () => {
    expect(await refuses({ status: 'complete' }, hostMessageFor([spaceId('default'), spaceId('public', other)]))).toBe(true);
  });
});

describe('refusesThirdPartySpaceHost, for the other cases', () => {
  test('signs targets that are all the owner\'s own spaces, `default` included, with a complete row', async () => {
    expect(await refuses({ status: 'complete' }, hostMessageFor([spaceId('default'), spaceId('public')]))).toBe(false);
  });

  test('refuses a target on a chain that has no complete row', async () => {
    // The row lookup is per chain: this one answers complete only for chain 1.
    const findUnique = mock(async ({ where }: { where: { keyId_chainId_tinycloudHost_bootstrapVersion: { chainId: number } } }) =>
      (where.keyId_chainId_tinycloudHost_bootstrapVersion.chainId === 1 ? { status: 'complete' } : null));
    const prisma = { tinyCloudBootstrapState: { findUnique } } as unknown as PrismaLike;

    expect(await refusesThirdPartySpaceHost({ prisma, message: hostMessageFor([spaceId('default', owner, 1), spaceId('public', owner, 5)]), key, authorities: thirdParty })).toBe(true);
  });

  test('signs for a first-party authority with no row', async () => {
    expect(await refuses(null, hostMessage('default'), firstParty)).toBe(false);
  });

  test('refuses an unattributed request with no row', async () => {
    expect(await refuses(null, hostMessage('default'), [UNATTRIBUTED_PROVISION_AUTHORITY])).toBe(true);
  });

  test('signs a message that asks for no space host ability', async () => {
    const { prisma, findUnique } = prismaWith(null);
    expect(await refusesThirdPartySpaceHost({ prisma, message: noSpaceAbility(), key, authorities: thirdParty })).toBe(false);
    expect(findUnique).not.toHaveBeenCalled();
  });

  test('refuses a ReCap it cannot read', async () => {
    const unreadable = hostMessage('default').replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(`not json ${HOST}`).toString('base64url')}`);
    expect(await refuses({ status: 'complete' }, unreadable)).toBe(true);
  });
});

describe('refusesThirdPartySpaceHost, for a request that binds no context', () => {
  const noContext = (row: Row, message: string) =>
    refusesThirdPartySpaceHost({ prisma: prismaWith(row).prisma, message, key, authorities: [UNATTRIBUTED_PROVISION_AUTHORITY], noBoundContext: true });

  test('refuses the owner\'s `default` space although the primary space has a complete row', async () => {
    expect(await noContext({ status: 'complete' }, hostMessage('default'))).toBe(true);
  });

  test('refuses a mix of `default` and another own space although the primary space has a complete row', async () => {
    expect(await noContext({ status: 'complete' }, hostMessageFor([spaceId('default'), spaceId('public')]))).toBe(true);
  });

  test('signs the owner\'s non-default space when the primary space has a complete row', async () => {
    expect(await noContext({ status: 'complete' }, hostMessage('public'))).toBe(false);
  });

  test('refuses the owner\'s non-default space without a complete row', async () => {
    expect(await noContext(null, hostMessage('public'))).toBe(true);
  });
});
