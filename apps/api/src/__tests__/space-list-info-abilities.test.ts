// `tinycloud.space/list` and `tinycloud.space/info` read and create nothing: a message that asks for them and no host
// ability is signed for a site that is not first-party. Every other space ability, and every near-miss spelling of
// those two, is refused. A `host` ability beside them follows the owner's complete-row rule.

import { describe, expect, mock, test } from 'bun:test';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { originProvisionAuthority } from '../services/provision-authority';
import { refusesThirdPartySpaceHost } from '../services/space-host-signing';
import type { PrismaLike } from '../services/tinycloud-bootstrap';
import { spaceHostRequest } from '../services/tinycloud-siwe';

const owner = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const key = { id: 'key_1', address: owner };
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${owner}:${name}`;
const space = (name: string) => `${spaceId(name)}/space`;

/** A message whose ReCap is `att` (the statement is rewritten to what the recap parser checks). */
function withRecap(att: Record<string, Record<string, unknown[]>>) {
  const base = generateHostSIWEMessage({
    address: owner, chainId: 1, domain: 'account.example.test', issuedAt: new Date().toISOString(), spaceId: spaceId('public'), peerId: PEER,
  });
  // One clause per resource and service: `'service': 'a', 'b' for 'resource'`.
  const lines = Object.entries(att).sort(([a], [b]) => a.localeCompare(b)).flatMap(([resource, abilities]) => {
    const byService = new Map<string, string[]>();
    for (const ability of Object.keys(abilities).sort()) {
      const service = ability.slice(0, ability.indexOf('/'));
      byService.set(service, [...(byService.get(service) ?? []), ability.slice(ability.indexOf('/') + 1)]);
    }
    return [...byService].map(([service, names]) => `'${service}': ${names.map((name) => `'${name}'`).join(', ')} for '${resource}'`);
  });
  const statement = `I further authorize the stated URI to perform the following actions on my behalf: ${lines.map((line, i) => `(${i + 1}) ${line}.`).join(' ')}`;
  return base
    .replace(/I further authorize[^\n]*/, statement)
    .replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`);
}
const spaceAbilities = (...abilities: string[]) => withRecap({ [space('account')]: Object.fromEntries(abilities.map((ability) => [ability, [{}]])) });
const KV = { [`${spaceId('account')}/kv/`]: { 'tinycloud.kv/get': [{}] } };

type Row = { status: string } | null;
const refuses = (message: string, row: Row = { status: 'complete' }) => refusesThirdPartySpaceHost({
  prisma: { tinyCloudBootstrapState: { findUnique: mock(async () => row) } } as unknown as PrismaLike,
  message, key, authorities: [originProvisionAuthority('https://account.example.test')],
});

describe('a space `list` or `info` ability from a site that is not first-party', () => {
  test('a list-only message names no host target and is signed', async () => {
    const message = spaceAbilities('tinycloud.space/list');
    expect(spaceHostRequest(message)).toEqual({ kind: 'none' });
    expect(await refuses(message, null)).toBe(false);
  });

  test('an info-only message names no host target and is signed', async () => {
    const message = spaceAbilities('tinycloud.space/info');
    expect(spaceHostRequest(message)).toEqual({ kind: 'none' });
    expect(await refuses(message, null)).toBe(false);
  });

  test('a message with list and info is signed', async () => {
    expect(await refuses(spaceAbilities('tinycloud.space/list', 'tinycloud.space/info'), null)).toBe(false);
  });

  test('a list ability beside a kv ability is signed', async () => {
    expect(await refuses(withRecap({ ...KV, [space('account')]: { 'tinycloud.space/list': [{}] } }), null)).toBe(false);
  });

  test('list beside a host of the owner\'s `default` space is signed with a complete row and refused without one', async () => {
    const message = withRecap({ [space('default')]: { 'tinycloud.space/host': [{}], 'tinycloud.space/list': [{}] } });
    expect(spaceHostRequest(message)).toEqual({ kind: 'hosts', targets: [{ address: owner, chainId: 1, name: 'default' }] });
    expect(await refuses(message, { status: 'complete' })).toBe(false);
    expect(await refuses(message, null)).toBe(true);
    expect(await refuses(message, { status: 'pending' })).toBe(true);
  });

  test('a list entry for one space beside a host entry for another yields only the host target', async () => {
    const message = withRecap({ [space('account')]: { 'tinycloud.space/list': [{}] }, [space('public')]: { 'tinycloud.space/host': [{}] } });
    expect(spaceHostRequest(message)).toEqual({ kind: 'hosts', targets: [{ address: owner, chainId: 1, name: 'public' }] });
    expect(await refuses(message, null)).toBe(true);
  });

  test('a create ability is refused', async () => {
    const message = spaceAbilities('tinycloud.space/create');
    expect(spaceHostRequest(message)).toEqual({ kind: 'unreadable' });
    expect(await refuses(message)).toBe(true);
  });

  test('a delete ability and an unknown space ability are refused', async () => {
    for (const ability of ['tinycloud.space/delete', 'tinycloud.space/unknown-ability']) {
      expect(await refuses(spaceAbilities(ability))).toBe(true);
    }
  });

  test('list beside an ability that is not allowed is refused', async () => {
    for (const other of ['tinycloud.space/create', 'tinycloud.space/delete']) {
      expect(await refuses(spaceAbilities('tinycloud.space/list', other))).toBe(true);
    }
  });

  test('a wildcard space ability is refused, alone and beside list', async () => {
    expect(await refuses(spaceAbilities('tinycloud.space/*'))).toBe(true);
    expect(await refuses(spaceAbilities('tinycloud.space/list', 'tinycloud.space/*'))).toBe(true);
    expect(await refuses(withRecap({ '*': { 'tinycloud.space/list': [{}], '*': [{}] } }))).toBe(true);
  });

  test('a spelling of list that is not exactly the ability is refused', async () => {
    for (const variant of ['tinycloud.space/List', 'tinycloud.space/LIST', 'tinycloud.space/list ', ' tinycloud.space/list', 'tinycloud.space/list/x', 'tinycloud.space/listing', 'tinycloud.space/lis']) {
      expect([variant, await refuses(spaceAbilities(variant))]).toEqual([variant, true]);
    }
  });

  test('a spelling of info that is not exactly the ability is refused', async () => {
    for (const variant of ['tinycloud.space/Info', 'tinycloud.space/info ', 'tinycloud.space/info/x', 'tinycloud.space/information']) {
      expect([variant, await refuses(spaceAbilities(variant))]).toEqual([variant, true]);
    }
  });
});
