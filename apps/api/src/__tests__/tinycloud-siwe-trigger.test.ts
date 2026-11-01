// TC-2232 child: which TinyCloud sign-ins make OpenKey set up the signer's account before it signs.
// Beyond the account-space entries, a sign-in that names one of the SIGNER'S OWN canonical bootstrap
// spaces (applications, default, ...) is a trigger, so the SDK never has to host that space itself.
import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  isTinyCloudSiweForSigner,
  ownBootstrapSpaceName,
  parseTinyCloudSiwe,
  requestedOwnSpaceForSiwe,
} from '../services/tinycloud-siwe';

const signer = '0x31d40B62C395B9418C4198363619B11c65cD406F';
const other = '0x1111111111111111111111111111111111111111';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'test' };
const spaceOf = (owner: string, name: string, chainId = 1) => `tinycloud:pkh:eip155:${chainId}:${owner}:${name}`;

/** A TinyCloud sign-in by `address` for one space: `abilities` are the service -> path -> actions in it. */
function siwe(options: { address?: string; spaceId: string; abilities?: Record<string, Record<string, string[]>> }) {
  return prepareSession({
    address: options.address ?? signer,
    chainId: 1,
    domain: 'app.example.test',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
    spaceId: options.spaceId,
    jwk,
    abilities: options.abilities ?? { kv: { 'data/': ['tinycloud.kv/get'] } },
  }).siwe;
}

function parsed(message: string) {
  const result = parseTinyCloudSiwe(message);
  if (!result) throw new Error('the fixture SIWE did not parse');
  return result;
}

describe('ownBootstrapSpaceName', () => {
  test('names a space only when it is exactly one of this address\'s canonical bootstrap spaces', () => {
    for (const name of ['default', 'applications', 'account', 'secrets', 'public', 'agents'] as const) {
      expect(ownBootstrapSpaceName(spaceOf(signer, name), signer, 1)).toBe(name);
    }
  });

  test.each([
    ['another account\'s space', spaceOf(other, 'applications')],
    ['another chain', spaceOf(signer, 'applications', 5)],
    ['a lower-case spelling of the address', spaceOf(signer.toLowerCase(), 'applications')],
    ['a name that is not a bootstrap space', spaceOf(signer, 'messages')],
    ['a prefix of a bootstrap space name', spaceOf(signer, 'applications2')],
    ['an extra path segment', `${spaceOf(signer, 'applications')}:extra`],
    ['a bare name', 'applications'],
    ['nothing', ''],
  ])('refuses %s', (_label, spaceId) => {
    expect(ownBootstrapSpaceName(spaceId, signer, 1)).toBeNull();
  });
});

describe('ownBootstrapSpaceName with a chain id the wasm rejects', () => {
  test('compares text and never throws, so a message like that cannot stop the signature', () => {
    expect(() => ownBootstrapSpaceName(spaceOf(signer, 'applications', 0), signer, 0)).not.toThrow();
    expect(ownBootstrapSpaceName(spaceOf(signer, 'applications', 0), signer, 0)).toBe('applications');
  });
});

describe('isTinyCloudSiweForSigner', () => {
  test('an applications-only sign-in by the signer is a trigger (it names no account-space entry)', () => {
    expect(isTinyCloudSiweForSigner(parsed(siwe({ spaceId: spaceOf(signer, 'applications') })), signer)).toBe(true);
  });

  test('so is a sign-in for the default space, and the existing account-space entries still are', () => {
    expect(isTinyCloudSiweForSigner(parsed(siwe({ spaceId: spaceOf(signer, 'default') })), signer)).toBe(true);
    expect(isTinyCloudSiweForSigner(parsed(siwe({
      spaceId: spaceOf(signer, 'account'),
      abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
    })), signer)).toBe(true);
  });

  test('a space that is not a canonical bootstrap space is not', () => {
    expect(isTinyCloudSiweForSigner(parsed(siwe({ spaceId: spaceOf(signer, 'randomapp') })), signer)).toBe(false);
  });

  test('another account\'s applications space is not, even inside a sign-in whose address is the signer\'s', () => {
    const message = siwe({ spaceId: spaceOf(other, 'applications') });
    expect(isTinyCloudSiweForSigner(parsed(message), signer)).toBe(false);
  });

  test('a sign-in by another address is not, even for a space that looks like the signer\'s', () => {
    const message = siwe({ address: other, spaceId: spaceOf(signer, 'applications') });
    expect(isTinyCloudSiweForSigner(parsed(message), signer)).toBe(false);
    expect(isTinyCloudSiweForSigner(parsed(siwe({ address: other, spaceId: spaceOf(other, 'applications') })), signer)).toBe(false);
  });
});

describe('requestedOwnSpaceForSiwe', () => {
  test('is the signer\'s own space the sign-in names', () => {
    expect(requestedOwnSpaceForSiwe(parsed(siwe({ spaceId: spaceOf(signer, 'applications') })), signer)).toBe('applications');
    expect(requestedOwnSpaceForSiwe(parsed(siwe({ spaceId: spaceOf(signer, 'default') })), signer)).toBe('default');
    expect(requestedOwnSpaceForSiwe(parsed(siwe({ spaceId: spaceOf(signer, 'public') })), signer)).toBe('public');
  });

  test('is null for an account-space sign-in: that already runs the whole setup', () => {
    const message = siwe({
      spaceId: spaceOf(signer, 'account'),
      abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
    });
    expect(requestedOwnSpaceForSiwe(parsed(message), signer)).toBeNull();
  });

  test.each([
    ['a space that is not canonical', spaceOf(signer, 'randomapp')],
    ['another account\'s space', spaceOf(other, 'applications')],
    ['another chain\'s space', spaceOf(signer, 'applications', 5)],
  ])('is null for %s', (_label, spaceId) => {
    expect(requestedOwnSpaceForSiwe(parsed(siwe({ spaceId })), signer)).toBeNull();
  });

  test('with several of the signer\'s own spaces named, applications is awaited first, then the default order', () => {
    const kv = { kv: { 'data/': ['tinycloud.kv/get'] } };
    const several = (spaces: string[]) => prepareSession({
      address: signer,
      chainId: 1,
      domain: 'app.example.test',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
      spaceId: spaceOf(signer, spaces[0]!),
      jwk,
      abilities: kv,
      spaceAbilities: Object.fromEntries(spaces.map((name) => [spaceOf(signer, name), kv])),
    } as never).siwe;
    expect(requestedOwnSpaceForSiwe(parsed(several(['public', 'default', 'applications'])), signer)).toBe('applications');
    expect(requestedOwnSpaceForSiwe(parsed(several(['public', 'default'])), signer)).toBe('default');
    // A space of another account named beside the signer's own is never the one awaited.
    const mixed = prepareSession({
      address: signer,
      chainId: 1,
      domain: 'app.example.test',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
      spaceId: spaceOf(signer, 'default'),
      jwk,
      abilities: kv,
      spaceAbilities: { [spaceOf(other, 'applications')]: kv, [spaceOf(signer, 'default')]: kv },
    } as never).siwe;
    expect(requestedOwnSpaceForSiwe(parsed(mixed), signer)).toBe('default');
  });

  test('is null for a sign-in by another address', () => {
    expect(requestedOwnSpaceForSiwe(parsed(siwe({ address: other, spaceId: spaceOf(signer, 'applications') })), signer)).toBeNull();
  });

});
