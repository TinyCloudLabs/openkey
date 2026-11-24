// A KV resource in a signed ReCap is written `<space>/kv` (no path, the whole space), `<space>/kv/` or
// `<space>/kv/<path>`. Only a read of `vault/secrets` or `secrets` (and what is under them) is held to 7 days; a read
// of the whole space or of another folder is not, whichever way the resource is written. A KV resource with no `kv`
// segment cannot be read as a space path, so it counts as the secrets vault.

import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { exceedsSecretLifetime, messageExceedsSecretLifetime, secretCapExpirationTime } from '../services/secret-lifetime';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const SPACE = `tinycloud:pkh:eip155:1:${address}:applications`;
const DAY_MS = 86_400_000;
const KV = 'tinycloud.kv/';

function siweFor(rawAbilities: Record<string, string[]>, lifetimeMs: number, now = Date.now()): string {
  return prepareSession({
    address,
    chainId: 1,
    domain: 'tinycloud.one',
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + lifetimeMs).toISOString(),
    spaceId: SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    rawAbilities,
  }).siwe;
}

const ALL_KV_ACTIONS = ['get', 'list', 'put', 'del', 'metadata'].map((verb) => `${KV}${verb}`);

describe('a KV resource that names the whole space or another folder is not held to 7 days', () => {
  const OPEN: Array<[string, string]> = [
    ['<space>/kv', `${SPACE}/kv`],
    ['<space>/kv/', `${SPACE}/kv/`],
    ['<space>/kv/notes/', `${SPACE}/kv/notes/`],
    ['<space>/kv/vault', `${SPACE}/kv/vault`],
    ['<space>/kv/vault/', `${SPACE}/kv/vault/`],
    ['<space>/kv/vault/variables/', `${SPACE}/kv/vault/variables/`],
  ];

  test.each(OPEN)('%s with get, list, put, del and metadata for 30 days', (_name, resource) => {
    const siwe = siweFor({ [resource]: ALL_KV_ACTIONS }, 30 * DAY_MS);
    expect(exceedsSecretLifetime(siwe, Date.now())).toBeNull();
    expect(secretCapExpirationTime(siwe, Date.now())).toBeNull();
    expect(messageExceedsSecretLifetime(siwe, Date.now())).toBeNull();
  });

  test('<space>/kv with sync reads the whole space, so it is not held either', () => {
    const siwe = siweFor({ [`${SPACE}/kv`]: [`${KV}sync`] }, 30 * DAY_MS);
    expect(exceedsSecretLifetime(siwe, Date.now())).toBeNull();
    expect(secretCapExpirationTime(siwe, Date.now())).toBeNull();
  });

  test('the explorer shape: kv, sql and capabilities on the space with no path, for 30 days', () => {
    const siwe = siweFor({
      [`${SPACE}/kv`]: ALL_KV_ACTIONS,
      [`${SPACE}/capabilities`]: ['tinycloud.capabilities/read'],
      [`${SPACE}/sql`]: ['tinycloud.sql/read', 'tinycloud.sql/write'],
    }, 30 * DAY_MS);
    expect(exceedsSecretLifetime(siwe, Date.now())).toBeNull();
    expect(secretCapExpirationTime(siwe, Date.now())).toBeNull();
  });
});

describe('a KV read of the secrets vault is held to 7 days, whichever way the resource is written', () => {
  const HELD: Array<[string, string]> = [
    ['<space>/kv/vault/secrets', `${SPACE}/kv/vault/secrets`],
    ['<space>/kv/vault/secrets/', `${SPACE}/kv/vault/secrets/`],
    ['<space>/kv/vault/secrets/OPENAI_API_KEY', `${SPACE}/kv/vault/secrets/OPENAI_API_KEY`],
    ['<space>/kv/secrets', `${SPACE}/kv/secrets`],
    ['<space>/kv/secrets/', `${SPACE}/kv/secrets/`],
    ['<space>/kv/secrets/x', `${SPACE}/kv/secrets/x`],
  ];

  test.each(HELD)('%s: 8 days is over the cap and 7 days is not', (_name, resource) => {
    const now = Date.now();
    expect(exceedsSecretLifetime(siweFor({ [resource]: [`${KV}get`] }, 8 * DAY_MS, now), now)).toBe('secrets');
    expect(exceedsSecretLifetime(siweFor({ [resource]: [`${KV}get`] }, 7 * DAY_MS, now), now)).toBeNull();
    expect(secretCapExpirationTime(siweFor({ [resource]: [`${KV}get`] }, 30 * DAY_MS, now), now)).not.toBeNull();
  });

  test('a put or del there is not a read, so it is not held', () => {
    const siwe = siweFor({ [`${SPACE}/kv/vault/secrets/`]: [`${KV}put`, `${KV}del`] }, 30 * DAY_MS);
    expect(exceedsSecretLifetime(siwe, Date.now())).toBeNull();
  });

  test('a whole-space read next to a vault read: the vault read holds the message', () => {
    const now = Date.now();
    const siwe = siweFor({ [`${SPACE}/kv`]: ALL_KV_ACTIONS, [`${SPACE}/kv/vault/secrets/`]: [`${KV}get`] }, 30 * DAY_MS, now);
    expect(exceedsSecretLifetime(siwe, now)).toBe('secrets');
  });
});

describe('a KV resource with no kv segment counts as the secrets vault', () => {
  test.each([
    ['<space>/share/x', `${SPACE}/share/x`],
    ['<space>/kvx', `${SPACE}/kvx`],
    ['<space>/kvx/notes', `${SPACE}/kvx/notes`],
  ])('%s: 8 days is over the cap', (_name, resource) => {
    const now = Date.now();
    expect(exceedsSecretLifetime(siweFor({ [resource]: [`${KV}get`] }, 8 * DAY_MS, now), now)).toBe('secrets');
    expect(exceedsSecretLifetime(siweFor({ [resource]: [`${KV}get`] }, 7 * DAY_MS, now), now)).toBeNull();
  });
});
