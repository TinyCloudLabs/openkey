// OpenKey classifies every form of an app-key resource as an app key: the key
// URN (`urn:tinycloud:encryption:<owner>:<network>/apps/…`) and the space-path
// form (`<space>/encryption/apps/…`), from the text of a message and from the
// parsed entries alike. Paths that are not app keys keep passing.

import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { parsePreparedRecap, prepareDelegationSession } from '../routes/delegate-session';
import { appKeyRefusalForMessage, appKeyRefusalForSiwe } from '../services/app-key-refusal';
import { isAppsKeyResource, keyPathOfAnyResource, parseKeyResource } from '../services/key-resource';

const ADDRESS = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const JWK = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const DECRYPT = 'tinycloud.encryption/decrypt';

/** A message built the way `/api/delegate/prepare` builds it: one permission entry through the session builder. */
function preparedWith(permission: { service: string; space?: string; path: string; actions: string[] }): string {
  return prepareDelegationSession({
    address: ADDRESS,
    chainId: 1,
    prefix: 'default',
    jwk: JWK,
    permissions: [{ ...permission, space: permission.space ?? SPACE }],
    expiryMs: 3_600_000,
  }).prepared.siwe;
}

function recapResources(siwe: string): string[] {
  const encoded = /^- urn:recap:(.+)$/m.exec(siwe)?.[1] ?? '';
  return Object.keys(JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')).att);
}

const encryptionEntry = (path: string, actions: string[] = [DECRYPT], space: string = SPACE) => ({
  service: 'tinycloud.encryption',
  space,
  path,
  actions,
});

describe('the request that reached /api/delegate/prepare: service tinycloud.encryption, a space, an apps/ path, decrypt', () => {
  test.each([
    ['an exact key', 'apps/xyz.tinycloud.qa/k1'],
    ['a prefix', 'apps/xyz.tinycloud.qa/'],
    ['a first segment in capitals', 'APPS/xyz.tinycloud.qa/k1'],
    ['a nested path', 'apps/a/b/c'],
    ['the first segment alone', 'apps'],
  ])('%s: the prepared message is refused from its text, with no entries', (_name, path) => {
    const siwe = preparedWith(encryptionEntry(path));
    expect(recapResources(siwe)).toEqual([expect.stringMatching(new RegExp(`^${SPACE}/encryption/`))]);
    expect(appKeyRefusalForSiwe(siwe)).not.toBeNull();
    expect(appKeyRefusalForMessage(siwe)).not.toBeNull();
  });

  test.each([
    ['an exact key', 'apps/xyz.tinycloud.qa/k1'],
    ['a prefix', 'apps/xyz.tinycloud.qa/'],
    ['a first segment in capitals', 'APPS/xyz.tinycloud.qa/k1'],
    ['a nested path', 'apps/a/b/c'],
  ])('%s: the parsed entries are refused on their own, without the text', (_name, path) => {
    const entries = parsePreparedRecap(preparedWith(encryptionEntry(path)));
    expect(entries).toEqual([expect.objectContaining({ service: 'encryption', space: SPACE, path })]);
    expect(appKeyRefusalForSiwe('not a message', entries)).not.toBeNull();
  });

  test('the text and the entries of one message agree', () => {
    const siwe = preparedWith(encryptionEntry('apps/xyz.tinycloud.qa/k1'));
    const entries = parsePreparedRecap(siwe);
    const fromText = appKeyRefusalForSiwe(siwe);
    expect(appKeyRefusalForSiwe('not a message', entries)).toEqual(fromText);
    expect(appKeyRefusalForSiwe(siwe, entries)).toEqual(fromText);
  });

  test.each(['default', 'secrets', 'shared-with-me'])('any space name: %s', (space) => {
    const id = `tinycloud:pkh:eip155:1:${ADDRESS}:${space}`;
    const siwe = preparedWith(encryptionEntry('apps/x/k', [DECRYPT], id));
    expect(appKeyRefusalForSiwe(siwe)).not.toBeNull();
  });

  test('another owner', () => {
    const other = '0x1111111111111111111111111111111111111111';
    const siwe = preparedWith(encryptionEntry('apps/x/k', [DECRYPT], `tinycloud:pkh:eip155:1:${other}:default`));
    expect(appKeyRefusalForSiwe(siwe)).not.toBeNull();
  });

  test('a recap on an earlier resource line does not hide it', () => {
    const siwe = preparedWith(encryptionEntry('apps/xyz.tinycloud.qa/k1'));
    const extra = `urn:recap:${Buffer.from(JSON.stringify({ att: { [SPACE]: { 'tinycloud.kv/get': [{}] } }, prf: [] })).toString('base64url')}`;
    const withEarlier = siwe.replace(/^- urn:recap:/m, `- ${extra}\n- urn:recap:`);
    expect(appKeyRefusalForSiwe(withEarlier)).not.toBeNull();
  });

  test('written as hex', () => {
    const hex = `0x${Buffer.from(preparedWith(encryptionEntry('apps/xyz.tinycloud.qa/k1')), 'utf8').toString('hex')}`;
    expect(appKeyRefusalForMessage(hex)).not.toBeNull();
  });
});

describe('what keeps passing', () => {
  test('a kv path under apps/', () => {
    const siwe = preparedWith({ service: 'tinycloud.kv', path: 'apps/x', actions: ['tinycloud.kv/get'] });
    expect(recapResources(siwe)).toEqual([`${SPACE}/kv/apps/x`]);
    expect(appKeyRefusalForSiwe(siwe, parsePreparedRecap(siwe))).toBeNull();
  });

  test('the space-level decrypt with an empty path', () => {
    const siwe = preparedWith(encryptionEntry(''));
    expect(appKeyRefusalForSiwe(siwe, parsePreparedRecap(siwe))).toBeNull();
  });

  test.each(['appsx/y', 'apps.x/y', 'secrets/apps/x', 'app/x'])('an encryption path that is not under apps/: %s', (path) => {
    const siwe = preparedWith(encryptionEntry(path));
    expect(appKeyRefusalForSiwe(siwe, parsePreparedRecap(siwe))).toBeNull();
  });

  test('the default network written as a key URN', () => {
    const siwe = prepareSession({
      address: ADDRESS,
      chainId: 1,
      domain: 'listen.tinycloud.xyz',
      issuedAt: new Date().toISOString(),
      expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
      spaceId: SPACE,
      jwk: JWK,
      abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
      rawAbilities: { [`urn:tinycloud:encryption:${OWNER}:default`]: [DECRYPT] },
    }).siwe;
    expect(appKeyRefusalForSiwe(siwe, parsePreparedRecap(siwe))).toBeNull();
  });
});

describe('key.delete is refused under any resource form', () => {
  test.each([
    ['a space-path key', encryptionEntry('secrets/x', ['tinycloud.encryption/key.delete'])],
    ['a space-path apps/ key', encryptionEntry('apps/x/k', ['tinycloud.encryption/key.delete'])],
    ['the space-level resource', encryptionEntry('', ['tinycloud.encryption/key.delete'])],
  ])('%s', (_name, entry) => {
    const siwe = preparedWith(entry);
    expect(appKeyRefusalForSiwe(siwe, parsePreparedRecap(siwe))).toEqual({ reason: 'key_delete' });
  });
});

describe('the one classifier', () => {
  test.each([
    [`urn:tinycloud:encryption:${OWNER}:default/apps/x/k`, true],
    [`urn:tinycloud:encryption:${OWNER}:default/Apps/x/k`, true],
    [`${SPACE}/encryption/apps/x/k`, true],
    [`${SPACE}/encryption/Apps/x/`, true],
    [`${SPACE}/tinycloud.encryption/apps/x/k`, true],
    [`TINYCLOUD:pkh:eip155:1:${ADDRESS}:secrets/ENCRYPTION/APPS/x`, true],
    [`${SPACE}/encryption`, false],
    [`${SPACE}/encryption/`, false],
    [`${SPACE}/encryption/appsx/y`, false],
    [`${SPACE}/encryption/apps.x/y`, false],
    [`${SPACE}/encryption/secrets/apps/x`, false],
    [`${SPACE}/kv/apps/x`, false],
    [`${SPACE}/sql/apps/x`, false],
    [`${SPACE}/kv/encryption/apps/x`, false],
    [`urn:tinycloud:encryption:${OWNER}:default`, false],
    [`urn:tinycloud:encryption:${OWNER}:default/secrets/x`, false],
  ])('isAppsKeyResource(%s) is %s', (resource, expected) => {
    expect(isAppsKeyResource(resource)).toBe(expected);
  });

  test('the space-path form is not a key resource the parser knows, so admission can never admit it', () => {
    for (const resource of [`${SPACE}/encryption/apps/x/k`, `${SPACE}/encryption/apps/x/`]) {
      expect(isAppsKeyResource(resource)).toBe(true);
      expect(parseKeyResource(resource)).toBeNull();
    }
    expect(parseKeyResource(`urn:tinycloud:encryption:${OWNER}:default/apps/x/k`)).not.toBeNull();
  });

  test('the key path is read from either form, for any path', () => {
    expect(keyPathOfAnyResource(`urn:tinycloud:encryption:${OWNER}:default/secrets/x`)).toBe('secrets/x');
    expect(keyPathOfAnyResource(`${SPACE}/encryption/secrets/x`)).toBe('secrets/x');
    expect(keyPathOfAnyResource(`${SPACE}/encryption/`)).toBe('');
    expect(keyPathOfAnyResource(`${SPACE}/encryption`)).toBeNull();
    expect(keyPathOfAnyResource(`${SPACE}/kv/secrets/x`)).toBeNull();
  });
});
