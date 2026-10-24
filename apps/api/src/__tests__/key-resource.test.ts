import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
  appIdValid,
  isAppsKeyResource,
  isKeyPath,
  isPrefixPath,
  keyPathOfResource,
  parseKeyResource,
  prefixCovers,
} from '../services/key-resource';

// Shared vectors (node, sdk-core and OpenKey pass the same file). Every case is
// its own test so a failure names the vector.
const vectors = JSON.parse(readFileSync(new URL('./app-id-vectors.json', import.meta.url), 'utf8')) as {
  appIdValid: Array<{ id: string; valid: boolean }>;
  prefixValid: Array<{ prefix: string; valid: boolean }>;
  prefixCovers: Array<{ prefix: string; key: string; covers: boolean }>;
  nodeKeyPathUnderApps: Array<{ keyPath: string; accepted: boolean }>;
  keyPathsRefusedByGrammar: Array<{ keyPath: string }>;
};

describe('shared vectors: appIdValid', () => {
  for (const { id, valid } of vectors.appIdValid) {
    test(`${JSON.stringify(id)} -> ${valid}`, () => {
      expect(appIdValid(id)).toBe(valid);
    });
  }
});

describe('shared vectors: prefixValid', () => {
  for (const { prefix, valid } of vectors.prefixValid) {
    test(`${JSON.stringify(prefix)} -> ${valid}`, () => {
      expect(isPrefixPath(prefix)).toBe(valid);
    });
  }
});

describe('shared vectors: prefixCovers', () => {
  for (const { prefix, key, covers } of vectors.prefixCovers) {
    test(`${prefix} covers ${key} -> ${covers}`, () => {
      expect(prefixCovers(prefix, key)).toBe(covers);
    });
  }
});

describe('shared vectors: nodeKeyPathUnderApps', () => {
  for (const { keyPath, accepted } of vectors.nodeKeyPathUnderApps) {
    test(`${JSON.stringify(keyPath)} -> ${accepted}`, () => {
      expect(isKeyPath(keyPath)).toBe(accepted);
    });
  }
});

describe('shared vectors: keyPathsRefusedByGrammar', () => {
  for (const { keyPath } of vectors.keyPathsRefusedByGrammar) {
    test(`${JSON.stringify(keyPath)} is not a key and is never covered`, () => {
      expect(isKeyPath(keyPath)).toBe(false);
      expect(prefixCovers('apps/foo/', keyPath)).toBe(false);
    });
  }
});

// Grammar vectors (TEST-VECTORS.md). Where a row there predates the depth rule
// under `apps/` (a key needs three segments, a prefix two), the expectation
// below follows the depth rule.
const OWNER = 'did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const urn = (rest: string, owner = OWNER, network = 'default') => `urn:tinycloud:encryption:${owner}:${network}${rest}`;
const seg31 = 'a'.repeat(31);
const segments255 = Array.from({ length: 8 }, () => seg31).join('/').slice(0, 255);
const segments256 = [...Array.from({ length: 7 }, () => seg31), 'a'.repeat(32)].join('/');

const accepted: Array<[string, string, 'key' | 'prefix', string]> = [
  ['key under secrets/', urn('/secrets/software-factory'), 'key', 'secrets/software-factory'],
  ['prefix of an app', urn('/apps/tinychat/'), 'prefix', 'apps/tinychat'],
  ['8 segments, 255 bytes', urn(`/${segments255}`), 'key', segments255],
  ['did:web owner with colons', urn('/apps/x/y', 'did:web:example.com:user:alice'), 'key', 'apps/x/y'],
  ['network name with capital letter', urn('/apps/x/y', OWNER, 'Default'), 'key', 'apps/x/y'],
  ['prefix with a 255-byte path', urn(`/${segments255}/`), 'prefix', segments255],
  ['prefix of two segments under apps/', urn('/apps/x/'), 'prefix', 'apps/x'],
  ['dot, underscore and hyphen in a segment', urn('/apps/v1.2_x-y/k'), 'key', 'apps/v1.2_x-y/k'],
  ['did:key owner', urn('/apps/tinychat/k', 'did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi'), 'key', 'apps/tinychat/k'],
];

const refused: Array<[string, string]> = [
  ['bare network', urn('')],
  ['two trailing slashes', urn('/apps/x//')],
  ['empty segment', urn('/apps//x')],
  ['leading slash', urn('//apps')],
  ['uppercase segment', urn('/Apps/x')],
  ['.. segment', urn('/apps/../x')],
  ['. segment', urn('/apps/./x')],
  ['percent', urn('/apps/a%2Fb')],
  ['colon in path', urn('/apps/a:b')],
  ['space in path', urn('/apps/a b')],
  ['non-ASCII in path', urn('/apps/caf\u00e9')],
  ['9 segments', urn('/a/a/a/a/a/a/a/a/a')],
  ['65-byte segment', urn(`/${'a'.repeat(65)}`)],
  ['256-byte path', urn(`/${segments256}`)],
  ['segment starting with a dot', urn('/.hidden')],
  ['segment starting with a hyphen', urn('/-x')],
  ['empty prefix', urn('/')],
  ['hash in owner', urn('/apps/x/y', 'did:key:z6MkjHi79SMX4doJyo2w7jDTM6Fa7iX6EVZWXNbJ6RzBm3Wi#x')],
  ['hash in network', `urn:tinycloud:encryption:${OWNER}:default#x/apps/x/y`],
  ['question mark in network', `urn:tinycloud:encryption:${OWNER}:default?x/apps/x/y`],
  ['percent in owner', urn('/apps/x/y', 'did:web:example.com%3A8443')],
  ['uppercase URN scheme', `URN:tinycloud:encryption:${OWNER}:default/apps/x/y`],
  ['mixed-case namespace', `urn:TinyCloud:encryption:${OWNER}:default/apps/x/y`],
  ['prefix over 255 bytes', urn(`/${segments255}/a/`)],
  ['app key with two segments', urn('/apps/tinychat')],
  ['apps/ with nothing after it as a prefix', urn('/apps/')],
  ['network starting with a hyphen', urn('/apps/x/y', OWNER, '-x')],
  ['network of 65 characters', urn('/apps/x/y', OWNER, 'n'.repeat(65))],
  ['bidi control in network', urn('/apps/x/y', OWNER, 'de\u202efault')],
  ['zero-width space in network', urn('/apps/x/y', OWNER, 'de\u200bfault')],
  ['trailing newline', `${urn('/apps/x/y')}\n`],
  ['newline inside the path', urn('/apps/x\n/y')],
  ['empty string', ''],
];

describe('parseKeyResource', () => {
  for (const [name, uri, kind, keyPath] of accepted) {
    test(`accepts ${name}`, () => {
      const parsed = parseKeyResource(uri);
      expect(parsed).not.toBeNull();
      expect(parsed!.kind).toBe(kind);
      expect(parsed!.isPrefix).toBe(kind === 'prefix');
      expect(parsed!.keyPath).toBe(keyPath);
    });
  }
  for (const [name, uri] of refused) {
    test(`refuses ${name}`, () => {
      expect(parseKeyResource(uri)).toBeNull();
    });
  }

  test('keeps the owner and network exactly as written', () => {
    expect(parseKeyResource(urn('/apps/x/y', OWNER, 'Default'))).toMatchObject({ owner: OWNER, network: 'Default' });
  });

  test('the 255-byte path vector is exactly 255 bytes, and one more byte is refused', () => {
    expect(segments255.length).toBe(255);
    expect(segments256.length).toBe(256);
    expect(parseKeyResource(urn(`/${segments255}a`))).toBeNull();
  });
});

describe('apps resource detection', () => {
  test.each([
    [urn('/apps/x/y'), true],
    [urn('/apps/x/'), true],
    [urn('/apps'), true],
    [urn('/apps/'), true],
    [urn('/Apps/x'), true],
    [urn('/APPS/x'), true],
    [`URN:TINYCLOUD:ENCRYPTION:${OWNER}:default/apps/x`, true],
    [urn('/appsx/y'), false],
    [urn('/apps.x/y'), false],
    [urn('/secrets/apps/x'), false],
    [urn(''), false],
    ['tinycloud:pkh:eip155:1:0xabc:default/kv/apps/x', false],
    ['', false],
  ])('%s -> %p', (resource, expected) => {
    expect(isAppsKeyResource(resource)).toBe(expected);
  });

  test('the text after the first slash is returned unvalidated', () => {
    expect(keyPathOfResource(urn('/a//b'))).toBe('a//b');
    expect(keyPathOfResource(urn(''))).toBeNull();
    expect(keyPathOfResource('tinycloud:x/y')).toBeNull();
  });
});
