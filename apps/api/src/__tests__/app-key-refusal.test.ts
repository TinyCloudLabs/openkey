import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { BOOTSTRAP_ALLOWLIST, BOOTSTRAP_SESSION_REQUESTS } from '@tinycloud/bootstrap';
import {
  appKeyRefusalBody,
  appKeyRefusalCode,
  appKeyRefusalForMessage,
  appKeyRefusalForSiwe,
  appKeyRefusalMessage,
  appKeyRefusalStatus,
} from '../services/app-key-refusal';

const ADDRESS = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const JWK = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

function siweWith(rawAbilities: Record<string, string[]> = {}, abilities: Record<string, unknown> | null = null): string {
  const now = new Date();
  return prepareSession({
    address: ADDRESS,
    chainId: 1,
    domain: 'listen.tinycloud.xyz',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk: JWK,
    abilities: (abilities ?? { kv: { [SPACE]: ['tinycloud.kv/get'] } }) as never,
    ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}),
  }).siwe;
}

const b64 = (json: string) => Buffer.from(json, 'utf8').toString('base64url');
const RECAP_LINE = /(- urn:recap:)[^\s]*/;

/** The SIWE with its first ReCap payload replaced by the given JSON text. */
function withRecapJson(siwe: string, json: string): string {
  return siwe.replace(RECAP_LINE, `$1${b64(json)}`);
}

/** The SIWE with its first ReCap resource line replaced by the given token. */
function withRecapToken(siwe: string, token: string): string {
  return siwe.replace(RECAP_LINE, `$1${token}`);
}

const att = (resource: string, abilities: string[]) =>
  JSON.stringify({ att: { [resource]: Object.fromEntries(abilities.map((a) => [a, [{}]])) }, prf: [] });

const base = siweWith();

describe('messages that are passed', () => {
  test('a sign-in with ordinary entries', () => {
    expect(appKeyRefusalForSiwe(base)).toBeNull();
  });

  test('default-network decrypt and network setup', () => {
    const siwe = siweWith({ [urn('')]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create'] });
    expect(appKeyRefusalForSiwe(siwe)).toBeNull();
  });

  test.each([
    ['a key outside apps/', '/secrets/x'],
    ['a prefix outside apps/', '/secrets/'],
    ['a path whose first segment only starts with apps', '/appsx/y'],
    ['a path whose first segment is apps.x', '/apps.x/y'],
    ['a key with apps deeper in the path', '/secrets/apps/x'],
  ])('%s', (_name, rest) => {
    const siwe = siweWith({ [urn(rest)]: ['tinycloud.encryption/decrypt'] });
    expect(appKeyRefusalForSiwe(siwe)).toBeNull();
  });

  test('a kv path that starts with apps/', () => {
    const siwe = siweWith({}, { kv: { [SPACE]: ['tinycloud.kv/get'], 'x': [] } });
    expect(appKeyRefusalForSiwe(withRecapJson(siwe, att(`${SPACE}/kv/apps/x`, ['tinycloud.kv/get'])))).toBeNull();
  });

  test('text that is not a sign-in message, even when it mentions a ReCap', () => {
    expect(appKeyRefusalForSiwe('hello urn:recap:%%%')).toBeNull();
    expect(appKeyRefusalForMessage('0x68656c6c6f')).toBeNull();
  });

  test("OpenKey's own bootstrap requests", () => {
    const withRaw = BOOTSTRAP_ALLOWLIST.filter((entry) => entry.rawAbilities !== undefined);
    expect(withRaw.length).toBeGreaterThan(0);
    for (const entry of withRaw) {
      const rawAbilities = Object.fromEntries(
        entry.rawAbilities!.map((raw) => [raw.resource.replace('{ownerDid}', OWNER), [...raw.actions]]),
      );
      expect(appKeyRefusalForSiwe(siweWith(rawAbilities))).toBeNull();
    }
    for (const [space, request] of Object.entries(BOOTSTRAP_SESSION_REQUESTS)) {
      const abilities: Record<string, Record<string, string[]>> = {};
      for (const resource of request.resources) {
        const short = resource.service.replace(/^tinycloud\./, '');
        (abilities[short] ??= {})[resource.path] = [...resource.actions];
      }
      const siwe = siweWith({}, abilities);
      expect(siwe).toContain('urn:recap:');
      expect(appKeyRefusalForSiwe(siwe), space).toBeNull();
    }
  });
});

describe('apps/ key resources are refused', () => {
  test.each([
    ['an exact key, decrypt', '/apps/xyz.tinycloud.listen/k', ['tinycloud.encryption/decrypt']],
    ['a prefix, create and decrypt', '/apps/xyz.tinycloud.listen/', ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt']],
    ['block', '/apps/xyz.tinycloud.listen/k', ['tinycloud.encryption/key.block']],
    ['unblock', '/apps/xyz.tinycloud.listen/k', ['tinycloud.encryption/key.unblock']],
    ['an unknown ability', '/apps/xyz.tinycloud.listen/k', ['tinycloud.encryption/anything']],
    ['a path with an empty segment', '/apps//x', ['tinycloud.encryption/decrypt']],
    ['the apps prefix alone', '/apps/', ['tinycloud.encryption/decrypt']],
    ['two segments under apps', '/apps/x', ['tinycloud.encryption/decrypt']],
    ['an upper-case first segment', '/Apps/x/y', ['tinycloud.encryption/decrypt']],
    ['an upper-case path', '/apps/X/y', ['tinycloud.encryption/decrypt']],
  ])('%s', (_name, rest, abilities) => {
    const refusal = appKeyRefusalForSiwe(siweWith({ [urn(rest)]: abilities }));
    expect(refusal).not.toBeNull();
    expect(appKeyRefusalCode(refusal!)).toBe('app_key_grant_refused');
    expect(appKeyRefusalStatus(refusal!)).toBe(403);
  });

  test('a well-formed key is reported as apps_key and a malformed one as apps_key_unparsed', () => {
    expect(appKeyRefusalForSiwe(siweWith({ [urn('/apps/x/y')]: ['tinycloud.encryption/decrypt'] }))).toEqual({ reason: 'apps_key' });
    expect(appKeyRefusalForSiwe(siweWith({ [urn('/apps//y')]: ['tinycloud.encryption/decrypt'] }))).toEqual({ reason: 'apps_key_unparsed' });
  });

  test.each([
    ['upper-case URN scheme', `URN:TINYCLOUD:ENCRYPTION:${OWNER}:default/apps/x/y`],
    ['mixed-case namespace', `urn:TinyCloud:Encryption:${OWNER}:default/apps/x/y`],
    ['escaped slashes', urn('/apps/x/y').replace(/\//g, '\\/')],
    ['an escaped letter in the first segment', urn('/\\u0061pps/x/y')],
  ])('the detector reads the decoded string: %s', (_name, resource) => {
    // `att` keys written as JSON text, so the escapes are decoded by the parser.
    const json = `{"att":{"${resource.replace(/"/g, '\\"')}":{"tinycloud.encryption/decrypt":[{}]}},"prf":[]}`;
    expect(appKeyRefusalForSiwe(withRecapJson(base, json))).not.toBeNull();
  });

  test('any later ReCap resource line is read, not only the first', () => {
    const first = `- urn:recap:${b64(att(`${SPACE}/kv/x`, ['tinycloud.kv/get']))}`;
    const second = `- urn:recap:${b64(att(urn('/apps/x/y'), ['tinycloud.encryption/decrypt']))}`;
    const siwe = base.replace(RECAP_LINE, `${first}\n${second}`);
    expect(appKeyRefusalForSiwe(siwe)).toEqual({ reason: 'apps_key' });
  });

  test('the same message as hex is refused through the message check only', () => {
    const siwe = siweWith({ [urn('/apps/x/y')]: ['tinycloud.encryption/decrypt'] });
    const hex = `0x${Buffer.from(siwe, 'utf8').toString('hex')}`;
    expect(appKeyRefusalForMessage(hex)).toEqual({ reason: 'apps_key' });
    expect(appKeyRefusalForMessage(siwe)).toEqual({ reason: 'apps_key' });
    expect(appKeyRefusalForSiwe(hex)).toBeNull();
  });
});

describe('key.delete is refused under every spelling', () => {
  test.each([
    ['on a key outside apps/', urn('/secrets/x'), 'tinycloud.encryption/key.delete'],
    ['on an apps/ prefix', urn('/apps/x/'), 'tinycloud.encryption/key.delete'],
    ['on the bare network', urn(''), 'tinycloud.encryption/key.delete'],
    ['in the short namespace', urn('/secrets/x'), 'encryption/key.delete'],
    ['upper-case', urn('/secrets/x'), 'TINYCLOUD.ENCRYPTION/KEY.DELETE'],
    ['under another service name', `${SPACE}/kv/x`, 'tinycloud.kv/key.delete'],
    ['under a wildcard namespace', urn('/secrets/x'), '*/key.delete'],
    ['with no namespace', urn('/secrets/x'), 'key.delete'],
  ])('%s', (_name, resource, ability) => {
    const refusal = appKeyRefusalForSiwe(withRecapJson(base, att(resource, [ability])));
    expect(refusal).toEqual({ reason: 'key_delete' });
    expect(appKeyRefusalCode(refusal!)).toBe('key_delete_not_grantable');
    expect(appKeyRefusalStatus(refusal!)).toBe(403);
  });

  test('is reported ahead of an apps/ resource in the same message', () => {
    const json = JSON.stringify({
      att: {
        [urn('/apps/x/y')]: { 'tinycloud.encryption/decrypt': [{}] },
        [urn('/secrets/z')]: { 'tinycloud.encryption/key.delete': [{}] },
      },
    });
    expect(appKeyRefusalForSiwe(withRecapJson(base, json))).toEqual({ reason: 'key_delete' });
  });

  test('a lookalike ability is not key.delete', () => {
    expect(appKeyRefusalForSiwe(withRecapJson(base, att(urn('/secrets/x'), ['tinycloud.encryption/key.deleted'])))).toBeNull();
  });
});

describe('a ReCap that cannot be read exactly is refused', () => {
  test.each([
    ['a repeated att key', `{"att":{"${urn('/secrets/x')}":{"tinycloud.encryption/decrypt":[{}]}},"att":{}}`],
    ['a repeated resource', `{"att":{"${urn('/secrets/x')}":{"a/b":[{}]},"${urn('/secrets/x')}":{"a/c":[{}]}}}`],
    ['a repeated ability', `{"att":{"${urn('/secrets/x')}":{"a/b":[{}],"a/b":[{}]}}}`],
    ['a repeated key written with an escape', `{"att":{"${urn('/secrets/x')}":{"a/b":[{}]},"${urn('/secrets/x')}":{}}}`.replace('"urn:tinycloud:encryption:did', '"\\u0075rn:tinycloud:encryption:did')],
    ['a repeated key inside an array element', `{"att":{"r":{"a/b":[{"k":1,"k":2}]}}}`],
    ['no att', '{"prf":[]}'],
    ['att as an array', '{"att":[]}'],
    ['an ability map that is not an object', `{"att":{"r":"a/b"}}`],
    ['JSON that is not an object', '[1,2]'],
    ['text that is not JSON', 'not json'],
  ])('%s', (_name, json) => {
    const refusal = appKeyRefusalForSiwe(withRecapJson(base, json));
    expect(refusal).toEqual({ reason: 'recap_unreadable' });
    expect(appKeyRefusalCode(refusal!)).toBe('invalid_siwe_recap');
    expect(appKeyRefusalStatus(refusal!)).toBe(400);
  });

  test.each([
    ['standard base64 characters', 'a+b/'],
    ['a character outside base64', 'abc$'],
    ['padding in the middle', 'ab=c'],
    ['an empty payload', ''],
  ])('a payload with %s', (_name, token) => {
    expect(appKeyRefusalForSiwe(withRecapToken(base, token))).toEqual({ reason: 'recap_unreadable' });
  });

  test('a non-canonical encoding of a valid payload', () => {
    const token = b64(att(`${SPACE}/kv/x`, ['tinycloud.kv/get']));
    // Change the final character so the unused trailing bits are not zero.
    const last = token.at(-1)!;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const other = alphabet[(alphabet.indexOf(last) + 1) % 64]!;
    expect(appKeyRefusalForSiwe(withRecapToken(base, token.slice(0, -1) + other))).toEqual({ reason: 'recap_unreadable' });
  });

  test('padded and unpadded base64url both decode', () => {
    const json = att(`${SPACE}/kv/x`, ['tinycloud.kv/get']);
    const padded = Buffer.from(json, 'utf8').toString('base64');
    expect(padded.includes('=') || padded.length % 4 === 0).toBe(true);
    expect(appKeyRefusalForSiwe(withRecapToken(base, padded.replace(/\+/g, '-').replace(/\//g, '_')))).toBeNull();
    expect(appKeyRefusalForSiwe(withRecapToken(base, b64(json)))).toBeNull();
  });

  test('every ReCap line is decoded: a bad second line refuses the message', () => {
    const good = `- urn:recap:${b64(att(`${SPACE}/kv/x`, ['tinycloud.kv/get']))}`;
    expect(appKeyRefusalForSiwe(base.replace(RECAP_LINE, `${good}\n- urn:recap:%%%`))).toEqual({ reason: 'recap_unreadable' });
  });
});

describe('the wasm-parsed entries are a second check', () => {
  const entry = (over: Partial<{ service: string; space: string; path: string; actions: string[] }>) => ({
    service: 'encryption',
    space: 'encryption',
    path: urn(''),
    actions: ['tinycloud.encryption/decrypt'],
    ...over,
  });

  test('passes ordinary entries', () => {
    expect(appKeyRefusalForSiwe(base, [entry({})])).toBeNull();
  });

  test.each([
    ['in path', { path: urn('/apps/x/y') }],
    ['in space', { space: urn('/apps/x/y'), path: '' }],
    ['under another service name', { service: 'kv', path: urn('/apps/x/y') }],
    ['with a capital letter', { path: urn('/Apps/x/y') }],
  ])('an apps/ resource %s', (_name, over) => {
    expect(appKeyRefusalForSiwe(base, [entry(over)])?.reason).toMatch(/^apps_key/);
  });

  test('a key.delete action', () => {
    expect(appKeyRefusalForSiwe(base, [entry({ actions: ['tinycloud.encryption/key.delete'] })])).toEqual({ reason: 'key_delete' });
  });

  test('the entries are checked even when the text scan finds nothing', () => {
    expect(appKeyRefusalForSiwe('not a sign-in message', [entry({ path: urn('/apps/x/y') })])).toEqual({ reason: 'apps_key' });
  });
});

describe('refusal text', () => {
  test('uses the approved wording per request source', () => {
    const appKey = { reason: 'apps_key' } as const;
    expect(appKeyRefusalMessage(appKey, 'browser')).toBe(
      "This website doesn't list the key this app asked for, so OpenKey didn't approve it.",
    );
    expect(appKeyRefusalMessage(appKey, 'non_browser')).toBe(
      'App keys can only be requested from a website, not from the command line or a device sign-in.',
    );
    expect(appKeyRefusalMessage({ reason: 'key_delete' }, 'browser')).toBe(
      "Apps can't be given permission to delete keys, so OpenKey didn't approve this request.",
    );
    expect(appKeyRefusalBody({ reason: 'key_delete' }, 'non_browser')).toEqual({
      error: "Apps can't be given permission to delete keys, so OpenKey didn't approve this request.",
      code: 'key_delete_not_grantable',
    });
  });
});
