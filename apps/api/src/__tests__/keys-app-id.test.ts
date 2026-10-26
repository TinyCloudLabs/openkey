import { afterAll, describe, expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';

const testHome = execFileSync('mktemp', ['-d', '-p', '/var/tmp', 'keysid.XXXXXX'], { encoding: 'utf8' }).trim();
const homeNames = ['HOME', 'COURIER_HOME', 'BUN_INSTALL_CACHE_DIR', 'TC_HOME', 'TINYCLOUD_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME'] as const;
const savedHomes = homeNames.map(name => [name, process.env[name]] as const);
for (const name of homeNames) process.env[name] = testHome;
if (!testHome.startsWith('/var/tmp/keysid.') || homeNames.some(name => process.env[name] !== testHome)) {
  throw new Error('The keys-app-id test home is not isolated');
}
writeFileSync(`${testHome}/path-record`, `${testHome}\n`, { mode: 0o600 });
afterAll(() => {
  for (const [name, value] of savedHomes) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(testHome, { recursive: true, force: true });
});

const { bindWellKnownManifestBytes, canonicalManifestSha256Hex } = await import('../services/manifest-origin-fetch');
const { admitAppKeys } = await import('../services/app-key-gate');

const ORIGIN = 'https://tinycloud.chat';
const KEYS_ID = 'chat.tinycloud.tinychat';
const OTHER_ID = 'chat.tinycloud.other';
const UNBOUND_ID = 'xyz.tinycloud.tinychat';
const OWNER = 'did:pkh:eip155:1:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const ability = 'tinycloud.encryption/decrypt';
const resource = (id: string) => `urn:tinycloud:encryption:${OWNER}:default/apps/${id}/token`;
const declaration = (id: string) => [{ path: `apps/${id}/token`, abilities: ['decrypt'] }];

function admission(manifest: Record<string, unknown>, requestedId = KEYS_ID) {
  const binding = bindWellKnownManifestBytes(
    new TextEncoder().encode(JSON.stringify(manifest)),
    canonicalManifestSha256Hex(manifest),
  );
  if (!binding.ok || !binding.manifest) throw new Error('Manifest digest did not bind');
  return {
    keys: binding.manifest.declaredKeys,
    result: admitAppKeys({
      siwe: 'tinycloud.chat wants you to sign in with your Ethereum account:\n0xabc\n',
      resources: [[resource(requestedId), [ability]]],
      requestOrigin: ORIGIN,
      reportedOrigin: ORIGIN,
      siweOriginChecked: true,
      ticket: false,
      manifestBound: true,
      declaredAppId: binding.manifest.declaredAppId,
      declaredKeysAppId: binding.manifest.declaredKeysAppId,
      declaredKeys: binding.manifest.declaredKeys,
      ownerDid: OWNER,
      expirationTime: '2026-11-23T10:00:00.000Z',
    }),
  };
}

const admitted = { ok: true as const, admitted: [{ resource: resource(KEYS_ID), abilities: [ability] }] };

describe('origin-bound keys_app_id', () => {
  test('absent field preserves app_id key admission', () => {
    expect(admission({ app_id: KEYS_ID, keys: declaration(KEYS_ID) }).result).toEqual(admitted);
  });

  test('a host-bound key namespace admits a matching path even with a separate data app id', () => {
    expect(admission({ app_id: 'dev.pages.okqa-dev', keys_app_id: KEYS_ID, keys: declaration(KEYS_ID) }).result).toEqual(admitted);
  });

  test('a host-bound key namespace admits its exact prefix', () => {
    expect(admission({ app_id: OTHER_ID, keys_app_id: KEYS_ID, keys: [{ prefix: `apps/${KEYS_ID}/`, abilities: ['decrypt'] }] }).result)
      .toEqual(admitted);
  });

  test.each([
    ['a host-bound data app id', KEYS_ID, UNBOUND_ID],
    ['another data app id', OTHER_ID, UNBOUND_ID],
    ['another app namespace', KEYS_ID, 'dev.pages.okqa-dev'],
  ])('refuses a key namespace not belonging to the origin with %s', (_label, appId, keysAppId) => {
    expect(admission({ app_id: appId, keys_app_id: keysAppId, keys: declaration(keysAppId) }, keysAppId).result)
      .toEqual({ ok: false, reason: 'app_id' });
  });

  test.each([[null], [7], [{}], [[]], [false]])('refuses non-string keys_app_id %j without using app_id', keysAppId => {
    const { keys, result } = admission({ app_id: KEYS_ID, keys_app_id: keysAppId, keys: declaration(KEYS_ID) });
    expect(keys).toEqual({ status: 'invalid' });
    expect(result).toEqual({ ok: false, reason: 'keys_unreadable' });
  });

  test('a non-string key namespace marks the block invalid even without keys', () => {
    const { keys, result } = admission({ app_id: KEYS_ID, keys_app_id: null });
    expect(keys).toEqual({ status: 'invalid' });
    expect(result).toEqual({ ok: false, reason: 'keys_unreadable' });
  });

  test.each(['', 'Invalid.Id', 'chat.tinycloudx'])('refuses invalid string keys_app_id %j', keysAppId => {
    const { keys, result } = admission({ app_id: KEYS_ID, keys_app_id: keysAppId, keys: declaration(KEYS_ID) });
    expect(keys).toEqual({ status: 'invalid' });
    expect(result.ok).toBe(false);
  });

  test.each([
    ['path', declaration(OTHER_ID)],
    ['prefix', [{ prefix: `apps/${OTHER_ID}/`, abilities: ['decrypt'] }]],
  ])('refuses %s declarations outside the key namespace', (_label, keys) => {
    expect(admission({ app_id: OTHER_ID, keys_app_id: KEYS_ID, keys }).result)
      .toEqual({ ok: false, reason: 'keys_unreadable' });
  });

  test('a resource under the data app id is not declared by the key namespace', () => {
    expect(admission({ app_id: OTHER_ID, keys_app_id: KEYS_ID, keys: declaration(KEYS_ID) }, OTHER_ID).result)
      .toEqual({ ok: false, reason: 'not_declared' });
  });
});
