import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { APP_KEY_GROUP_PARTIAL_MESSAGE, appKeyRefusalMessage } from '../services/app-key-refusal';
import { bindWellKnownManifestBytes, canonicalManifestSha256Hex } from '../services/manifest-origin-fetch';
import {
  admitAppKeys,
  appKeyAdmissionRefusal,
  appKeyOrigin,
  hostBinding,
  parseManifestKeys,
  siweSchemeOk,
  type AppKeyAdmissionFailure,
  type AppKeyAdmissionInput,
} from '../services/app-key-gate';

// Shared vectors: the same files the node and the SDK pass.
const appIdVectors = JSON.parse(readFileSync(new URL('./app-id-vectors.json', import.meta.url), 'utf8')) as {
  hostBinding: { cases: Array<{ origin: string; id: string; bound: boolean }> };
};
const manifestVectors = JSON.parse(readFileSync(new URL('./manifest-keys-vectors.json', import.meta.url), 'utf8')) as {
  cases: Array<{
    id: string;
    app_id: string;
    keys?: unknown;
    keys_generated?: { count: number; path_template: string; abilities: string[] };
    expect: 'valid' | 'invalid';
  }>;
};

describe('shared vectors: hostBinding (every origin run with its own scheme, none skipped)', () => {
  for (const { origin, id, bound } of appIdVectors.hostBinding.cases) {
    test(`${origin} + ${JSON.stringify(id)} -> ${bound}`, () => {
      expect(hostBinding(origin, id)).toBe(bound);
    });
  }

  test('the three Unicode cases: the id decides, and a Unicode origin is read in its A-label form', () => {
    expect(hostBinding('https://xn--bcher-kva.example', 'example.b\u00fccher')).toBe(false);
    expect(hostBinding('https://b\u00fccher.example', 'example.xn--bcher-kva')).toBe(true);
    expect(hostBinding('https://b\u00fccher.example', 'example.b\u00fccher')).toBe(false);
  });

  test.each([
    ['an empty port', 'https://listen.tinycloud.xyz:'],
    ['port 443 written out', 'https://listen.tinycloud.xyz:443x'],
    ['userinfo', 'https://user@listen.tinycloud.xyz'],
    ['a path', 'https://listen.tinycloud.xyz/app'],
    ['a query', 'https://listen.tinycloud.xyz?x=1'],
    ['an IPv4 address in hex form', 'https://0x7f.1'],
    ['an IPv6 address', 'https://[::1]'],
    ['an underscore in a label', 'https://li_sten.tinycloud.xyz'],
    ['a host ending in localhost', 'https://listen.localhost'],
    ['a label with a leading hyphen', 'https://-listen.tinycloud.xyz'],
    ['a label with a trailing hyphen', 'https://listen-.tinycloud.xyz'],
    ['a label of 64 characters', `https://${'a'.repeat(64)}.tinycloud.xyz`],
    ['not a URL', 'listen.tinycloud.xyz'],
    ['wss', 'wss://listen.tinycloud.xyz'],
  ])('does not bind %s', (_name, origin) => {
    expect(hostBinding(origin, 'xyz.tinycloud.listen')).toBe(false);
  });

  test('a label of 63 characters is an acceptable origin (no id that long exists), and a hyphen inside a label still binds', () => {
    const label = 'a'.repeat(63);
    expect(appKeyOrigin(`https://${label}.tinycloud.xyz`, `https://${label}.tinycloud.xyz`)).toBe(`https://${label}.tinycloud.xyz`);
    expect(hostBinding('https://my-app.tinycloud.xyz', 'xyz.tinycloud.my-app')).toBe(true);
    expect(hostBinding('https://xn--bcher-kva.example', 'example.xn--bcher-kva')).toBe(true);
  });

  test('an id binds only on a label boundary', () => {
    expect(hostBinding('https://listen.tinycloud.xyz', 'xyz.tinycloud.listen.notes')).toBe(true);
    expect(hostBinding('https://listen.tinycloud.xyz', 'xyz.tinycloud.listen-notes')).toBe(false);
    expect(hostBinding('https://listen.tinycloud.xyz', 'XYZ.tinycloud.listen')).toBe(false);
  });
});

describe('shared vectors: manifest keys (CN-13a, 38 cases)', () => {
  for (const vector of manifestVectors.cases) {
    test(`${vector.id}: ${vector.expect}`, () => {
      const keys = vector.keys_generated
        ? Array.from({ length: vector.keys_generated.count }, (_, i) => ({
            path: vector.keys_generated!.path_template.replace('{i}', String(i)),
            abilities: vector.keys_generated!.abilities,
          }))
        : vector.keys;
      const result = parseManifestKeys(vector.app_id, keys);
      expect(result.status === 'invalid').toBe(vector.expect === 'invalid');
    });
  }

  test('an empty array is valid and declares nothing; no keys field is absent', () => {
    expect(parseManifestKeys('healthlog', [])).toEqual({ status: 'valid', declarations: [] });
    expect(parseManifestKeys('healthlog', undefined)).toEqual({ status: 'absent' });
  });

  test('a valid block keeps the declarations as written', () => {
    expect(
      parseManifestKeys('healthlog', [
        { prefix: 'apps/healthlog/', abilities: ['decrypt'] },
        { path: 'apps/healthlog/x', abilities: ['key.block'] },
      ]),
    ).toEqual({
      status: 'valid',
      declarations: [
        { prefix: 'apps/healthlog/', abilities: ['decrypt'] },
        { path: 'apps/healthlog/x', abilities: ['key.block'] },
      ],
    });
  });
});

describe('appKeyOrigin', () => {
  test('both origins present, equal and in URL-parser form', () => {
    expect(appKeyOrigin('https://listen.tinycloud.xyz', 'https://listen.tinycloud.xyz')).toBe('https://listen.tinycloud.xyz');
  });

  test.each([
    ['different strings', 'https://listen.tinycloud.xyz', 'https://notes.tinycloud.xyz'],
    ['upper case, even when equal', 'https://LISTEN.tinycloud.xyz', 'https://LISTEN.tinycloud.xyz'],
    ['a trailing slash', 'https://listen.tinycloud.xyz/', 'https://listen.tinycloud.xyz/'],
    ['a default port written out', 'https://listen.tinycloud.xyz:443', 'https://listen.tinycloud.xyz:443'],
    ['a U-label host', 'https://b\u00fccher.example', 'https://b\u00fccher.example'],
    ['http', 'http://listen.tinycloud.xyz', 'http://listen.tinycloud.xyz'],
    ['localhost', 'https://localhost', 'https://localhost'],
    ['an IP address', 'https://127.0.0.1', 'https://127.0.0.1'],
    ['a single label', 'https://intranet', 'https://intranet'],
    ['a trailing dot', 'https://listen.tinycloud.xyz.', 'https://listen.tinycloud.xyz.'],
    ['a host ending in localhost', 'https://listen.localhost', 'https://listen.localhost'],
    ['a label with a leading hyphen', 'https://-listen.tinycloud.xyz', 'https://-listen.tinycloud.xyz'],
    ['a label with a trailing hyphen', 'https://listen-.tinycloud.xyz', 'https://listen-.tinycloud.xyz'],
    ['a label of 64 characters', `https://${'a'.repeat(64)}.tinycloud.xyz`, `https://${'a'.repeat(64)}.tinycloud.xyz`],
  ])('refuses %s', (_name, requestOrigin, reportedOrigin) => {
    expect(appKeyOrigin(requestOrigin, reportedOrigin)).toBeNull();
  });

  test.each([[undefined, 'https://a.b'], ['https://a.b', undefined], [null, null], [1, 1]])('refuses %p / %p', (a, b) => {
    expect(appKeyOrigin(a, b)).toBeNull();
  });
});

describe('siweSchemeOk', () => {
  const header = (domain: string) => `${domain} wants you to sign in with your Ethereum account:\n0xabc\n`;

  test.each([
    ['no scheme', 'listen.tinycloud.xyz', true],
    ['https', 'https://listen.tinycloud.xyz', true],
    ['HTTPS', 'HTTPS://listen.tinycloud.xyz', true],
    ['Https', 'Https://listen.tinycloud.xyz', true],
    ['http', 'http://listen.tinycloud.xyz', false],
    ['ws', 'ws://listen.tinycloud.xyz', false],
    ['wss', 'wss://listen.tinycloud.xyz', false],
    ['an empty trailing port', 'listen.tinycloud.xyz:', false],
    ['a port', 'listen.tinycloud.xyz:8443', false],
    ['https and a port', 'https://listen.tinycloud.xyz:443', false],
  ])('%s', (_name, domain, expected) => {
    expect(siweSchemeOk(header(domain))).toBe(expected);
  });

  test('text without a header is not accepted', () => {
    expect(siweSchemeOk('not a message')).toBe(false);
  });
});

const ADDRESS = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const APP_ID = 'xyz.tinycloud.listen';
const ORIGIN = 'https://listen.tinycloud.xyz';
const urn = (rest: string, owner = OWNER, network = 'default') => `urn:tinycloud:encryption:${owner}:${network}${rest}`;
const E = 'tinycloud.encryption/';

function input(over: Partial<AppKeyAdmissionInput> = {}): AppKeyAdmissionInput {
  return {
    siwe: 'listen.tinycloud.xyz wants you to sign in with your Ethereum account:\n0xabc\n',
    resources: [[urn(`/apps/${APP_ID}/`), [`${E}key.create`, `${E}decrypt`]]],
    requestOrigin: ORIGIN,
    reportedOrigin: ORIGIN,
    siweOriginChecked: true,
    ticket: false,
    manifestBound: true,
    declaredAppId: APP_ID,
    declaredKeys: parseManifestKeys(APP_ID, [{ prefix: `apps/${APP_ID}/`, abilities: ['key.create', 'decrypt'] }]),
    ownerDid: OWNER,
    expirationTime: '2026-11-23T10:00:00.000Z',
    ...over,
  };
}

describe('admitAppKeys', () => {
  test('admits a declared prefix and returns the resources as written', () => {
    expect(admitAppKeys(input())).toEqual({
      ok: true,
      admitted: [{ resource: urn(`/apps/${APP_ID}/`), abilities: [`${E}key.create`, `${E}decrypt`] }],
    });
  });

  test('admits an exact key under a declared prefix, and an exact declared key', () => {
    expect(admitAppKeys(input({ resources: [[urn(`/apps/${APP_ID}/a/b`), [`${E}decrypt`]]] })).ok).toBe(true);
    const exact = parseManifestKeys(APP_ID, [{ path: `apps/${APP_ID}/api-token`, abilities: ['key.block'] }]);
    expect(admitAppKeys(input({ declaredKeys: exact, resources: [[urn(`/apps/${APP_ID}/api-token`), [`${E}key.block`]]] })).ok).toBe(true);
  });

  test('a SIWE header with an https scheme passes the helper; the route\'s origin check still refuses it', () => {
    const siwe = 'https://listen.tinycloud.xyz wants you to sign in with your Ethereum account:\n0xabc\n';
    expect(admitAppKeys(input({ siwe })).ok).toBe(true);
  });

  test('admits the short ability namespace as written', () => {
    expect(admitAppKeys(input({ resources: [[urn(`/apps/${APP_ID}/k`), ['encryption/decrypt']]] })).ok).toBe(true);
  });

  test('admits an app id that extends the host with a dot', () => {
    const id = `${APP_ID}.notes`;
    const keys = parseManifestKeys(id, [{ prefix: `apps/${id}/`, abilities: ['decrypt'] }]);
    expect(admitAppKeys(input({ declaredAppId: id, declaredKeys: keys, resources: [[urn(`/apps/${id}/`), [`${E}decrypt`]]] })).ok).toBe(true);
  });

  const refused: Array<[string, Partial<AppKeyAdmissionInput>, AppKeyAdmissionFailure]> = [
    ['a prepared-handoff ticket', { ticket: true }, 'non_browser'],
    ['an origin check that was not fully ok', { siweOriginChecked: false }, 'origin'],
    ['different request and reported origins', { reportedOrigin: 'https://notes.tinycloud.xyz' }, 'origin'],
    ['an upper-case origin on both fields', { requestOrigin: 'https://LISTEN.tinycloud.xyz', reportedOrigin: 'https://LISTEN.tinycloud.xyz' }, 'origin'],
    ['a missing reported origin', { reportedOrigin: undefined }, 'origin'],
    ['an origin with a port', { requestOrigin: `${ORIGIN}:8443`, reportedOrigin: `${ORIGIN}:8443` }, 'origin'],
    ['a SIWE header with an http scheme', { siwe: `http://listen.tinycloud.xyz wants you to sign in with your Ethereum account:\n` }, 'origin'],
    ['a SIWE header with a port', { siwe: `listen.tinycloud.xyz:443 wants you to sign in with your Ethereum account:\n` }, 'origin'],
    ['a manifest that is not origin-bound', { manifestBound: false }, 'manifest_unverified'],
    ['a manifest with no app_id', { declaredAppId: undefined }, 'not_declared'],
    ['an app_id that is not a valid id', { declaredAppId: 'Xyz.App' }, 'not_declared'],
    ['an app id that belongs to another host', { declaredAppId: 'xyz.tinycloud.notes' }, 'app_id'],
    ['an app id that only starts with the host text', { declaredAppId: `${APP_ID}x` }, 'app_id'],
    ['no keys block', { declaredKeys: undefined }, 'not_declared'],
    ['an absent keys block', { declaredKeys: { status: 'absent' } }, 'not_declared'],
    ['an invalid keys block', { declaredKeys: { status: 'invalid' } }, 'keys_unreadable'],
    ['an empty keys block', { declaredKeys: { status: 'valid', declarations: [] } }, 'not_declared'],
    ['no Expiration Time', { expirationTime: '' }, 'no_expiry'],
    ['an Expiration Time that is not a date', { expirationTime: 'soon' }, 'no_expiry'],
    ['no apps/ resource', { resources: [] }, 'not_declared'],
    ['another owner', { resources: [[urn(`/apps/${APP_ID}/`, 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001'), [`${E}decrypt`]]] }, 'account_mismatch'],
    ['a lower-case owner address', { resources: [[urn(`/apps/${APP_ID}/`, OWNER.toLowerCase()), [`${E}decrypt`]]] }, 'account_mismatch'],
    ['another chain', { resources: [[urn(`/apps/${APP_ID}/`, `did:pkh:eip155:5:${ADDRESS}`), [`${E}decrypt`]]] }, 'account_mismatch'],
    ['another network', { resources: [[urn(`/apps/${APP_ID}/`, OWNER, 'team'), [`${E}decrypt`]]] }, 'account_mismatch'],
    ['another app prefix', { resources: [[urn('/apps/xyz.tinycloud.notes/'), [`${E}decrypt`]]] }, 'not_declared'],
    ['a deeper prefix than the declared one', { resources: [[urn(`/apps/${APP_ID}/sub/`), [`${E}decrypt`]]] }, 'not_declared'],
    ['a key outside the app prefix', { resources: [[urn('/apps/xyz.tinycloud.listenx/k'), [`${E}decrypt`]]] }, 'not_declared'],
    ['an ability the manifest does not declare', { resources: [[urn(`/apps/${APP_ID}/`), [`${E}key.block`]]] }, 'not_declared'],
    ['key.delete', { resources: [[urn(`/apps/${APP_ID}/k`), [`${E}key.delete`]]] }, 'not_declared'],
    ['a wildcard ability', { resources: [[urn(`/apps/${APP_ID}/k`), [`${E}*`]]] }, 'not_declared'],
    ['an ability in the wrong case', { resources: [[urn(`/apps/${APP_ID}/k`), [`${E}Decrypt`]]] }, 'not_declared'],
    ['the bare network ability on an app key', { resources: [[urn(`/apps/${APP_ID}/k`), [`${E}network.create`]]] }, 'not_declared'],
    ['a resource that is not a key', { resources: [[urn('/apps/'), [`${E}decrypt`]]] }, 'not_declared'],
    ['a resource with no abilities', { resources: [[urn(`/apps/${APP_ID}/k`), []]] }, 'not_declared'],
    ['one undeclared resource among declared ones', {
      resources: [
        [urn(`/apps/${APP_ID}/`), [`${E}decrypt`]],
        [urn('/apps/xyz.tinycloud.notes/'), [`${E}decrypt`]],
      ],
    }, 'not_declared'],
  ];

  test.each(refused)('refuses %s', (_name, over, reason) => {
    expect(admitAppKeys(input(over))).toEqual({ ok: false, reason });
  });

  test('a declared path does not cover a prefix request', () => {
    const exact = parseManifestKeys(APP_ID, [{ path: `apps/${APP_ID}/k`, abilities: ['decrypt'] }]);
    expect(admitAppKeys(input({ declaredKeys: exact, resources: [[urn(`/apps/${APP_ID}/`), [`${E}decrypt`]]] }))).toEqual({
      ok: false,
      reason: 'not_declared',
    });
  });

  test('an ability declared only on another declaration does not cover the key', () => {
    const keys = parseManifestKeys(APP_ID, [
      { prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] },
      { path: `apps/${APP_ID}/other`, abilities: ['key.block'] },
    ]);
    const result = admitAppKeys(input({ declaredKeys: keys, resources: [[urn(`/apps/${APP_ID}/k`), [`${E}key.block`]]] }));
    expect(result).toEqual({ ok: false, reason: 'not_declared' });
  });

  test('every refusal reason maps to its own refusal', () => {
    expect(appKeyAdmissionRefusal('origin')).toEqual({ reason: 'apps_key_origin' });
    expect(appKeyAdmissionRefusal('app_id')).toEqual({ reason: 'apps_key_app_id' });
    expect(appKeyAdmissionRefusal('manifest_unverified')).toEqual({ reason: 'apps_key_manifest' });
    expect(appKeyAdmissionRefusal('keys_unreadable')).toEqual({ reason: 'apps_key_keys' });
    expect(appKeyAdmissionRefusal('no_expiry')).toEqual({ reason: 'apps_key_expiry' });
    expect(appKeyAdmissionRefusal('account_mismatch')).toEqual({ reason: 'apps_key_account' });
    for (const reason of ['non_browser', 'not_declared'] as const) {
      expect(appKeyAdmissionRefusal(reason)).toEqual({ reason: 'apps_key' });
    }
  });
});

describe('the manifest fetch reads the app-key fields of the fetched file', () => {
  function bind(manifest: Record<string, unknown>) {
    const result = bindWellKnownManifestBytes(
      new TextEncoder().encode(JSON.stringify(manifest)),
      canonicalManifestSha256Hex(manifest),
    );
    expect(result.ok).toBe(true);
    return result.manifest!;
  }

  test('app_id and a valid keys block', () => {
    const manifest = bind({ app_id: APP_ID, name: 'Listen', keys: [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] }] });
    expect(manifest.declaredAppId).toBe(APP_ID);
    expect(manifest.declaredKeys).toEqual({ status: 'valid', declarations: [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] }] });
  });

  test('a camelCase appId is shown but is not the app_id the gate reads', () => {
    const manifest = bind({ appId: APP_ID, name: 'Listen', keys: [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] }] });
    expect(manifest.appId).toBe(APP_ID);
    expect(manifest.declaredAppId).toBeUndefined();
    expect(manifest.declaredKeys).toEqual({ status: 'invalid' });
  });

  test('no keys field is not a declaration', () => {
    const manifest = bind({ app_id: APP_ID, name: 'Listen' });
    expect(manifest.declaredAppId).toBe(APP_ID);
    expect(manifest.declaredKeys).toBeUndefined();
  });

  test('an invalid keys block is kept as invalid, never partly', () => {
    const manifest = bind({
      app_id: APP_ID,
      keys: [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] }, { path: `apps/${APP_ID}/k`, abilities: ['key.delete'] }],
    });
    expect(manifest.declaredKeys).toEqual({ status: 'invalid' });
  });
});

describe('the words for each admission failure', () => {
  const texts: Array<[Parameters<typeof appKeyAdmissionRefusal>[0], string]> = [
    ['origin', "App keys can only be requested by the app's own website, so OpenKey didn't approve this request."],
    ['app_id', "This app doesn't belong to this website, so OpenKey didn't approve its keys."],
    ['manifest_unverified', "OpenKey couldn't check this website's app details, so it didn't approve this request."],
    ['keys_unreadable', "This website's list of app keys can't be read, so OpenKey didn't approve this request."],
    ['no_expiry', "This request doesn't say when access ends, so OpenKey didn't approve it."],
    ['account_mismatch', "This request doesn't match your account, so OpenKey didn't approve it."],
    ['not_declared', "This website doesn't list the key this app asked for, so OpenKey didn't approve it."],
  ];

  test.each(texts)('%s', (reason, text) => {
    expect(appKeyRefusalMessage(appKeyAdmissionRefusal(reason), 'browser')).toBe(text);
  });

  test('a ticket gets the sign-in wording', () => {
    expect(appKeyRefusalMessage(appKeyAdmissionRefusal('non_browser'), 'non_browser')).toBe(
      "App keys can only be requested through a website's sign-in, not from the command line or a device sign-in, so OpenKey didn't approve this request.",
    );
  });

  test('the partial selection text', () => {
    expect(APP_KEY_GROUP_PARTIAL_MESSAGE).toBe("App keys can only be approved together, so OpenKey didn't approve this request.");
  });

  test('every text is different', () => {
    expect(new Set(texts.map(([, text]) => text)).size).toBe(texts.length);
  });
});
