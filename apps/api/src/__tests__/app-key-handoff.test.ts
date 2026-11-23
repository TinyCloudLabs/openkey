// The rules for a command-line request for one exact app key: the request
// shape, the host an app id belongs to, the exact SIWE, the app's file, and the
// prepared handoff claim.

import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  appKeyHandoffHost,
  appKeyHandoffRefusal,
  checkAppKeyHandoffSiwe,
  checkAppKeysFile,
  parseAppKeyHandoff,
  verifyAppKeyHandoffFile,
} from '../services/app-key-handoff';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';

const address = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string, owner = OWNER, network = 'default') => `urn:tinycloud:encryption:${owner}:${network}${rest}`;
const APP_ID = 'xyz.tinycloud.share';
const KEY = 'xyz.tinycloud.tinyapps.contacts/seal-v1';
const appKey = { appId: APP_ID, key: KEY };
const BOTH = ['tinycloud.encryption/decrypt', 'tinycloud.encryption/key.create'];
const DAY = 24 * 60 * 60 * 1000;
const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
const NOW = Date.parse('2026-11-23T12:00:00.000Z');

function siwe(raw: Record<string, string[]>, lifetimeMs = 3_600_000, extra: Record<string, unknown> = {}) {
  return prepareSession({
    address, chainId: 1, domain: 'cli.tinycloud.xyz',
    issuedAt: new Date(NOW).toISOString(), expirationTime: new Date(NOW + lifetimeMs).toISOString(),
    spaceId: SPACE, jwk, abilities: {} as never, rawAbilities: raw, ...extra,
  } as never).siwe;
}
const check = (message: string, over: Record<string, unknown> = {}) =>
  checkAppKeyHandoffSiwe({ siwe: message, appKey, ownerDid: OWNER, now: NOW, ...over });
const reasonOf = (result: ReturnType<typeof check>) => (result.ok ? 'ok' : result.reason);
const file = (body: unknown) => new TextEncoder().encode(JSON.stringify(body));
const listing = (over: Record<string, unknown> = {}) => ({
  type: 'openkey-app-keys',
  app_id: APP_ID, keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['decrypt', 'key.create'] }], ...over,
});

describe('parseAppKeyHandoff', () => {
  test('takes { appId, key } with a key relative to apps/<appId>/', () => {
    expect(parseAppKeyHandoff(appKey)).toEqual(appKey);
    expect(parseAppKeyHandoff({ appId: APP_ID, key: 'k' })).toEqual({ appId: APP_ID, key: 'k' });
  });

  test.each([
    ['null', null],
    ['an array', []],
    ['an extra field', { ...appKey, network: 'default' }],
    ['no key', { appId: APP_ID }],
    ['an absolute key', { appId: APP_ID, key: `apps/${APP_ID}/k` }],
    ['a leading slash', { appId: APP_ID, key: '/k' }],
    ['a trailing slash (a prefix)', { appId: APP_ID, key: 'k/' }],
    ['an empty key', { appId: APP_ID, key: '' }],
    ['a dot segment', { appId: APP_ID, key: 'a/../b' }],
    ['upper case', { appId: APP_ID, key: 'K' }],
    ['nine segments in all', { appId: APP_ID, key: 'a/b/c/d/e/f/g' }],
    ['an app id with a slash', { appId: 'xyz/tinycloud', key: 'k' }],
    ['numbers', { appId: 1, key: 2 }],
  ])('refuses %s', (_name, value) => {
    expect(parseAppKeyHandoff(value)).toBeNull();
  });
});

describe('appKeyHandoffHost', () => {
  test('is the app id with its labels reversed', () => {
    expect(appKeyHandoffHost('xyz.tinycloud.share')).toBe('share.tinycloud.xyz');
    expect(appKeyHandoffHost('com.example')).toBe('example.com');
  });

  test.each(['xyz', 'a_b.example.com', 'localhost.tinycloud', '1.2.3.4', 'xyz.-bad.share', ''])('an id that is no host has none (%s)', (id) => {
    expect(appKeyHandoffHost(id)).toBeNull();
  });
});

describe('checkAppKeyHandoffSiwe', () => {
  const resource = urn(`/apps/${APP_ID}/${KEY}`);

  test('admits exactly the key with decrypt and key.create and reports the expiry', () => {
    const result = check(siwe({ [resource]: BOTH }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.grant.admitted).toEqual({ resource, abilities: BOTH });
      expect(result.grant.expirationTime).toBe(new Date(NOW + 3_600_000).toISOString());
    }
  });

  test('without an owner it reads the owner from the SIWE (the claim)', () => {
    expect(reasonOf(check(siwe({ [resource]: BOTH }), { ownerDid: undefined }))).toBe('ok');
  });

  test('ability order does not matter', () => {
    expect(reasonOf(check(siwe({ [resource]: [...BOTH].reverse() })))).toBe('ok');
  });

  test.each([
    ['a second key', { [resource]: BOTH, [urn(`/apps/${APP_ID}/other`)]: BOTH }, 'recap'],
    ['a prefix', { [urn(`/apps/${APP_ID}/`)]: BOTH }, 'recap'],
    ['another key', { [urn(`/apps/${APP_ID}/other`)]: BOTH }, 'recap'],
    ['another app', { [urn(`/apps/xyz.tinycloud.listen/${KEY}`)]: BOTH }, 'recap'],
    ['a key outside apps', { [urn('/secrets/x')]: BOTH }, 'recap'],
    ['decrypt only', { [resource]: [BOTH[0]!] }, 'recap'],
    ['key.create only', { [resource]: [BOTH[1]!] }, 'recap'],
    ['key.block as well', { [resource]: [...BOTH, 'tinycloud.encryption/key.block'] }, 'recap'],
    ['key.delete as well', { [resource]: [...BOTH, 'tinycloud.encryption/key.delete'] }, 'recap'],
    ['another owner', { [urn(`/apps/${APP_ID}/${KEY}`, 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111')]: BOTH }, 'account'],
    ['another network', { [urn(`/apps/${APP_ID}/${KEY}`, OWNER, 'other')]: BOTH }, 'account'],
    ['the bare network', { [urn('')]: BOTH }, 'recap'],
  ])('refuses %s', (_name, raw, reason) => {
    expect(reasonOf(check(siwe(raw)))).toBe(reason);
  });

  test('refuses a kv grant next to the key', () => {
    const message = siwe({ [resource]: BOTH }, 3_600_000, { abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } });
    expect(reasonOf(check(message))).toBe('recap');
  });

  test('refuses an id that is no host', () => {
    expect(reasonOf(checkAppKeyHandoffSiwe({ siwe: siwe({ [urn('/apps/xyz/k')]: BOTH }), appKey: { appId: 'xyz', key: 'k' }, ownerDid: OWNER, now: NOW }))).toBe('app_id');
  });

  test('seven days (and the skew) is the longest; more is refused, nothing is clamped', () => {
    expect(reasonOf(check(siwe({ [resource]: BOTH }, 7 * DAY)))).toBe('ok');
    expect(reasonOf(check(siwe({ [resource]: BOTH }, 7 * DAY + 61_000)))).toBe('expiry');
    expect(reasonOf(check(siwe({ [resource]: BOTH }, 30 * DAY)))).toBe('expiry');
  });

  test('an expiry in the past is refused', () => {
    expect(reasonOf(check(siwe({ [resource]: BOTH }, 3_600_000), { now: NOW + 2 * 3_600_000 }))).toBe('expiry');
  });

  test('text that is no SIWE is refused', () => {
    expect(reasonOf(check('hello'))).toBe('recap');
  });
});

describe('checkAppKeysFile', () => {
  test('lists the exact path with decrypt and key.create', () => {
    expect(checkAppKeysFile(file(listing()), appKey)).toEqual({ ok: true });
  });

  test('extra abilities and other entries do not matter', () => {
    const keys = [
      { path: `apps/${APP_ID}/zzz`, abilities: ['decrypt'] },
      { path: `apps/${APP_ID}/${KEY}`, abilities: ['key.block', 'key.create', 'decrypt'] },
      { prefix: `apps/${APP_ID}/`, abilities: ['decrypt'] },
    ];
    expect(checkAppKeysFile(file(listing({ keys })), appKey)).toEqual({ ok: true });
  });

  test.each([
    ['not JSON', new TextEncoder().encode('<html>'), 'file_invalid'],
    ['invalid UTF-8', new Uint8Array([0xff, 0xfe]), 'file_invalid'],
    ['an array', file([]), 'file_invalid'],
    ['no app_id', file({ type: 'openkey-app-keys', keys: listing().keys }), 'file_invalid'],
    ['a numeric app_id', file(listing({ app_id: 1 })), 'file_invalid'],
    ['another app_id', file(listing({ app_id: 'xyz.tinycloud.listen' })), 'file_app_mismatch'],
    ['no keys', file({ type: 'openkey-app-keys', app_id: APP_ID }), 'file_invalid'],
    ['keys that are not a list', file(listing({ keys: {} })), 'file_invalid'],
    ['more than 32 entries', file(listing({ keys: Array.from({ length: 33 }, (_, i) => ({ path: `apps/${APP_ID}/k${i}`, abilities: ['decrypt', 'key.create'] })) })), 'file_invalid'],
    ['an unknown entry field', file(listing({ keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['decrypt', 'key.create'], note: 'x' }] })), 'file_invalid'],
    ['a path of another app', file(listing({ keys: [{ path: 'apps/xyz.tinycloud.listen/k', abilities: ['decrypt', 'key.create'] }] })), 'file_invalid'],
    ['a repeated path', file(listing({ keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['decrypt'] }, { path: `apps/${APP_ID}/${KEY}`, abilities: ['key.create'] }] })), 'file_invalid'],
    ['an empty list', file(listing({ keys: [] })), 'key_not_listed'],
    ['a prefix only', file(listing({ keys: [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt', 'key.create'] }] })), 'key_not_listed'],
    ['a prefix of the key path', file(listing({ keys: [{ path: `apps/${APP_ID}/xyz.tinycloud.tinyapps.contacts`, abilities: ['decrypt', 'key.create'] }] })), 'key_not_listed'],
    ['decrypt only', file(listing({ keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['decrypt'] }] })), 'key_not_listed'],
    ['key.create only', file(listing({ keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['key.create'] }] })), 'key_not_listed'],
  ])('refuses %s', (_name, bytes, reason) => {
    expect(checkAppKeysFile(bytes, appKey)).toMatchObject({ ok: false, reason });
  });
});

describe('verifyAppKeyHandoffFile', () => {
  test('fetches the host of the app id and reads the answer', async () => {
    const hosts: string[] = [];
    const result = await verifyAppKeyHandoffFile(appKey, async (host) => { hosts.push(host); return { ok: true, bytes: file(listing()) }; });
    expect(result).toEqual({ ok: true, host: 'share.tinycloud.xyz' });
    expect(hosts).toEqual(['share.tinycloud.xyz']);
  });

  test('maps a missing file and an unavailable one', async () => {
    await expect(verifyAppKeyHandoffFile(appKey, async () => ({ ok: false, kind: 'missing', reason: 'x' }))).resolves.toEqual({ ok: false, reason: 'file_missing' });
    await expect(verifyAppKeyHandoffFile(appKey, async () => ({ ok: false, kind: 'unavailable', reason: 'x' }))).resolves.toEqual({ ok: false, reason: 'file_unavailable' });
  });

  test('fetches nothing for an id that is no host', async () => {
    let called = false;
    const result = await verifyAppKeyHandoffFile({ appId: 'xyz', key: 'k' }, async () => { called = true; return { ok: true, bytes: file({}) }; });
    expect(result).toEqual({ ok: false, reason: 'app_id' });
    expect(called).toBe(false);
  });
});

describe('appKeyHandoffRefusal', () => {
  test('answers each reason with a code the screen can match on', () => {
    expect(appKeyHandoffRefusal('file_missing', appKey)).toMatchObject({ status: 403, body: { code: 'app_keys_file_missing', reason: 'file_missing' } });
    expect(appKeyHandoffRefusal('file_app_mismatch', appKey).body.code).toBe('app_keys_file_invalid');
    expect(appKeyHandoffRefusal('file_unavailable', appKey).body.code).toBe('app_keys_file_unavailable');
    expect(appKeyHandoffRefusal('key_not_listed', appKey).body.code).toBe('app_key_not_listed');
    expect(appKeyHandoffRefusal('process_capacity')).toEqual({
      status: 429,
      body: {
        code: 'app_key_fetch_busy',
        reason: 'process_capacity',
        error: "OpenKey is busy and couldn't check apps' lists of keys for command-line tools. Nothing was approved. Try again in a minute.",
      },
    });
    expect(appKeyHandoffRefusal('expiry')).toMatchObject({ status: 400, body: { code: 'app_key_request_invalid' } });
  });

  test('the owner-visible lines are the owner screen words with the host and key name filled in', () => {
    const line = (reason: Parameters<typeof appKeyHandoffRefusal>[0]) => appKeyHandoffRefusal(reason, appKey).body.error;
    expect(line('file_missing')).toBe("OpenKey can't approve this request: share.tinycloud.xyz doesn't list keys that command-line tools can ask for. Nothing was approved.");
    expect(line('file_invalid')).toBe("OpenKey can't approve this request: share.tinycloud.xyz's list of keys for command-line tools can't be read. Nothing was approved.");
    expect(line('file_app_mismatch')).toBe(line('file_invalid'));
    expect(line('key_not_listed')).toBe("OpenKey can't approve this request: share.tinycloud.xyz doesn't let command-line tools ask for the key seal-v1. Nothing was approved.");
    expect(line('request_invalid')).toBe("OpenKey can't read the app key in this request. Nothing was approved.");
    expect(line('ticket_required')).toBe("App keys can be requested only through a command-line sign-in link. Nothing was approved.");
    expect(line('app_id')).toBe("This app id isn't a website address written in reverse, such as xyz.tinycloud.share. Nothing was approved.");
    expect(line('recap')).toBe("This request asks for more than the one app key it names. Nothing was approved.");
    expect(line('account')).toBe("This request was made for a different account. Nothing was approved.");
    expect(line('expiry')).toBe("This request lasts longer than 7 days. Nothing was approved.");
    expect(line('file_unavailable')).toBe("OpenKey couldn't check share.tinycloud.xyz's list of keys for command-line tools. Nothing was approved. Try again.");
  });
});

describe('prepared handoff claim with an appKey', () => {
  const resource = urn(`/apps/${APP_ID}/${KEY}`);
  const delivery = {
    handoffId: Buffer.alloc(32, 7).toString('base64url'),
    state: Buffer.alloc(32, 8).toString('base64url'),
    cancelSecret: Buffer.alloc(32, 9).toString('base64url'),
  };
  const claim = (message: string, over: Record<string, unknown> = { appKey }) => {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => NOW });
    return service.claim({
      transportVersion: 2,
      request: { protocolVersion: 1, siwe: message, jwk, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:session-cli', ...over },
      delivery,
    }, 'owner');
  };

  test('claims the one exact key', async () => {
    await expect(claim(siwe({ [resource]: BOTH }))).resolves.toMatchObject({ ticket: delivery.handoffId });
  });

  test('a claim of the same request is idempotent and a changed appKey is a different request', async () => {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => NOW });
    const message = siwe({ [resource]: BOTH });
    const body = (key: unknown) => ({
      transportVersion: 2,
      request: { protocolVersion: 1, siwe: message, jwk, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:session-cli', appKey: key },
      delivery,
    });
    await service.claim(body(appKey), 'owner');
    await expect(service.claim(body(appKey), 'owner')).resolves.toMatchObject({ ticket: delivery.handoffId });
    await expect(service.claim(body({ appId: APP_ID, key: 'other' }), 'owner')).rejects.toMatchObject({ code: 'app_key_request_invalid' });
  });

  test.each([
    ['a different key in the SIWE', siwe({ [urn(`/apps/${APP_ID}/other`)]: BOTH }), 'app_key_request_invalid', 403],
    ['a second resource', siwe({ [resource]: BOTH, [urn('/secrets/x')]: BOTH }), 'app_key_request_invalid', 403],
    ['one ability only', siwe({ [resource]: [BOTH[0]!] }), 'app_key_request_invalid', 403],
    ['more than seven days', siwe({ [resource]: BOTH }, 8 * DAY), 'app_key_request_invalid', 400],
  ])('refuses %s', async (_name, message, code, status) => {
    await expect(claim(message)).rejects.toMatchObject({ code, status });
  });

  test.each([
    ['a malformed appKey', { appKey: { appId: APP_ID } }],
    ['a null appKey', { appKey: null }],
    ['a presentation with it', { appKey, presentation: { manifestDigest: 'a'.repeat(64) } }],
  ])('refuses %s', async (_name, over) => {
    await expect(claim(siwe({ [resource]: BOTH }), over)).rejects.toMatchObject({ code: 'app_key_request_invalid', status: 400 });
  });

  test('without an appKey the app key is still refused for the command line', async () => {
    await expect(claim(siwe({ [resource]: BOTH }), {})).rejects.toMatchObject({ code: 'app_key_grant_refused', status: 403 });
  });
});
