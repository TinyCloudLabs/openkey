// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { encryptionOutsideAppsRefusal } from '../../../api/src/services/app-key-refusal';
import { isFirstPartyEncryptionOrigin } from '../../../api/src/services/first-party-origins';
import { refusesEncryptionOutsideApps } from './encryption-grant-refusal';

const OWNER = 'did:pkh:eip155:1:0xd559CCd9EB87c530A9a349262669386dE93cf412';
const OUTSIDE = 'https://outside-app.example';

function siwe(att: Record<string, Record<string, unknown[]>>, domain = 'outside-app.example'): string {
  const recap = Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url');
  return `${domain} wants you to sign in with your Ethereum account:\n0xd559CCd9EB87c530A9a349262669386dE93cf412\n\nSign in\n\nURI: https://${domain}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-11-13T00:00:00.000Z\nResources:\n- urn:recap:${recap}`;
}

/** What `/api/keys/:keyId/sign` decides for the same message and verified origin. */
const serverRefuses = (message: string, origin: string) =>
  !isFirstPartyEncryptionOrigin(origin) && encryptionOutsideAppsRefusal(message)?.reason === 'encryption_outside_apps';

describe('the widget refuses up front exactly the encryption grants the signing route refuses (TC-2928)', () => {
  const kv = { 'tinycloud:pkh:eip155:1:0xd559CCd9EB87c530A9a349262669386dE93cf412:applications/kv/notes/': { 'tinycloud.kv/get': [{}] } };
  const cases: Array<[string, string, string, boolean]> = [
    ['share prefix decrypt', siwe({ ...kv, [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/decrypt': [{}] } }), OUTSIDE, true],
    ['share key.create', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/key.create': [{}] } }), OUTSIDE, true],
    ['bare network decrypt', siwe({ [`urn:tinycloud:encryption:${OWNER}:default`]: { 'tinycloud.encryption/decrypt': [{}] } }), OUTSIDE, true],
    ['exact share key decrypt', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/share/abc`]: { 'tinycloud.encryption/decrypt': [{}] } }), OUTSIDE, true],
    ['upper-case prefix and ability', siwe({ [`URN:TINYCLOUD:ENCRYPTION:${OWNER}:default/share/`]: { 'Tinycloud.Encryption/DECRYPT': [{}] } }), OUTSIDE, true],
    ['the same grant from a first-party site', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/decrypt': [{}] } }, 'share.tinycloud.xyz'), 'https://share.tinycloud.xyz', false],
    ['the same grant from a first-party Pages preview', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/decrypt': [{}] } }, 'abc.share-2fz.pages.dev'), 'https://abc.share-2fz.pages.dev', false],
    ['the same grant from tinycloud.one', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/decrypt': [{}] } }, 'tinycloud.one'), 'https://tinycloud.one', false],
    ['the same grant from a look-alike of tinycloud.one', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/decrypt': [{}] } }, 'tinycloud.one.evil.example'), 'https://tinycloud.one.evil.example', true],
    ['decrypt under apps/', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/apps/notes/`]: { 'tinycloud.encryption/decrypt': [{}] } }), OUTSIDE, false],
    ['encrypt outside apps/', siwe({ [`urn:tinycloud:encryption:${OWNER}:default/share/`]: { 'tinycloud.encryption/encrypt': [{}] } }), OUTSIDE, false],
    ['storage only', siwe(kv), OUTSIDE, false],
    ['not a sign-in message', 'hello', OUTSIDE, false],
  ];

  for (const [name, message, origin, refused] of cases) {
    test(name, () => {
      expect(serverRefuses(message, origin)).toBe(refused);
      expect(refusesEncryptionOutsideApps(message, origin)).toBe(refused);
    });
  }
});
