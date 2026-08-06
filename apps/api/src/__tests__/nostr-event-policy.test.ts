// Per-kind payload policy: one accepted canonical fixture per supported
// kind (the exact shapes the Buzz web client produces) plus a rejection
// matrix for malformed, oversized, duplicated, and out-of-journey payloads.
// Destination binding is covered against real grant relay URLs.
import { describe, expect, test } from 'bun:test';
import { SUPPORTED_NOSTR_KINDS } from '@openkey/tee';
import {
  eventDestinationMatchesGrant,
  maxContentLengthForKind,
  validateEventForKind,
  POLICY_KINDS,
  type NostrEventTemplate,
} from '../services/nostr-event-policy';
import {
  isAllowedNip98Url,
  relayHttpOrigin,
  relayInvitesHttpBase,
  relayServerAuthority,
} from '../services/nostr-destinations';

const NOW = Math.floor(Date.now() / 1000);
const PK = 'a'.repeat(64);
const PK2 = 'b'.repeat(64);
const ID = 'c'.repeat(64);
const SHA = 'd'.repeat(64);
const UUID = '01234567-89ab-cdef-0123-456789abcdef';
const D32 = 'e'.repeat(32);

/** Minimal structurally valid NIP-44 v2 payload: version 2, 99 decoded bytes. */
const NIP44_PAYLOAD = (() => {
  const bytes = new Uint8Array(99);
  bytes[0] = 2;
  return Buffer.from(bytes).toString('base64');
})();

function tpl(kind: number, tags: string[][], content: string): NostrEventTemplate {
  return { pubkey: PK, created_at: NOW, kind, tags, content };
}

function ok(template: NostrEventTemplate) {
  const result = validateEventForKind(template);
  expect(result).toEqual({ ok: true });
}

function bad(template: NostrEventTemplate, reason?: string) {
  const result = validateEventForKind(template);
  expect(result.ok).toBe(false);
  if (reason && !result.ok) expect(result.reason).toBe(reason);
}

// The canonical accepted fixture for every kind in the Buzz matrix. If a
// kind is added to the capability model without a fixture here, the
// completeness test at the bottom fails.
const CANONICAL_FIXTURES: Record<number, NostrEventTemplate[]> = {
  0: [tpl(0, [], JSON.stringify({ name: 'Ocean', display_name: 'Ocean V', picture: 'https://x.example/p.png', about: 'hi', nip05: 'ocean@example.com' })), tpl(0, [], '{}')],
  7: [tpl(7, [['e', ID], ['h', 'chan-general']], '🔥')],
  9: [tpl(9, [['h', 'dev']], 'hello channel')],
  1984: [
    tpl(1984, [['p', PK2], ['e', ID, 'spam']], 'this is spam'),
    tpl(1984, [['p', PK2], ['e', ID, 'other']], ''),
  ],
  9030: [tpl(9030, [['p', PK2], ['role', 'member']], '')],
  9031: [tpl(9031, [['p', PK2]], '')],
  9032: [tpl(9032, [['p', PK2], ['role', 'admin']], '')],
  9040: [
    tpl(9040, [['p', PK2], ['expiration', String(NOW + 86400)], ['reason', 'spamming']], ''),
    tpl(9040, [['p', PK2]], ''),
  ],
  9041: [tpl(9041, [['p', PK2], ['reason', 'appeal accepted']], '')],
  9042: [tpl(9042, [['p', PK2], ['expiration', String(NOW + 3600)]], '')],
  9043: [tpl(9043, [['p', PK2]], '')],
  9044: [
    tpl(9044, [['report', ID], ['status', 'resolved'], ['action', 'ban'], ['reason', 'confirmed']], ''),
    tpl(9044, [['report', ID], ['status', 'dismissed'], ['action', 'dismiss']], ''),
  ],
  20001: [tpl(20001, [['status', 'online']], 'online'), tpl(20001, [['status', 'away']], 'away')],
  22242: [tpl(22242, [['relay', 'wss://relay.example.com'], ['challenge', 'abc123']], '')],
  24242: [
    tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW + 300)], ['server', 'relay.example.com']], 'Upload buzz-media'),
    tpl(24242, [['t', 'get'], ['expiration', String(NOW + 600)], ['server', 'localhost:3000']], 'Get buzz-media'),
  ],
  27235: [
    tpl(27235, [['u', 'https://relay.example.com/api/invites'], ['method', 'POST'], ['payload', SHA], ['nonce', UUID]], ''),
    tpl(27235, [['u', 'https://relay.example.com/moderation/reports?status=open&limit=100'], ['method', 'GET'], ['nonce', UUID]], ''),
  ],
  30300: [tpl(30300, [['d', D32], ['not_before', String(NOW + 600)]], NIP44_PAYLOAD)],
  40002: [
    tpl(40002, [['h', 'chan-general']], 'plain message'),
    tpl(
      40002,
      [
        ['h', 'chan-general'],
        ['imeta', 'url https://relay.example.com/media/abc', 'm image/png', `x ${SHA}`, 'size 1234', 'dim 100x100'],
        ['e', ID, '', 'reply'],
      ],
      'with attachment\n![image](https://relay.example.com/media/abc)',
    ),
  ],
  41010: [tpl(41010, [['p', PK2]], ''), tpl(41010, [['p', PK2], ['p', 'f'.repeat(64)]], '')],
};

describe('canonical Buzz fixtures are accepted', () => {
  for (const [kind, fixtures] of Object.entries(CANONICAL_FIXTURES)) {
    test(`kind ${kind}`, () => {
      for (const fixture of fixtures) ok(fixture);
    });
  }

  test('every supported kind has at least one canonical fixture (contract completeness)', () => {
    for (const kind of SUPPORTED_NOSTR_KINDS) {
      expect(CANONICAL_FIXTURES[kind]?.length ?? 0).toBeGreaterThan(0);
    }
    expect(new Set(Object.keys(CANONICAL_FIXTURES).map(Number))).toEqual(new Set(SUPPORTED_NOSTR_KINDS));
    expect(POLICY_KINDS).toEqual(new Set(SUPPORTED_NOSTR_KINDS));
  });
});

describe('kind 0 - profile metadata', () => {
  test('rejects non-JSON, arrays, unknown keys, non-string values, and tags', () => {
    bad(tpl(0, [], 'not-json'), 'profile_content_invalid');
    bad(tpl(0, [], '[]'), 'profile_content_invalid');
    bad(tpl(0, [], JSON.stringify({ lud16: 'x@y' })), 'profile_content_invalid');
    bad(tpl(0, [], JSON.stringify({ name: 42 })), 'profile_content_invalid');
    bad(tpl(0, [], JSON.stringify({ name: '' })), 'profile_content_invalid');
    bad(tpl(0, [], JSON.stringify({ name: 'x'.repeat(1025) })), 'profile_content_invalid');
    bad(tpl(0, [['p', PK]], '{}'), 'profile_tags_must_be_empty');
  });
});

describe('kind 7 - reaction', () => {
  test('rejects empty/oversized content, wrong tag order, bad ids, extra tags', () => {
    bad(tpl(7, [['e', ID], ['h', 'c']], ''), 'reaction_content_invalid');
    bad(tpl(7, [['e', ID], ['h', 'c']], 'x'.repeat(65)), 'reaction_content_invalid');
    bad(tpl(7, [['h', 'c'], ['e', ID]], '🔥'), 'reaction_tags_invalid');
    bad(tpl(7, [['e', 'nothex'], ['h', 'c']], '🔥'), 'reaction_tags_invalid');
    bad(tpl(7, [['e', ID.toUpperCase()], ['h', 'c']], '🔥'), 'reaction_tags_invalid');
    bad(tpl(7, [['e', ID], ['h', 'c'], ['p', PK]], '🔥'), 'reaction_tags_invalid');
    bad(tpl(7, [['e', ID, 'extra'], ['h', 'c']], '🔥'), 'reaction_tags_invalid');
    bad(tpl(7, [['e', ID]], '🔥'), 'reaction_tags_invalid');
  });
});

describe('kind 40002 - channel message v2', () => {
  test('rejects missing h, malformed imeta, misplaced/duplicate reply tags', () => {
    bad(tpl(40002, [], 'x'), 'channel_message_tags_invalid');
    bad(tpl(40002, [['e', ID, '', 'reply']], 'x'), 'channel_message_tags_invalid');
    bad(tpl(40002, [['h', 'c'], ['p', PK]], 'x'), 'channel_message_tags_invalid');
    // imeta missing required url/m/x/size quartet
    bad(tpl(40002, [['h', 'c'], ['imeta', 'url https://x.example/a']], 'x'), 'channel_message_tags_invalid');
    // imeta with a non-http url
    bad(tpl(40002, [['h', 'c'], ['imeta', 'url javascript:alert(1)', 'm image/png', `x ${SHA}`, 'size 1']], 'x'), 'channel_message_tags_invalid');
    // imeta with duplicate key
    bad(tpl(40002, [['h', 'c'], ['imeta', 'url https://x.example/a', 'url https://x.example/b', 'm image/png', `x ${SHA}`, 'size 1']], 'x'), 'channel_message_tags_invalid');
    // imeta with a bad hash
    bad(tpl(40002, [['h', 'c'], ['imeta', 'url https://x.example/a', 'm image/png', 'x nothex', 'size 1']], 'x'), 'channel_message_tags_invalid');
    // reply tag not last / duplicated / malformed marker
    bad(tpl(40002, [['h', 'c'], ['e', ID, '', 'reply'], ['imeta', 'url https://x.example/a', 'm image/png', `x ${SHA}`, 'size 1']], 'x'), 'channel_message_tags_invalid');
    bad(tpl(40002, [['h', 'c'], ['e', ID, '', 'reply'], ['e', ID, '', 'reply']], 'x'), 'channel_message_tags_invalid');
    bad(tpl(40002, [['h', 'c'], ['e', ID, '', 'root']], 'x'), 'channel_message_tags_invalid');
    bad(tpl(40002, [['h', 'c'], ['e', ID]], 'x'), 'channel_message_tags_invalid');
  });
});

describe('kind 1984 - report', () => {
  test('rejects unknown report types, bad ids, uppercase pubkeys, extra tags', () => {
    bad(tpl(1984, [['p', PK2], ['e', ID, 'rude']], ''), 'report_tags_invalid');
    bad(tpl(1984, [['p', PK2], ['e', ID]], ''), 'report_tags_invalid');
    bad(tpl(1984, [['p', PK2.toUpperCase()], ['e', ID, 'spam']], ''), 'report_tags_invalid');
    bad(tpl(1984, [['e', ID, 'spam'], ['p', PK2]], ''), 'report_tags_invalid');
    bad(tpl(1984, [['p', PK2], ['e', ID, 'spam'], ['p', PK]], ''), 'report_tags_invalid');
    bad(tpl(1984, [['p', PK2], ['e', ID, 'spam']], 'x'.repeat(2049)), 'report_content_invalid');
  });
});

describe('kind 22242 - relay auth (regression: original slice behavior)', () => {
  test('rejects non-empty content, duplicate/missing relay or challenge tags', () => {
    bad(tpl(22242, [['relay', 'wss://r.example'], ['challenge', 'a']], 'x'), 'auth_content_must_be_empty');
    bad(tpl(22242, [['relay', 'wss://r.example']], ''), 'auth_tags_invalid');
    bad(tpl(22242, [['relay', 'wss://r.example'], ['relay', 'wss://evil.example'], ['challenge', 'a']], ''), 'auth_tags_invalid');
    bad(tpl(22242, [['relay', 'wss://r.example'], ['challenge', 'a'], ['challenge', 'b']], ''), 'auth_tags_invalid');
    bad(tpl(22242, [['relay'], ['challenge', 'a']], ''), 'auth_tags_invalid');
  });
});

describe('kind 24242 - Blossom auth', () => {
  test('rejects hash on get, missing hash on upload, stale/far expirations, bad server authorities', () => {
    bad(tpl(24242, [['t', 'get'], ['x', SHA], ['expiration', String(NOW + 600)], ['server', 'x.example']], 'Get buzz-media'), 'blossom_tags_invalid');
    bad(tpl(24242, [['t', 'upload'], ['expiration', String(NOW + 300)], ['server', 'x.example']], 'Upload buzz-media'), 'blossom_tags_invalid');
    bad(tpl(24242, [['t', 'delete'], ['expiration', String(NOW + 300)], ['server', 'x.example']], 'x'), 'blossom_tags_invalid');
    bad(tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW - 10)], ['server', 'x.example']], 'x'), 'blossom_expiration_invalid');
    bad(tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW + 4000)], ['server', 'x.example']], 'x'), 'blossom_expiration_invalid');
    bad(tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW + 300)], ['server', 'https://x.example']], 'x'), 'blossom_tags_invalid');
    bad(tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW + 300)], ['server', 'X.EXAMPLE']], 'x'), 'blossom_tags_invalid');
    bad(tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW + 300)], ['server', 'x.example'], ['extra', 'v']], 'x'), 'blossom_tags_invalid');
    bad(tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW + 300)], ['server', 'x.example']], ''), 'blossom_content_invalid');
  });
});

describe('kind 27235 - NIP-98 HTTP auth', () => {
  test('binds payload presence to method and requires a UUID nonce', () => {
    bad(tpl(27235, [['u', 'https://r.example/api/invites'], ['method', 'POST'], ['nonce', UUID]], ''), 'http_auth_payload_required');
    bad(tpl(27235, [['u', 'https://r.example/moderation/restricted'], ['method', 'GET'], ['payload', SHA], ['nonce', UUID]], ''), 'http_auth_payload_forbidden');
    bad(tpl(27235, [['u', 'https://r.example/api/invites'], ['method', 'PUT'], ['payload', SHA], ['nonce', UUID]], ''), 'http_auth_tags_invalid');
    bad(tpl(27235, [['u', 'https://r.example/api/invites'], ['method', 'POST'], ['payload', 'nothex'], ['nonce', UUID]], ''), 'http_auth_tags_invalid');
    bad(tpl(27235, [['u', 'https://r.example/api/invites'], ['method', 'POST'], ['payload', SHA], ['nonce', 'not-a-uuid']], ''), 'http_auth_tags_invalid');
    bad(tpl(27235, [['u', 'https://r.example/api/invites'], ['method', 'POST'], ['payload', SHA], ['nonce', UUID]], 'x'), 'http_auth_content_must_be_empty');
    bad(tpl(27235, [['method', 'POST'], ['u', 'https://r.example/api/invites'], ['payload', SHA], ['nonce', UUID]], ''), 'http_auth_tags_invalid');
  });
});

describe('kind 20001 - presence', () => {
  test('rejects unknown statuses and content/tag mismatch', () => {
    bad(tpl(20001, [['status', 'busy']], 'busy'), 'presence_content_invalid');
    bad(tpl(20001, [['status', 'away']], 'online'), 'presence_tags_invalid');
    bad(tpl(20001, [['status', 'online'], ['status', 'online']], 'online'), 'presence_tags_invalid');
    bad(tpl(20001, [], 'online'), 'presence_tags_invalid');
  });
});

describe('kind 30300 - encrypted reminder', () => {
  test('rejects non-NIP-44 content, malformed d/not_before tags', () => {
    bad(tpl(30300, [['d', D32], ['not_before', '123']], 'plaintext reminder'), 'reminder_content_not_nip44');
    bad(tpl(30300, [['d', 'short'], ['not_before', '123']], NIP44_PAYLOAD), 'reminder_tags_invalid');
    bad(tpl(30300, [['d', D32], ['not_before', '0123']], NIP44_PAYLOAD), 'reminder_tags_invalid');
    bad(tpl(30300, [['d', D32], ['not_before', '-5']], NIP44_PAYLOAD), 'reminder_tags_invalid');
    bad(tpl(30300, [['d', D32], ['not_before', '9007199254740993']], NIP44_PAYLOAD), 'reminder_tags_invalid');
    bad(tpl(30300, [['d', D32]], NIP44_PAYLOAD), 'reminder_tags_invalid');
    bad(tpl(30300, [['d', D32], ['not_before', '1'], ['p', PK]], NIP44_PAYLOAD), 'reminder_tags_invalid');
  });
});

describe('kind 41010 - DM open', () => {
  test('rejects empty/oversized recipient lists, duplicates, bad pubkeys, content', () => {
    bad(tpl(41010, [], ''), 'dm_open_tags_invalid');
    bad(tpl(41010, Array.from({ length: 9 }, (_, i) => ['p', `${i}`.repeat(64).slice(0, 63) + 'a']), ''), 'dm_open_tags_invalid');
    bad(tpl(41010, [['p', PK2], ['p', PK2]], ''), 'dm_open_tags_invalid');
    bad(tpl(41010, [['p', PK2.toUpperCase()]], ''), 'dm_open_tags_invalid');
    bad(tpl(41010, [['p', PK2]], 'hello'), 'dm_open_content_must_be_empty');
  });
});

describe('kinds 9030-9032 - membership', () => {
  test('rejects unknown roles, missing tags, non-empty content', () => {
    bad(tpl(9030, [['p', PK2], ['role', 'god']], ''), 'membership_tags_invalid');
    bad(tpl(9030, [['p', PK2]], ''), 'membership_tags_invalid');
    bad(tpl(9031, [['p', PK2], ['role', 'member']], ''), 'membership_tags_invalid');
    bad(tpl(9032, [['role', 'admin'], ['p', PK2]], ''), 'membership_tags_invalid');
    bad(tpl(9030, [['p', PK2], ['role', 'member']], 'x'), 'membership_content_must_be_empty');
  });
});

describe('kinds 9040-9044 - moderation', () => {
  test('rejects out-of-order optionals, bad expirations, oversized reasons', () => {
    bad(tpl(9040, [['expiration', '123'], ['p', PK2]], ''), 'moderation_tags_invalid');
    bad(tpl(9040, [['p', PK2], ['reason', 'r'], ['expiration', '123']], ''), 'moderation_tags_invalid');
    bad(tpl(9040, [['p', PK2], ['expiration', '0']], ''), 'moderation_tags_invalid');
    bad(tpl(9040, [['p', PK2], ['expiration', '12.5']], ''), 'moderation_tags_invalid');
    bad(tpl(9040, [['p', PK2], ['reason', '']], ''), 'moderation_tags_invalid');
    bad(tpl(9040, [['p', PK2], ['reason', 'x'.repeat(513)]], ''), 'moderation_tags_invalid');
    bad(tpl(9040, [['p', PK2]], 'x'), 'moderation_content_must_be_empty');
    bad(tpl(9044, [['report', ID], ['status', 'open'], ['action', 'ban']], ''), 'moderation_tags_invalid');
    bad(tpl(9044, [['report', ID], ['status', 'resolved'], ['action', 'obliterate']], ''), 'moderation_tags_invalid');
    bad(tpl(9044, [['status', 'resolved'], ['report', ID], ['action', 'ban']], ''), 'moderation_tags_invalid');
    bad(tpl(9044, [['report', 'nothex'], ['status', 'resolved'], ['action', 'ban']], ''), 'moderation_tags_invalid');
  });
});

describe('unknown kinds fail closed', () => {
  test('kind 1 and kind 41011 have no validator', () => {
    bad(tpl(1, [], 'hello'), 'kind_not_supported');
    bad(tpl(41011, [['p', PK2]], ''), 'kind_not_supported');
  });
});

describe('per-kind content ceilings', () => {
  test('only kind 30300 gets the larger NIP-44 ciphertext ceiling', () => {
    expect(maxContentLengthForKind(30300)).toBe(8192);
    expect(maxContentLengthForKind(9)).toBe(4096);
    expect(maxContentLengthForKind(40002)).toBe(4096);
  });
});

describe('destination derivations (mirror of Buzz URL handling)', () => {
  test('relayHttpOrigin maps ws->http and strips path/query', () => {
    expect(relayHttpOrigin('ws://localhost:3000')).toBe('http://localhost:3000');
    expect(relayHttpOrigin('wss://relay.example.com/nested?x=1')).toBe('https://relay.example.com');
    expect(relayHttpOrigin('https://relay.example.com')).toBeNull();
    expect(relayHttpOrigin('not a url')).toBeNull();
  });

  test('relayInvitesHttpBase keeps the path, strips hash and trailing slash', () => {
    expect(relayInvitesHttpBase('wss://relay.example.com')).toBe('https://relay.example.com');
    expect(relayInvitesHttpBase('wss://relay.example.com/')).toBe('https://relay.example.com');
    expect(relayInvitesHttpBase('ws://localhost:3000/nested')).toBe('http://localhost:3000/nested');
    expect(relayInvitesHttpBase('wss://relay.example.com/nested#frag')).toBe('https://relay.example.com/nested');
  });

  test('relayServerAuthority lowercases and strips mapped default ports', () => {
    expect(relayServerAuthority('wss://Relay.Example.COM')).toBe('relay.example.com');
    expect(relayServerAuthority('wss://relay.example.com:443')).toBe('relay.example.com');
    expect(relayServerAuthority('ws://relay.example.com:80')).toBe('relay.example.com');
    expect(relayServerAuthority('ws://localhost:3000')).toBe('localhost:3000');
    expect(relayServerAuthority('wss://relay.example.com:8443')).toBe('relay.example.com:8443');
  });

  test('isAllowedNip98Url binds journeys to the granted relay', () => {
    const relay = 'wss://relay.example.com';
    expect(isAllowedNip98Url('https://relay.example.com/api/invites', 'POST', relay)).toBe(true);
    expect(isAllowedNip98Url('https://relay.example.com/api/invites/claim', 'POST', relay)).toBe(true);
    expect(isAllowedNip98Url('https://evil.example.com/api/invites', 'POST', relay)).toBe(false);
    expect(isAllowedNip98Url('https://relay.example.com/api/other', 'POST', relay)).toBe(false);
    expect(isAllowedNip98Url('https://relay.example.com/api/invites?x=1', 'POST', relay)).toBe(false);
    expect(isAllowedNip98Url('https://relay.example.com/moderation/reports?status=open&limit=100', 'GET', relay)).toBe(true);
    expect(isAllowedNip98Url('https://relay.example.com/moderation/audit?limit=50', 'GET', relay)).toBe(true);
    expect(isAllowedNip98Url('https://relay.example.com/moderation/restricted', 'GET', relay)).toBe(true);
    expect(isAllowedNip98Url('https://relay.example.com/moderation/reports?status=<script>', 'GET', relay)).toBe(false);
    expect(isAllowedNip98Url('https://relay.example.com/moderation/reports?other=1', 'GET', relay)).toBe(false);
    expect(isAllowedNip98Url('https://relay.example.com/admin', 'GET', relay)).toBe(false);
    expect(isAllowedNip98Url('http://relay.example.com/moderation/restricted', 'GET', relay)).toBe(false);
    expect(isAllowedNip98Url('https://user:pw@relay.example.com/moderation/restricted', 'GET', relay)).toBe(false);
    // Relay with a nested path: invites keep it, moderation reads stay at the origin.
    const nested = 'wss://relay.example.com/nested';
    expect(isAllowedNip98Url('https://relay.example.com/nested/api/invites', 'POST', nested)).toBe(true);
    expect(isAllowedNip98Url('https://relay.example.com/api/invites', 'POST', nested)).toBe(false);
    expect(isAllowedNip98Url('https://relay.example.com/moderation/restricted', 'GET', nested)).toBe(true);
  });
});

describe('eventDestinationMatchesGrant', () => {
  const relay = 'ws://localhost:3000';

  test('non-destination kinds always match; destination kinds require a grant relay', () => {
    expect(eventDestinationMatchesGrant(tpl(9, [], 'x'), null)).toBe(true);
    expect(eventDestinationMatchesGrant(tpl(22242, [['relay', relay], ['challenge', 'a']], ''), null)).toBe(false);
    expect(eventDestinationMatchesGrant(tpl(24242, [['t', 'get'], ['expiration', String(NOW + 60)], ['server', 'localhost:3000']], 'Get buzz-media'), null)).toBe(false);
    expect(eventDestinationMatchesGrant(tpl(27235, [['u', 'http://localhost:3000/moderation/restricted'], ['method', 'GET'], ['nonce', UUID]], ''), null)).toBe(false);
  });

  test('22242 requires an exact relay-tag match', () => {
    const auth = (r: string) => tpl(22242, [['relay', r], ['challenge', 'a']], '');
    expect(eventDestinationMatchesGrant(auth(relay), relay)).toBe(true);
    expect(eventDestinationMatchesGrant(auth('ws://localhost:3000/'), relay)).toBe(false);
    expect(eventDestinationMatchesGrant(auth('ws://evil.example.com'), relay)).toBe(false);
  });

  test('24242 binds the server tag to the granted relay authority', () => {
    const blossom = (server: string) =>
      tpl(24242, [['t', 'upload'], ['x', SHA], ['expiration', String(NOW + 300)], ['server', server]], 'Upload buzz-media');
    expect(eventDestinationMatchesGrant(blossom('localhost:3000'), relay)).toBe(true);
    expect(eventDestinationMatchesGrant(blossom('localhost:4000'), relay)).toBe(false);
    expect(eventDestinationMatchesGrant(blossom('evil.example.com'), relay)).toBe(false);
    expect(eventDestinationMatchesGrant(blossom('relay.example.com'), 'wss://relay.example.com:443')).toBe(true);
  });

  test('27235 binds the u URL to the granted relay and journey', () => {
    const http = (u: string, method: 'GET' | 'POST') =>
      tpl(27235, method === 'POST'
        ? [['u', u], ['method', method], ['payload', SHA], ['nonce', UUID]]
        : [['u', u], ['method', method], ['nonce', UUID]], '');
    expect(eventDestinationMatchesGrant(http('http://localhost:3000/api/invites', 'POST'), relay)).toBe(true);
    expect(eventDestinationMatchesGrant(http('http://localhost:3000/moderation/audit?limit=50', 'GET'), relay)).toBe(true);
    expect(eventDestinationMatchesGrant(http('http://evil.example.com/api/invites', 'POST'), relay)).toBe(false);
    expect(eventDestinationMatchesGrant(http('http://localhost:3000/anything', 'GET'), relay)).toBe(false);
  });
});
