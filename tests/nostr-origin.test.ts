import { describe, expect, test } from 'bun:test';
import {
  deriveRelayUrlForGrant,
  extractRelayTag,
  parseCanonicalOrigin,
  parseNostrRelayUrl,
} from '../apps/web/src/lib/nostr-origin';

describe('Nostr widget origin validation (parseCanonicalOrigin)', () => {
  test('accepts exact http(s) origins with no path/query/credentials/fragment', () => {
    expect(parseCanonicalOrigin('https://example.com')).toBe('https://example.com');
    expect(parseCanonicalOrigin('http://localhost:3000')).toBe('http://localhost:3000');
    expect(parseCanonicalOrigin('https://example.com/')).toBe('https://example.com');
  });

  test('never returns a wildcard and fails closed on malformed input', () => {
    expect(parseCanonicalOrigin('*')).toBeNull();
    expect(parseCanonicalOrigin(null)).toBeNull();
    expect(parseCanonicalOrigin(undefined)).toBeNull();
    expect(parseCanonicalOrigin('')).toBeNull();
    expect(parseCanonicalOrigin('not a url')).toBeNull();
  });

  test('rejects paths, query strings, and fragments (would break exact-match comparisons)', () => {
    expect(parseCanonicalOrigin('https://example.com/path')).toBeNull();
    expect(parseCanonicalOrigin('https://example.com?x=1')).toBeNull();
    expect(parseCanonicalOrigin('https://example.com#frag')).toBeNull();
  });

  test('rejects embedded credentials and non-http(s) schemes', () => {
    expect(parseCanonicalOrigin('https://user:pass@example.com')).toBeNull();
    expect(parseCanonicalOrigin('javascript:alert(1)')).toBeNull();
    expect(parseCanonicalOrigin('ftp://example.com')).toBeNull();
    expect(parseCanonicalOrigin('ws://example.com')).toBeNull();
  });

  test('rejects an oversized origin string', () => {
    expect(parseCanonicalOrigin(`https://${'a'.repeat(300)}.com`)).toBeNull();
  });
});

describe('Nostr relay URL validation (parseNostrRelayUrl)', () => {
  test('accepts ws(s) URLs and preserves the original string exactly (no trailing-slash normalization)', () => {
    expect(parseNostrRelayUrl('ws://localhost:8080')).toBe('ws://localhost:8080');
    expect(parseNostrRelayUrl('wss://relay.example.com')).toBe('wss://relay.example.com');
  });

  test('rejects non-ws(s) schemes and malformed input', () => {
    expect(parseNostrRelayUrl('https://relay.example.com')).toBeNull();
    expect(parseNostrRelayUrl('*')).toBeNull();
    expect(parseNostrRelayUrl(undefined)).toBeNull();
    expect(parseNostrRelayUrl(123)).toBeNull();
    expect(parseNostrRelayUrl('not a url')).toBeNull();
  });
});

describe('extractRelayTag', () => {
  test('reads the single relay tag value from a kind:22242 event', () => {
    expect(extractRelayTag({ tags: [['relay', 'ws://x'], ['challenge', 'abc']] })).toBe('ws://x');
  });

  test('returns null when no relay tag is present', () => {
    expect(extractRelayTag({ tags: [] })).toBeNull();
    expect(extractRelayTag({ tags: [['challenge', 'abc']] })).toBeNull();
  });
});

describe('deriveRelayUrlForGrant (destination-bound consent binding)', () => {
  const UUID = '01234567-89ab-cdef-0123-456789abcdef';
  const SHA = 'd'.repeat(64);

  test('22242 always uses the relay tag and ignores any hint', () => {
    const event = { kind: 22242, tags: [['relay', 'ws://localhost:8080'], ['challenge', 'a']] };
    expect(deriveRelayUrlForGrant(event)).toBe('ws://localhost:8080');
    expect(deriveRelayUrlForGrant(event, 'wss://evil.example.com')).toBe('ws://localhost:8080');
    expect(deriveRelayUrlForGrant({ kind: 22242, tags: [['challenge', 'a']] })).toBeNull();
    expect(deriveRelayUrlForGrant({ kind: 22242, tags: [['relay', 'https://not-ws.example']] })).toBeNull();
  });

  test('a valid ws(s) hint wins for 24242 and 27235', () => {
    const blossom = { kind: 24242, tags: [['t', 'get'], ['expiration', '1'], ['server', 'localhost:3000']] };
    expect(deriveRelayUrlForGrant(blossom, 'ws://localhost:3000')).toBe('ws://localhost:3000');
    expect(deriveRelayUrlForGrant(blossom, 'not a url')).toBeNull();
    // 24242 has no scheme information of its own: no hint means fail closed.
    expect(deriveRelayUrlForGrant(blossom)).toBeNull();
  });

  test('27235 derives the relay from the u URL when no hint is given', () => {
    const get = {
      kind: 27235,
      tags: [['u', 'https://relay.example.com/moderation/restricted'], ['method', 'GET'], ['nonce', UUID]],
    };
    expect(deriveRelayUrlForGrant(get)).toBe('wss://relay.example.com');

    const post = {
      kind: 27235,
      tags: [['u', 'http://localhost:3000/api/invites'], ['method', 'POST'], ['payload', SHA], ['nonce', UUID]],
    };
    expect(deriveRelayUrlForGrant(post)).toBe('ws://localhost:3000');

    const postNested = {
      kind: 27235,
      tags: [['u', 'https://relay.example.com/nested/api/invites/claim'], ['method', 'POST'], ['payload', SHA], ['nonce', UUID]],
    };
    expect(deriveRelayUrlForGrant(postNested)).toBe('wss://relay.example.com/nested');

    const postWrongPath = {
      kind: 27235,
      tags: [['u', 'https://relay.example.com/api/other'], ['method', 'POST'], ['payload', SHA], ['nonce', UUID]],
    };
    expect(deriveRelayUrlForGrant(postWrongPath)).toBeNull();

    expect(deriveRelayUrlForGrant({ kind: 27235, tags: [['method', 'GET'], ['nonce', UUID]] })).toBeNull();
    expect(deriveRelayUrlForGrant({
      kind: 27235,
      tags: [['u', 'ftp://relay.example.com/x'], ['method', 'GET'], ['nonce', UUID]],
    })).toBeNull();
  });

  test('non-destination kinds derive nothing', () => {
    expect(deriveRelayUrlForGrant({ kind: 9, tags: [] })).toBeNull();
  });
});
