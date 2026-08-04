import { describe, expect, test } from 'bun:test';
import { extractRelayTag, parseCanonicalOrigin, parseNostrRelayUrl } from '../apps/web/src/lib/nostr-origin';

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
