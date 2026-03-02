import { describe, it, expect } from 'bun:test';
import {
  base64UrlEncode,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
} from '@openkey/core';
import type { SHA256Fn } from '@openkey/core';

const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

describe('base64UrlEncode', () => {
  it('correctly encodes known byte sequences', () => {
    // Empty buffer
    expect(base64UrlEncode(new Uint8Array([]))).toBe('');

    // Single byte 0x00 → "AA" (base64url, no padding)
    expect(base64UrlEncode(new Uint8Array([0]))).toBe('AA');

    // [0xff, 0xff, 0xff] → "////" in base64, "____" in base64url
    expect(base64UrlEncode(new Uint8Array([0xff, 0xff, 0xff]))).toBe('____');

    // [0xfb, 0xef, 0xbe] → "++++", which becomes "----" in base64url
    expect(base64UrlEncode(new Uint8Array([0xfb, 0xef, 0xbe]))).toBe('----');

    // "Hello" → SGVsbG8 in base64url (no padding)
    const hello = new TextEncoder().encode('Hello');
    expect(base64UrlEncode(hello)).toBe('SGVsbG8');
  });

  it('never includes padding characters', () => {
    // 1 byte → 2 base64 chars (no padding)
    const one = base64UrlEncode(new Uint8Array([0x42]));
    expect(one).not.toContain('=');

    // 2 bytes → 3 base64 chars (no padding)
    const two = base64UrlEncode(new Uint8Array([0x42, 0x43]));
    expect(two).not.toContain('=');

    // 3 bytes → 4 base64 chars (no padding)
    const three = base64UrlEncode(new Uint8Array([0x42, 0x43, 0x44]));
    expect(three).not.toContain('=');
  });

  it('uses only base64url alphabet characters', () => {
    // Encode a wide range of byte values
    const allBytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      allBytes[i] = i;
    }
    const encoded = base64UrlEncode(allBytes);
    expect(encoded).toMatch(BASE64URL_REGEX);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
  });
});

describe('generateCodeVerifier', () => {
  it('returns a 43-character string', () => {
    const verifier = generateCodeVerifier();
    expect(verifier.length).toBe(43);
  });

  it('uses only base64url alphabet characters', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).toMatch(BASE64URL_REGEX);
  });

  it('contains no padding characters', () => {
    const verifier = generateCodeVerifier();
    expect(verifier).not.toContain('=');
  });

  it('produces unique values on successive calls', () => {
    const verifiers = new Set<string>();
    for (let i = 0; i < 100; i++) {
      verifiers.add(generateCodeVerifier());
    }
    // All 100 should be unique (collision probability is astronomically low)
    expect(verifiers.size).toBe(100);
  });
});

describe('generateCodeChallenge', () => {
  it('returns a valid base64url string', async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    expect(challenge).toMatch(BASE64URL_REGEX);
    expect(challenge).not.toContain('=');
  });

  it('is deterministic for the same verifier', async () => {
    const verifier = 'test-verifier-deterministic';
    const challenge1 = await generateCodeChallenge(verifier);
    const challenge2 = await generateCodeChallenge(verifier);
    expect(challenge1).toBe(challenge2);
  });

  it('produces a 43-character string (SHA-256 = 32 bytes)', async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    // 32 bytes → ceil(32 * 4/3) = 43 base64url chars (no padding)
    expect(challenge.length).toBe(43);
  });

  it('uses custom SHA256Fn when provided', async () => {
    const verifier = 'test-verifier';

    // Custom SHA256 that returns all zeros (deterministic, easy to verify)
    const customSha256: SHA256Fn = async (_input: string) => {
      return new Uint8Array(32); // 32 zero bytes
    };

    const challenge = await generateCodeChallenge(verifier, customSha256);
    // 32 zero bytes base64url encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    const expectedZeros = base64UrlEncode(new Uint8Array(32));
    expect(challenge).toBe(expectedZeros);
  });

  it('custom SHA256Fn overrides default implementation', async () => {
    const verifier = 'test-verifier';

    // Get the default challenge
    const defaultChallenge = await generateCodeChallenge(verifier);

    // Custom SHA256 that returns a fixed non-zero value
    const customSha256: SHA256Fn = async (_input: string) => {
      const result = new Uint8Array(32);
      result.fill(0xab);
      return result;
    };

    const customChallenge = await generateCodeChallenge(verifier, customSha256);
    expect(customChallenge).not.toBe(defaultChallenge);
  });
});

describe('generateState', () => {
  it('returns a 22-character string', () => {
    const state = generateState();
    expect(state.length).toBe(22);
  });

  it('uses only base64url alphabet characters', () => {
    const state = generateState();
    expect(state).toMatch(BASE64URL_REGEX);
  });

  it('contains no padding characters', () => {
    const state = generateState();
    expect(state).not.toContain('=');
  });

  it('produces unique values on successive calls', () => {
    const states = new Set<string>();
    for (let i = 0; i < 100; i++) {
      states.add(generateState());
    }
    expect(states.size).toBe(100);
  });
});
