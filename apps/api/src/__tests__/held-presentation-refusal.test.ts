import { describe, expect, test } from 'bun:test';
import { SiweMessage } from 'siwe';
import {
  grantsHeldPresent,
  heldPresentOriginRefusal,
  heldPresentSigningEnabled,
  NO_VERIFIED_ORIGIN_REASON,
  refusesHeldPresentation,
} from '../services/held-presentation-refusal';
import { privateKeyToAccount } from 'viem/accounts';

const ADDRESS = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;

function recap(att: Record<string, Record<string, unknown[]>>): string {
  return `urn:recap:${Buffer.from(JSON.stringify({ att })).toString('base64url')}`;
}

function siwe(resources: string[], statement = 'Sign in to OpenKey'): string {
  return new SiweMessage({
    domain: 'share.tinycloud.xyz',
    address: ADDRESS,
    statement,
    uri: 'https://share.tinycloud.xyz',
    version: '1',
    chainId: 1,
    nonce: 'abcdefgh12',
    issuedAt: '2025-01-01T00:00:00.000Z',
    resources,
  }).prepareMessage();
}

const presentRecap = recap({ [`${SPACE}/credentials/mail`]: { 'tinycloud.credentials/present': [{}] } });
const kvRecap = recap({ [`${SPACE}/kv/notes`]: { 'tinycloud.kv/get': [{}] } });

describe('refusesHeldPresentation', () => {
  test('refuses a SIWE carrying a ReCap that grants tinycloud.credentials/present', () => {
    expect(refusesHeldPresentation(siwe([presentRecap]))).toBe(true);
  });

  test('refuses the same grant hidden inside 0x hex (raw format)', () => {
    const hex = `0x${Buffer.from(siwe([presentRecap])).toString('hex')}`;
    expect(refusesHeldPresentation(hex)).toBe(true);
  });

  test('refuses a ReCap whose resource service segment is credentials, even with another ability', () => {
    const mixed = recap({ [`${SPACE}/credentials/mail`]: { 'tinycloud.kv/get': [{}] } });
    expect(refusesHeldPresentation(siwe([mixed]))).toBe(true);
  });

  test('refuses a SIWE whose ReCap does not decode (fail closed)', () => {
    expect(refusesHeldPresentation(siwe(['urn:recap:e30']))).toBe(true);
  });

  test('refuses a SIWE whose ReCap token has non-base64url characters (fail closed)', () => {
    expect(refusesHeldPresentation(siwe(['urn:recap:@@@']))).toBe(true);
  });

  test('refuses a SIWE whose ReCap token has an empty body (fail closed)', () => {
    expect(refusesHeldPresentation(siwe(['urn:recap:']))).toBe(true);
  });

  test('refuses the literal credentials/present in the statement', () => {
    expect(refusesHeldPresentation(siwe([], 'Allow credentials/present for mail'))).toBe(true);
  });

  test('allows an ordinary SIWE sign-in whose ReCap grants kv only', () => {
    expect(refusesHeldPresentation(siwe([kvRecap]))).toBe(false);
  });

  test('allows the holder-binding bytes (not SIWE-shaped)', () => {
    expect(refusesHeldPresentation('tinycloud.credentials/holder-binding/v1\nholder: 0xabc')).toBe(false);
  });

  test('allows the account-binding bytes (not SIWE-shaped)', () => {
    expect(refusesHeldPresentation('tinycloud.credentials/account-binding/v1\naccount: 0xabc')).toBe(false);
  });

  test('does not match a bare tinycloud.credentials/ prefix in arbitrary bytes', () => {
    expect(refusesHeldPresentation('tinycloud.credentials/present')).toBe(false);
  });
});

describe('heldPresentSigningEnabled', () => {
  test('is off unless the flag is exactly "true"', () => {
    expect(heldPresentSigningEnabled({})).toBe(false);
    expect(heldPresentSigningEnabled({ HELD_PRESENT_SIGNING_ENABLED: 'false' })).toBe(false);
    expect(heldPresentSigningEnabled({ HELD_PRESENT_SIGNING_ENABLED: 'true' })).toBe(true);
  });
});

const FIRST_PARTY = 'https://share.tinycloud.xyz';

function siweWith(fields: { domain?: string; scheme?: string; resources?: string[] }): string {
  return new SiweMessage({
    domain: fields.domain ?? 'share.tinycloud.xyz',
    scheme: fields.scheme,
    address: ADDRESS,
    statement: 'Sign in to OpenKey',
    uri: 'https://share.tinycloud.xyz',
    version: '1',
    chainId: 1,
    nonce: 'abcdefgh12',
    issuedAt: '2025-01-01T00:00:00.000Z',
    resources: fields.resources ?? [presentRecap],
  }).prepareMessage();
}

describe('grantsHeldPresent', () => {
  test('is true for a ReCap that grants tinycloud.credentials/present', () => {
    expect(grantsHeldPresent(siwe([presentRecap]))).toBe(true);
  });

  test('is false for a kv-only ReCap', () => {
    expect(grantsHeldPresent(siwe([kvRecap]))).toBe(false);
  });

  test('is false for holder-binding bytes', () => {
    expect(grantsHeldPresent('tinycloud.credentials/holder-binding/v1\nholder: 0xabc')).toBe(false);
  });
});

describe('heldPresentOriginRefusal', () => {
  test('allows a first-party origin whose SIWE scheme and domain match exactly', () => {
    expect(heldPresentOriginRefusal(siweWith({ scheme: 'https' }), FIRST_PARTY)).toBeNull();
  });

  test('allows a SIWE with no Scheme line, which means https', () => {
    expect(heldPresentOriginRefusal(siweWith({}), FIRST_PARTY)).toBeNull();
  });

  test('refuses a SIWE with no verified origin, with the no-origin reason', () => {
    expect(heldPresentOriginRefusal(siweWith({}), undefined)).toBe(NO_VERIFIED_ORIGIN_REASON);
  });

  test('refuses an origin that is not first-party', () => {
    expect(heldPresentOriginRefusal(siweWith({}), 'https://preview.share.tinycloud.xyz')).not.toBeNull();
  });

  test('refuses a host that only ends with a first-party host, even with a matching domain', () => {
    expect(heldPresentOriginRefusal(siweWith({ domain: 'evil-share.tinycloud.xyz' }), 'https://evil-share.tinycloud.xyz')).not.toBeNull();
  });

  test('refuses a non-https origin even when its host matches', () => {
    expect(heldPresentOriginRefusal(siweWith({ scheme: 'http' }), 'http://share.tinycloud.xyz')).not.toBeNull();
  });

  test('refuses a SIWE scheme that differs from the verified origin', () => {
    expect(heldPresentOriginRefusal(siweWith({ scheme: 'http' }), FIRST_PARTY)).not.toBeNull();
  });

  test('refuses a SIWE domain that differs from the verified origin host', () => {
    expect(heldPresentOriginRefusal(siweWith({ domain: 'other.tinycloud.xyz' }), FIRST_PARTY)).not.toBeNull();
  });

  test('refuses a SIWE domain carrying an explicit default port', () => {
    expect(heldPresentOriginRefusal(siweWith({ domain: 'share.tinycloud.xyz:443' }), FIRST_PARTY)).not.toBeNull();
  });

  test('refuses SIWE text that cannot be parsed', () => {
    expect(heldPresentOriginRefusal('not a siwe message', FIRST_PARTY)).not.toBeNull();
  });
});

describe('CLI handoff requester', () => {
  // temporary: the CLI/agent requester is designed in a follow-up; remove or change this test deliberately then.
  test('temporary: a held presentation with no verified origin is refused', () => {
    expect(heldPresentOriginRefusal(siweWith({}), undefined)).toBe(NO_VERIFIED_ORIGIN_REASON);
  });
});
