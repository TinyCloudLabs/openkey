import { describe, expect, test } from 'bun:test';
import { buildOwnerRevocationSiwe, parseOwnerRevocationRequest, ownerRevocationResult } from '../src/owner-revocation';

const now = new Date('2026-10-26T12:00:00.000Z');
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const ownerDid = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const request = { kind: 'owner-revocation', ownerDid, cid, nonce: '0123456789abcdef0123456789abcdef', expiresAt: '2026-10-26T12:10:00.000Z' };

describe('owner revocation request', () => {
  test('accepts exact owner request and constructs the entire signed message', () => {
    const parsed = parseOwnerRevocationRequest(request, now);
    expect(parsed).toEqual(request);
    expect(buildOwnerRevocationSiwe(parsed, 'openkey.so', now)).toBe([
      'openkey.so wants you to sign in with your Ethereum account:',
      '0x1111111111111111111111111111111111111111', '', '',
      `URI: ucan:${cid}`, 'Version: 1', 'Chain ID: 1',
      'Nonce: 0123456789abcdef0123456789abcdef',
      'Issued At: 2026-10-26T12:00:00.000Z',
      'Expiration Time: 2026-10-26T12:10:00.000Z',
    ].join('\n'));
  });
  test.each([
    [{ ...request, kind: 'session' }, 'kind'],
    [{ ...request, siwe: 'caller supplied' }, 'field'],
    [{ ...request, cid: 'bafy-bad' }, 'cid'],
    [{ ...request, nonce: 'abcd' }, 'nonce'],
    [{ ...request, ownerDid: 'did:pkh:eip155:1:0x123' }, 'ownerDid'],
    [{ ...request, ownerDid: 'did:pkh:eip155:1:0xd559cCd9EB87c530A9a349262669386dE93cf412' }, 'ownerDid'],
    [{ ...request, expiresAt: '2026-10-26T11:59:59.000Z' }, 'expired'],
  ])('refuses invalid input %j', (input: Record<string, unknown>, reason: string) => {
    expect(() => parseOwnerRevocationRequest(input, now)).toThrow(reason);
  });
  test('caps later expiry at request time plus ten minutes', () => {
    expect(parseOwnerRevocationRequest({ ...request, expiresAt: '2026-10-26T13:00:00.000Z' }, now).expiresAt)
      .toBe('2026-10-26T12:10:00.000Z');
  });
  test('delivers the exact signed text with the signature', () => {
    const siwe = buildOwnerRevocationSiwe(parseOwnerRevocationRequest(request, now), 'openkey.so', now);
    expect(ownerRevocationResult(siwe, `0x${'ab'.repeat(65)}`)).toEqual({
      siwe, signature: `0x${'ab'.repeat(65)}`,
    });
  });
});
