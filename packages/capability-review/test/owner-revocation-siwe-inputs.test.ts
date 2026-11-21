import { describe, expect, test } from 'bun:test';
import { buildOwnerRevocationSiwe, type OwnerRevocationRequest } from '../src/owner-revocation';

// The owner's key signs exactly what buildOwnerRevocationSiwe returns. Some callers pass stored rows rather than a
// parsed request, so the builder itself refuses any field that could add a line (another SIWE field) to that text.
const now = new Date('2026-10-26T12:00:00.000Z');
const request: OwnerRevocationRequest = {
  kind: 'owner-revocation',
  ownerDid: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
  cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe',
  nonce: '0123456789abcdef0123456789abcdef',
  expiresAt: '2026-10-26T12:10:00.000Z',
};

describe('buildOwnerRevocationSiwe refuses input that would change the signed text', () => {
  test.each([
    ['cid', { ...request, cid: `${request.cid}\nResources:\n- urn:recap:x` }, 'openkey.so'],
    ['cid', { ...request, cid: 'bafy-bad' }, 'openkey.so'],
    ['nonce', { ...request, nonce: `${request.nonce}\nURI: ucan:bafyother` }, 'openkey.so'],
    ['nonce', { ...request, nonce: 'abc' }, 'openkey.so'],
    ['ownerDid', { ...request, ownerDid: `${request.ownerDid}\nChain ID: 5` }, 'openkey.so'],
    ['domain', request, 'openkey.so\nURI: ucan:bafyother'],
    ['domain', request, 'openkey.so wants'],
    ['domain', request, 'openkey.so/path'],
  ])('refuses a bad %s', (reason, input, domain) => {
    expect(() => buildOwnerRevocationSiwe(input as OwnerRevocationRequest, domain, now)).toThrow(`Invalid ${reason}`);
  });

  test('still builds the ten-line message from what the callers pass: a hex nonce, a host with a port', () => {
    const siwe = buildOwnerRevocationSiwe(request, 'localhost:5173', now);
    expect(siwe.split('\n')).toEqual([
      'localhost:5173 wants you to sign in with your Ethereum account:',
      '0x1111111111111111111111111111111111111111', '', '',
      `URI: ucan:${request.cid}`, 'Version: 1', 'Chain ID: 1',
      `Nonce: ${request.nonce}`,
      'Issued At: 2026-10-26T12:00:00.000Z',
      'Expiration Time: 2026-10-26T12:10:00.000Z',
    ]);
  });
});
