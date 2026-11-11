import { expect, test } from 'bun:test';
import {
  NEVER_SENT_TO_BROKER_FIELDS,
  PUBLIC_DELEGATION_FIELDS,
  PUBLIC_JWK_FIELDS,
  publicDelegationForCode,
} from './index';

test('short-code fields classify completion extras and filter own public JWK fields', () => {
  expect(NEVER_SENT_TO_BROKER_FIELDS).toEqual(['requestedSpaces']);
  const payload = Object.assign(Object.create(null), {
    delegationCid: 'cid', requestedSpaces: ['private-space'],
jwk: { kty: 'OKP', crv: 'Ed25519', x: 'public', kid: 'kid', d: 'private' },
  });
  expect(Object.keys(publicDelegationForCode(payload)).sort()).toEqual(['delegationCid', 'jwk']);
  expect(publicDelegationForCode(payload).jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: 'public', kid: 'kid' });
  expect(PUBLIC_DELEGATION_FIELDS).toContain('jwk');
  expect(PUBLIC_JWK_FIELDS).toEqual(['kty', 'crv', 'x', 'kid']);
});
