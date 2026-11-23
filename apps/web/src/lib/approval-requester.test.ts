// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  TINYCLOUD_ONE_REQUESTER_DIDS,
  approvalRequester,
  isEd25519DidKey,
  withConfiguredEntries,
} from './delegate-link-policy';

const ONE = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const OTHER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

describe('approvalRequester', () => {
  test('a request signed by a listed TinyCloud One key is from TinyCloud One, and returns there', () => {
    const listed = withConfiguredEntries(TINYCLOUD_ONE_REQUESTER_DIDS, ` ${ONE} `, isEd25519DidKey);
    expect(approvalRequester(ONE, listed)).toEqual({ displayName: 'TinyCloud One', returnTo: 'TinyCloud One' });
  });

  test('any other signer is not verified: no requester is named', () => {
    const listed = withConfiguredEntries(TINYCLOUD_ONE_REQUESTER_DIDS, ONE, isEd25519DidKey);
    for (const issuer of [OTHER, '', ONE.toLowerCase(), `${ONE} `, ONE.slice(0, -1)]) {
      expect(approvalRequester(issuer, listed)).toBeNull();
    }
  });

  test('the built-in list names no one until TinyCloud One has a key', () => {
    expect(approvalRequester(ONE, TINYCLOUD_ONE_REQUESTER_DIDS)).toBeNull();
  });

  test('a configured entry that is not an Ed25519 did:key is ignored', () => {
    const entries = [
      '',
      'did:key:',
      'did:web:tinycloud.one',
      'did:pkh:eip155:1:0xd559ccd9eb87c530a9a349262669386de93cf412',
      'did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme',
      `${ONE}0`,
      ONE.replace('z6Mk', 'z6MK'),
    ];
    expect(withConfiguredEntries([], entries.join(','), isEd25519DidKey)).toEqual([]);
    expect(withConfiguredEntries([], `${entries.join(',')},${ONE}`, isEd25519DidKey)).toEqual([ONE]);
  });
});
