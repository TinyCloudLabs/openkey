// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  TINYCLOUD_ONE_REQUESTER_DIDS,
  VERIFIED_REQUESTERS,
  isEd25519DidKey,
  isVerifiedRequesterEntry,
  verifiedApprovalRequester,
  withConfiguredEntries,
} from './delegate-link-policy';

const ONE = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const APP = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const OTHER = 'did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU';
const entry = { did: APP, displayName: 'Example App', returnTo: 'Example App' };

describe('verifiedApprovalRequester', () => {
  test('a valid listed app key names its signer and return destination', () => {
    expect(isVerifiedRequesterEntry(entry)).toBe(true);
    expect(verifiedApprovalRequester(APP, [], [entry])).toEqual({ displayName: 'Example App', returnTo: 'Example App' });
  });

  test('only the exact listed DID receives the app name', () => {
    for (const issuer of [OTHER, '', APP.toUpperCase(), `${APP} `, APP.slice(0, -1)]) {
      expect(verifiedApprovalRequester(issuer, [], [entry])).toBeNull();
    }
  });

  test('TinyCloud One keys take precedence over a matching app entry', () => {
    const configured = withConfiguredEntries(TINYCLOUD_ONE_REQUESTER_DIDS, ` ${ONE} `, isEd25519DidKey);
    expect(verifiedApprovalRequester(ONE, configured, [{ ...entry, did: ONE }])).toEqual({
      displayName: 'TinyCloud One', returnTo: 'TinyCloud One',
    });
  });

  test('invalid keys and unsafe or reserved names cannot enter the list', () => {
    for (const invalid of [
      { ...entry, did: 'did:web:example.test' },
      { ...entry, displayName: 'TinyCloud One' },
      { ...entry, displayName: 'TinyCloud CLI' },
      { ...entry, displayName: '' },
      { ...entry, displayName: 'x'.repeat(49) },
      { ...entry, displayName: 'Example\nApp' },
      { ...entry, returnTo: '' },
      { ...entry, returnTo: 'TinyCloud One' },
    ]) {
      expect(isVerifiedRequesterEntry(invalid)).toBe(false);
      expect(verifiedApprovalRequester(invalid.did, [], [invalid])).toBeNull();
    }
  });

  test('the empty built-in list names no signer', () => {
    expect(VERIFIED_REQUESTERS).toEqual([]);
    expect(verifiedApprovalRequester(APP, TINYCLOUD_ONE_REQUESTER_DIDS, VERIFIED_REQUESTERS)).toBeNull();
  });
});
