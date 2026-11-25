// The TinyCloud account app is not a first-party origin for provisioning: it signs in as any other app does.
// Look-alikes and the other TinyCloud app origins that are not on the list are not first-party either.

import { describe, expect, test } from 'bun:test';
import { FIRST_PARTY_PROVISION_ORIGINS, mayProvision, originProvisionAuthority } from '../services/provision-authority';

describe('https://account.tinycloud.xyz', () => {
  test('is not first-party', () => {
    expect(FIRST_PARTY_PROVISION_ORIGINS).not.toContain('https://account.tinycloud.xyz');
    expect(mayProvision(originProvisionAuthority('https://account.tinycloud.xyz'))).toBe(false);
  });

  test('a look-alike origin is not first-party', () => {
    for (const origin of [
      'https://account.tinycloud.xyz.evil.test',
      'http://account.tinycloud.xyz',
      'https://account.tinycloud.xyz/',
      'https://account.tinycloud.xyz:443',
      'https://evil.account.tinycloud.xyz',
      'https://account.tinycloud.xyz@evil.test',
      'https://ACCOUNT.TINYCLOUD.XYZ',
    ]) {
      expect([origin, mayProvision(originProvisionAuthority(origin))]).toEqual([origin, false]);
    }
  });

  test('feed and explorer are not first-party', () => {
    for (const origin of ['https://feed.tinycloud.xyz', 'https://explorer.tinycloud.xyz']) {
      expect([origin, mayProvision(originProvisionAuthority(origin))]).toEqual([origin, false]);
    }
  });

  test('a TinyChat preview origin is not first-party', () => {
    expect(mayProvision(originProvisionAuthority('https://0a31bc70.tinychat.pages.dev'))).toBe(false);
  });
});
