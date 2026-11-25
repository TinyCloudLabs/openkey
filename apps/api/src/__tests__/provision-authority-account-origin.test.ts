// The TinyCloud account app is a first-party origin for provisioning. Only the exact origin counts.

import { describe, expect, test } from 'bun:test';
import { mayProvision, originProvisionAuthority } from '../services/provision-authority';

describe('https://account.tinycloud.xyz', () => {
  test('is first-party', () => {
    expect(mayProvision(originProvisionAuthority('https://account.tinycloud.xyz'))).toBe(true);
  });

  test('a similar origin is not', () => {
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

  test('feed and explorer are not added with it', () => {
    for (const origin of ['https://feed.tinycloud.xyz', 'https://explorer.tinycloud.xyz']) {
      expect([origin, mayProvision(originProvisionAuthority(origin))]).toEqual([origin, false]);
    }
  });
});
