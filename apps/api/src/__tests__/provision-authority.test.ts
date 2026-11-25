import { describe, expect, test } from 'bun:test';
import { REGISTRY_RECORD_SIGN_ORIGINS } from '@openkey/capability-review';
import {
  FIRST_PARTY_PROVISION_NATIVE_CLIENTS,
  FIRST_PARTY_PROVISION_ORIGINS,
  sweepProvisionAuthority,
  UNATTRIBUTED_PROVISION_AUTHORITY,
  mayProvision,
  nativeClientProvisionAuthority,
  oauthClientProvisionAuthority,
  originProvisionAuthority,
  type ProvisionAuthority,
} from '../services/provision-authority';

const nativeClient = { clientId: 'ok_e1d13d0b220379f37a553aa0391d28a4', redirectUri: 'xyz.tinycloud.exo://openkey/callback' };

describe('who may have OpenKey set up an account on the node', () => {
  test('every first-party origin may, including TinyChat web', () => {
    expect(FIRST_PARTY_PROVISION_ORIGINS).toContain('https://tinycloud.chat');
    for (const origin of FIRST_PARTY_PROVISION_ORIGINS) {
      expect(mayProvision(originProvisionAuthority(origin))).toBe(true);
    }
    for (const origin of REGISTRY_RECORD_SIGN_ORIGINS) {
      expect(mayProvision(originProvisionAuthority(origin))).toBe(true);
    }
  });

  test('app.tinycloud.one is not first-party', () => {
    expect(mayProvision(originProvisionAuthority('https://app.tinycloud.one'))).toBe(false);
  });

  test('a third-party origin may not', () => {
    for (const origin of ['https://example.com', 'https://coordination.example', 'http://localhost:3000']) {
      expect(mayProvision(originProvisionAuthority(origin))).toBe(false);
    }
  });

  test('a first-party origin spelled differently may not', () => {
    for (const base of FIRST_PARTY_PROVISION_ORIGINS) {
      const host = new URL(base).host;
      for (const spelled of [
        `${base}/`,
        `${base}:443`,
        base.toUpperCase(),
        `${base}.evil.example`,
        `https://${host}.evil.example`,
        `https://evil.${host}`,
        `https://${host}@evil.example`,
        `https://evil.example#${host}`,
        ` ${base}`,
        `${base}\n`,
        '',
      ]) {
        expect(mayProvision(originProvisionAuthority(spelled))).toBe(false);
      }
    }
  });

  test('a missing or malformed origin may not', () => {
    expect(mayProvision(originProvisionAuthority(undefined))).toBe(false);
    expect(mayProvision(originProvisionAuthority(null))).toBe(false);
    expect(mayProvision(originProvisionAuthority(42 as never))).toBe(false);
    expect(mayProvision(originProvisionAuthority({ toString: () => FIRST_PARTY_PROVISION_ORIGINS[0] } as never))).toBe(false);
    expect(mayProvision(originProvisionAuthority([FIRST_PARTY_PROVISION_ORIGINS[0]] as never))).toBe(false);
  });

  test('an unattributed request may not, and an authority of an unknown kind may not', () => {
    expect(mayProvision(UNATTRIBUTED_PROVISION_AUTHORITY)).toBe(false);
    expect(mayProvision({ kind: 'anything-else' } as never)).toBe(false);
  });

  test('an OAuth client may not unless it is listed, and none is listed by default', () => {
    expect(mayProvision(oauthClientProvisionAuthority('coordinationos'))).toBe(false);
    expect(mayProvision(oauthClientProvisionAuthority(undefined))).toBe(false);
    expect(mayProvision(oauthClientProvisionAuthority(nativeClient.clientId))).toBe(false);
  });

  test('a native client may only with its exact client id and its exact redirect URI together', () => {
    expect(FIRST_PARTY_PROVISION_NATIVE_CLIENTS).toEqual([nativeClient]);
    expect(mayProvision(nativeClientProvisionAuthority(nativeClient.clientId, nativeClient.redirectUri))).toBe(true);
    // Right client id, different redirect.
    expect(mayProvision(nativeClientProvisionAuthority(nativeClient.clientId, 'xyz.tinycloud.test://openkey/callback'))).toBe(false);
    expect(mayProvision(nativeClientProvisionAuthority(nativeClient.clientId, `${nativeClient.redirectUri}/`))).toBe(false);
    expect(mayProvision(nativeClientProvisionAuthority(nativeClient.clientId, `${nativeClient.redirectUri}?x=1`))).toBe(false);
    expect(mayProvision(nativeClientProvisionAuthority(nativeClient.clientId, undefined))).toBe(false);
    // Right redirect, different client id.
    expect(mayProvision(nativeClientProvisionAuthority('ok_other', nativeClient.redirectUri))).toBe(false);
    expect(mayProvision(nativeClientProvisionAuthority(`${nativeClient.clientId}x`, nativeClient.redirectUri))).toBe(false);
    expect(mayProvision(nativeClientProvisionAuthority(undefined, nativeClient.redirectUri))).toBe(false);
  });

  test('the background retry is allowed only while it holds its claim on a row', () => {
    const claim = { observed: { status: 'failed' as const, sweepAttempts: 0, checkedAt: new Date(), attemptId: null }, onClaimed: () => {} };
    expect(mayProvision(sweepProvisionAuthority(claim))).toBe(true);
    // A sweep authority with no claim, or one that is not a claim, is refused.
    expect(mayProvision({ kind: 'sweep' } as ProvisionAuthority)).toBe(false);
    expect(mayProvision({ kind: 'sweep', claim: undefined } as unknown as ProvisionAuthority)).toBe(false);
    expect(mayProvision({ kind: 'sweep', claim: {} } as unknown as ProvisionAuthority)).toBe(false);
  });
});
