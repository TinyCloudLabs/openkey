import { describe, expect, test } from 'bun:test';
import { base64UrlDecode, sessionDidForPublicKey, type NativeFetch, type NativeFetchResponse } from '@openkey/core';
import { OpenKeyCapacitor, OpenKeyNative, OpenKeyNativeError, type OpenKeyCapacitorPlugin } from '../src/index';

const issuer = 'https://api.openkey.so/api/auth';
const host = 'https://tee.node.tinycloud.xyz';
const redirectUri = 'xyz.tinycloud.exo://openkey/callback';
const capabilities = [{ service: 'tinycloud.kv', space: 'applications', path: 'app/threads/', actions: ['tinycloud.kv/get'] }];

function response(status: number, data: unknown, retryAfter?: string): NativeFetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => data,
    headers: { get: () => retryAfter ?? null } };
}

class MockPlugin implements OpenKeyCapacitorPlugin {
  values = new Map<string, string>();
  callback: (url: string) => Promise<string> = async () => '';
  async openAuthSession({ url }: { url: string }): Promise<{ url: string }> { return { url: await this.callback(url) }; }
  async secureStoreGet({ key }: { key: string }): Promise<{ value: string | null }> { return { value: this.values.get(key) ?? null }; }
  async secureStoreSet({ key, value }: { key: string; value: string }): Promise<void> { this.values.set(key, value); }
  async secureStoreRemove({ key }: { key: string }): Promise<void> { this.values.delete(key); }
}

function fixture() {
  const plugin = new MockPlugin();
  let state = '';
  let keyId = '';
  let renewCalls = 0;
  let revokeCalls = 0;
  let renewReply: (call: number) => NativeFetchResponse = () => response(200, renewal('next'));
  let revokeReply: () => NativeFetchResponse = () => response(200, {});
  const delegation = () => ({
    verificationMethod: keyId, expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    issuedAt: new Date().toISOString(), permissions: [
      { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }, ...capabilities,
    ], tinycloudHost: host, address: '0x0000000000000000000000000000000000000001', chainId: 1,
    spaceId: 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:applications',
    siwe: 'signed siwe', signature: '0xsignature', delegationHeader: { Authorization: 'Bearer fake' }, delegationCid: 'bafyfake',
  });
  const renewal = (refreshToken: string) => ({ refresh_token: refreshToken, tinycloud_delegation: delegation() });
  const fetchFn: NativeFetch = async (url, init) => {
    if (url.includes('.well-known')) return response(200, {
      issuer, authorization_endpoint: `${issuer}/oauth2/authorize`, token_endpoint: `${issuer}/oauth2/token`,
      pushed_authorization_request_endpoint: `${issuer}/oauth2/par`,
      tinycloud_delegation_renew_endpoint: `${issuer}/oauth2/tinycloud/renew`,
      tinycloud_delegation_revocation_endpoint: `${issuer}/oauth2/tinycloud/revoke`,
    });
    if (url.endsWith('/par')) {
      const form = new URLSearchParams(init?.body);
      state = form.get('state')!;
      const detail = JSON.parse(form.get('authorization_details')!)[0];
      const did = sessionDidForPublicKey(base64UrlDecode(detail.session_key.x));
      keyId = `${did}#${did.slice('did:key:'.length)}`;
      return response(201, { request_uri: 'urn:request:1', expires_in: 90 });
    }
    if (url.endsWith('/token')) return response(200, { access_token: 'access', refresh_token: 'initial', tinycloud_delegation: delegation() });
    if (url.endsWith('/renew')) return renewReply(++renewCalls);
    if (url.endsWith('/revoke')) { revokeCalls++; return revokeReply(); }
    throw new Error('unexpected request');
  };
  plugin.callback = async () => `${redirectUri}?code=code&state=${state}&iss=${encodeURIComponent(issuer)}`;
  const make = (verifyDelegation: (delegation: ReturnType<typeof delegation>) => Promise<void> = async () => {}) =>
    new OpenKeyNative({ clientId: 'exo', redirectUri, plugin, fetchFn, verifyDelegation, sleepFn: async () => {} });
  return { plugin, make, delegation, renewal, get state() { return state; }, get renewCalls() { return renewCalls; }, get revokeCalls() { return revokeCalls; },
    setRenewReply: (fn: typeof renewReply) => { renewReply = fn; }, setRevokeReply: (fn: typeof revokeReply) => { revokeReply = fn; } };
}

describe('OpenKeyNative', () => {
  test('web fallback reports UNAVAILABLE', async () => {
    await expect(OpenKeyCapacitor.openAuthSession({ url: `${issuer}/oauth2/authorize`, callbackScheme: 'xyz.tinycloud.exo' }))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
  });
  test('signs in, verifies before storing, and restores offline', async () => {
    const f = fixture();
    const client = f.make();
    const session = await client.signIn({ capabilities });
    expect(session.tokens.refreshToken).toBe('initial');
    expect(session.sessionKey.privateJwk.d).toBeTruthy();
    expect((await f.make().current())?.delegation.delegationCid).toBe('bafyfake');
    expect((await client.getSessionKey())?.did).toBe(session.sessionKey.did);
  });

  test('revokes an exchanged grant if TinyCloud verification fails before storage', async () => {
    const f = fixture();
    const client = f.make(async () => { throw new OpenKeyNativeError('SERVER', 'integrity failure'); });
    await expect(client.signIn({ capabilities })).rejects.toMatchObject({ code: 'SERVER' });
    expect(f.revokeCalls).toBe(1);
    expect(await client.current()).toBeNull();
  });

  test('maps cancel, access_denied, and state mismatch', async () => {
    for (const code of ['USER_CANCELLED', 'ACCESS_DENIED', 'STATE_MISMATCH'] as const) {
      const f = fixture();
      f.plugin.callback = code === 'USER_CANCELLED'
        ? async () => { throw { code: 'USER_CANCELLED' }; }
        : code === 'ACCESS_DENIED'
          ? async () => `${redirectUri}?error=access_denied&state=${f.state}&iss=${encodeURIComponent(issuer)}`
          : async () => `${redirectUri}?code=x&state=wrong&iss=${encodeURIComponent(issuer)}`;
      try { await f.make().signIn({ capabilities }); throw new Error('expected failure'); }
      catch (error) { expect(error).toBeInstanceOf(OpenKeyNativeError); expect((error as OpenKeyNativeError).code).toBe(code); }
    }
  });

  test('renew is single-flight and persists rotation', async () => {
    const f = fixture(); const client = f.make();
    await client.signIn({ capabilities });
    const [a, b] = await Promise.all([client.renew(), client.renew()]);
    expect(a.tokens.refreshToken).toBe('next');
    expect(b.tokens.refreshToken).toBe('next');
    expect(f.renewCalls).toBe(1);
    expect((await f.make().current())?.tokens.refreshToken).toBe('next');
  });

  test('keeps a rotated token when post-2xx delegation validation fails', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(200, { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'rotated' });
    expect((await f.make().current())?.tokens.refreshToken).toBe('rotated');
  });

  test('reloads after renewal_conflict and retries with the newer token', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply((call) => {
      if (call === 1) {
        for (const [key, value] of f.plugin.values) {
          if (key.endsWith(':session')) {
            const record = JSON.parse(value); record.tokens.refreshToken = 'other';
            f.plugin.values.set(key, JSON.stringify(record));
          }
        }
        return response(409, { error: 'renewal_conflict' });
      }
      return response(200, f.renewal('next'));
    });
    expect((await client.renew()).tokens.refreshToken).toBe('next');
    expect(f.renewCalls).toBe(2);
  });

  test('core obeys Retry-After for 429 and retries once', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply((call) => call === 1 ? response(429, { error: 'renewal_too_soon' }, '1') : response(200, f.renewal('next')));
    expect((await client.renew()).tokens.refreshToken).toBe('next');
    expect(f.renewCalls).toBe(2);
  });

  test('signOut wipes OpenKey and TinyCloud state after terminal revoke failure', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities });
    await client.sessionStorageAdapter().save(session.delegation.address!, { sessionKey: 'private-jwk' } as never);
    f.setRevokeReply(() => response(401, { error: 'invalid_session_proof' }));
    await expect(client.signOut()).rejects.toMatchObject({ code: 'INVALID_GRANT' });
    expect(await client.current()).toBeNull();
    expect(await client.sessionStorageAdapter().load(session.delegation.address!)).toBeNull();
  });

  test('TinyCloud storage adapter never accesses localStorage', async () => {
    const f = fixture(); const storage = f.make().sessionStorageAdapter();
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, get() { throw new Error('localStorage touched'); } });
    try {
      await storage.save('0xabc', { sessionKey: 'private-jwk' } as never);
      expect((await storage.load('0xabc'))?.sessionKey).toBe('private-jwk');
      expect(storage.exists('0xabc')).toBe(true);
      await storage.clear('0xabc');
      expect(storage.exists('0xabc')).toBe(false);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'localStorage', previous);
      else Reflect.deleteProperty(globalThis, 'localStorage');
    }
  });
});
