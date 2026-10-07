import { describe, expect, test } from 'bun:test';
import { base64UrlDecode, sessionDidForPublicKey, type NativeFetch, type NativeFetchResponse } from '@openkey/core';
import { OpenKeyCapacitor, OpenKeyNative, OpenKeyNativeError, type NativeSession, type OpenKeyCapacitorPlugin } from '../src/index';

const issuer = 'https://api.openkey.so/api/auth';
const host = 'https://tee.node.tinycloud.xyz';
const redirectUri = 'xyz.tinycloud.exo://openkey/callback';
const capabilities = [{ service: 'tinycloud.kv', space: 'applications', path: 'app/threads/', actions: ['tinycloud.kv/get'] }];
const persisted = (session: NativeSession) => ({ address: session.delegation.address!, sessionKey: JSON.stringify(session.sessionKey.privateJwk) }) as never;

function response(status: number, data: unknown, retryAfter?: string): NativeFetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => data,
    headers: { get: () => retryAfter ?? null } };
}

class MockPlugin implements OpenKeyCapacitorPlugin {
  values = new Map<string, string>();
  failSet = false;
  failGet = false;
  failRemove = false;
  setCount = 0;
  callback: (url: string) => Promise<string> = async () => '';
  async openAuthSession({ url }: { url: string }): Promise<{ url: string }> { return { url: await this.callback(url) }; }
  async secureStoreGet({ key }: { key: string }): Promise<{ value: string | null }> { if (this.failGet) throw new Error('decrypt'); return { value: this.values.get(key) ?? null }; }
  async secureStoreSet({ key, value }: { key: string; value: string }): Promise<void> { this.setCount++; if (this.failSet) throw new Error('write'); this.values.set(key, value); }
  async secureStoreRemove({ key }: { key: string }): Promise<void> { if (this.failRemove) throw new Error('wipe'); this.values.delete(key); }
}

function fixture(approved = capabilities) {
  const plugin = new MockPlugin();
  let state = '';
  let keyId = '';
  let renewCalls = 0;
  let revokeCalls = 0;
  let immediateRenewal = false;
  let tokenReply: () => NativeFetchResponse = () => response(200, { access_token: 'access', refresh_token: 'initial', tinycloud_delegation: delegation() });
  let renewReply: (call: number) => NativeFetchResponse = () => response(200, renewal('next'));
  let revokeReply: () => NativeFetchResponse = () => response(200, {});
  const delegation = (granted = approved) => ({
    verificationMethod: keyId, expiresAt: new Date(Date.now() + (immediateRenewal ? 30_000 : 3_600_000)).toISOString(),
    issuedAt: new Date(Date.now() - (immediateRenewal ? 3_600_000 : 0)).toISOString(), permissions: [
      { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }, ...granted,
    ], tinycloudHost: host, address: '0x0000000000000000000000000000000000000001', chainId: 1,
    spaceId: 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:applications',
    siwe: 'signed siwe', signature: '0xsignature', delegationHeader: { Authorization: 'Bearer fake' }, delegationCid: 'bafyfake',
  });
  const renewal = (refreshToken: string, granted = approved) => ({ refresh_token: refreshToken, tinycloud_delegation: delegation(granted) });
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
    if (url.endsWith('/token')) return tokenReply();
    if (url.endsWith('/renew')) return renewReply(++renewCalls);
    if (url.endsWith('/revoke')) { revokeCalls++; return revokeReply(); }
    throw new Error('unexpected request');
  };
  plugin.callback = async () => `${redirectUri}?code=code&state=${state}&iss=${encodeURIComponent(issuer)}`;
  const make = (verifyDelegation: (delegation: ReturnType<typeof delegation>) => Promise<void> = async () => {}) =>
    new OpenKeyNative({ clientId: 'exo', redirectUri, plugin, fetchFn, verifyDelegation, sleepFn: async () => {} });
  return { plugin, make, delegation, renewal, get state() { return state; }, get renewCalls() { return renewCalls; }, get revokeCalls() { return revokeCalls; },
    setRenewReply: (fn: typeof renewReply) => { renewReply = fn; }, setRevokeReply: (fn: typeof revokeReply) => { revokeReply = fn; },
    setImmediateRenewal: () => { immediateRenewal = true; }, setTokenReply: (fn: typeof tokenReply) => { tokenReply = fn; } };
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

  test('a subset renew preserves the approved set for a later plain renew', async () => {
    const second = { service: 'tinycloud.kv', space: 'applications', path: 'app/files/', actions: ['tinycloud.kv/get'] };
    const approved = [...capabilities, second];
    const f = fixture(approved); const client = f.make();
    await client.signIn({ capabilities: approved });
    f.setRenewReply((call) => response(200, f.renewal(`rotated${call}`, call === 1 ? capabilities : approved)));
    expect((await client.renew({ capabilities })).tokens.refreshToken).toBe('rotated1');
    expect((await client.renew()).tokens.refreshToken).toBe('rotated2');
    expect(f.renewCalls).toBe(2);
    const stored = JSON.parse([...f.plugin.values].find(([key]) => key.endsWith(':session'))![1]);
    expect(stored.permissions).toEqual(expect.arrayContaining(approved));
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
    await client.sessionStorageAdapter().save(session.delegation.address!, persisted(session));
    f.setRevokeReply(() => response(401, { error: 'invalid_session_proof' }));
    await client.signOut();
    expect(await client.current()).toBeNull();
    expect(await client.sessionStorageAdapter().load(session.delegation.address!)).toBeNull();
  });

  test('TinyCloud storage adapter never accesses localStorage', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities }); const storage = client.sessionStorageAdapter();
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, get() { throw new Error('localStorage touched'); } });
    try {
      await storage.save(session.delegation.address!, persisted(session));
      expect((await storage.load(session.delegation.address!))?.sessionKey).toBe(JSON.stringify(session.sessionKey.privateJwk));
      expect(storage.exists(session.delegation.address!)).toBe(true);
      await storage.clear(session.delegation.address!);
      expect(storage.exists(session.delegation.address!)).toBe(false);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'localStorage', previous);
      else Reflect.deleteProperty(globalThis, 'localStorage');
    }
  });

  test('offline current binds the restored session for a secure TinyCloud handoff', async () => {
    const first = fixture();
    await first.make().signIn({ capabilities });
    const restoredApp = fixture();
    restoredApp.plugin.values = new Map(first.plugin.values);
    const client = restoredApp.make();
    const restored = await client.current();
    expect(restored).not.toBeNull();
    await client.sessionStorageAdapter().save(restored!.delegation.address!, persisted(restored!));
    expect((await client.sessionStorageAdapter().load(restored!.delegation.address!))?.sessionKey)
      .toBe(JSON.stringify(restored!.sessionKey.privateJwk));
  });

  test('UNIMPLEMENTED maps to UNAVAILABLE and concurrent authorization has a distinct message', async () => {
    const f = fixture();
    f.plugin.callback = async () => { throw { code: 'UNIMPLEMENTED' }; };
    await expect(f.make().signIn({ capabilities })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    f.plugin.callback = async () => { throw { code: 'ALREADY_IN_PROGRESS' }; };
    await expect(f.make().signIn({ capabilities })).rejects.toMatchObject({ code: 'UNAVAILABLE', message: 'An authorization session is already in progress' });
  });

  test('failed rotation write reports the live token', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.plugin.failSet = true;
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'next' });
  });

  test('post-2xx validation error retains its token when persistence also fails', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(200, { refresh_token: 'rotated', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    f.plugin.failSet = true;
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'rotated' });
  });

  test('verifier rejection after renew keeps the rotated token', async () => {
    const f = fixture(); let verifications = 0;
    const client = f.make(async () => { if (++verifications === 2) throw new Error('bad wasm'); });
    await client.signIn({ capabilities });
    await expect(client.renew()).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'next' });
    expect((await client.current())?.tokens.refreshToken).toBe('next');
  });

  test('terminal renew clears the session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply(() => response(401, { error: 'invalid_grant' }));
    await expect(client.renew()).rejects.toMatchObject({ code: 'INVALID_GRANT' });
    expect(await client.current()).toBeNull();
  });

  test('different renew options serialize instead of sharing a flight', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRenewReply((call) => response(200, f.renewal(`next${call}`)));
    const [first, second] = await Promise.all([client.renew({ siweNonce: 'nonce0001' }), client.renew({ siweNonce: 'nonce0002' })]);
    expect(first.tokens.refreshToken).toBe('next1');
    expect(second.tokens.refreshToken).toBe('next2');
    expect(f.renewCalls).toBe(2);
  });

  test('a renew resolving after signOut cannot restore the wiped session', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRenewReply(() => ({ ...response(200, f.renewal('late')), json: async () => { entered(); await gate; return f.renewal('late'); } }));
    const renewal = client.renew(); await started;
    await client.signOut();
    release();
    await expect(renewal).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(await client.current()).toBeNull();
  });

  test('a TinyCloud session save already in flight is followed by the signOut wipe', async () => {
    const f = fixture(); const client = f.make(); const session = await client.signIn({ capabilities });
    const originalSet = f.plugin.secureStoreSet.bind(f.plugin);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.plugin.secureStoreSet = async (item) => {
      if (item.key.includes(':tinycloud:')) { entered(); await gate; }
      await originalSet(item);
    };
    const save = client.sessionStorageAdapter().save(session.delegation.address!, persisted(session));
    await started;
    const signOut = client.signOut();
    release();
    await Promise.all([save, signOut]);
    expect(await client.sessionStorageAdapter().load(session.delegation.address!)).toBeNull();
  });

  test('a TinyCloud handoff after signOut cannot restore the old session', async () => {
    const f = fixture(); const client = f.make(); const old = await client.signIn({ capabilities });
    await client.signOut();
    await expect(client.sessionStorageAdapter().save(old.delegation.address!, persisted(old))).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(await client.sessionStorageAdapter().load(old.delegation.address!)).toBeNull();
    const fresh = await client.signIn({ capabilities });
    await expect(client.sessionStorageAdapter().save(old.delegation.address!, persisted(old))).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    await client.sessionStorageAdapter().save(fresh.delegation.address!, persisted(fresh));
    expect((await client.sessionStorageAdapter().load(fresh.delegation.address!))?.sessionKey).toBe(JSON.stringify(fresh.sessionKey.privateJwk));
  });

  test('signIn then signOut in the same tick always wipes', async () => {
    const f = fixture(); const client = f.make();
    await client.signIn({ capabilities });
    const signIn = client.signIn({ capabilities });
    const signOut = client.signOut();
    await signOut;
    await expect(signIn).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect(await client.current()).toBeNull();
    expect(f.plugin.values.size).toBe(0);
  });

  test('an old renew cannot write over a new sign-in', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    f.setRenewReply(() => ({ ...response(200, f.renewal('old')), json: async () => { entered(); await gate; return f.renewal('old'); } }));
    const old = client.renew(); await started;
    const fresh = await client.signIn({ capabilities });
    release();
    await expect(old).rejects.toMatchObject({ code: 'NOT_SIGNED_IN' });
    expect((await client.current())?.sessionKey.did).toBe(fresh.sessionKey.did);
    expect((await client.current())?.tokens.refreshToken).toBe('initial');
  });

  test('transient revoke failure wipes and reports that the grant may remain active', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(client.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE', message: 'Local state was cleared; the server grant may still be active' });
    expect(await client.current()).toBeNull();
    expect(f.revokeCalls).toBe(2);
  });

  test('an undecryptable record is wiped even when revoke cannot run', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.plugin.failGet = true;
    await expect(client.signOut()).rejects.toMatchObject({ code: 'SERVER', message: 'Local state was cleared; the server grant may still be active' });
    expect(f.plugin.values.size).toBe(0);
  });

  test('signOut reports a local wipe failure', async () => {
    const f = fixture(); const client = f.make(); await client.signIn({ capabilities });
    f.plugin.failRemove = true;
    await expect(client.signOut()).rejects.toMatchObject({ code: 'SERVER', message: 'Local secure-store wipe failed' });
  });

  test('immediate renew failure rejects signIn and removes the initial session', async () => {
    const f = fixture(); f.setImmediateRenewal();
    f.setRenewReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    const client = f.make();
    await expect(client.signIn({ capabilities })).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
    expect(f.renewCalls).toBe(2);
    expect(await client.current()).toBeNull();
  });

  test('successful cleanup removes rotatedRefreshToken from an exchange error', async () => {
    const f = fixture();
    f.setTokenReply(() => response(200, { access_token: 'access', refresh_token: 'live', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    try { await f.make().signIn({ capabilities }); throw new Error('expected failure'); }
    catch (error) {
      expect(error).toMatchObject({ code: 'SERVER' });
      expect((error as OpenKeyNativeError).rotatedRefreshToken).toBeUndefined();
    }
    expect(f.revokeCalls).toBe(1);
  });

  test('failed cleanup retains the live token on an exchange error', async () => {
    const f = fixture();
    f.setTokenReply(() => response(200, { access_token: 'access', refresh_token: 'live', tinycloud_delegation: { ...f.delegation(), verificationMethod: 'wrong' } }));
    f.setRevokeReply(() => response(503, { error: 'temporarily_unavailable' }, '1'));
    await expect(f.make().signIn({ capabilities })).rejects.toMatchObject({ code: 'SERVER', rotatedRefreshToken: 'live' });
  });
});
