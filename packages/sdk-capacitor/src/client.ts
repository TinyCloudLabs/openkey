import {
  OpenKeyNativeError,
  buildNativeAuthorizeUrl,
  delegationNeedsRenewalNow,
  discoverOpenKeyServer,
  exchangeDelegationCode,
  generateCodeChallenge,
  generateCodeVerifier,
  generateSessionKeypair,
  generateState,
  normalizeDelegationPermissions,
  parseNativeCallback,
  renewDelegation,
  revokeDelegation,
  sendParRequest,
  sessionKeypairFromJwk,
  type NativeDelegationPermission,
  type NativeFetch,
  type NativeSessionJwk,
  type NativeSessionKeypair,
  type NativeTokenResult,
  type OpenKeyServerMetadata,
  type SleepFn,
  type TinyCloudDelegation,
} from '@openkey/core';
import { OpenKeyCapacitor, type OpenKeyCapacitorPlugin } from './plugin';
import { NativeSessionStorage } from './storage';
import { verifyTinyCloudDelegation } from './verify';

export interface OpenKeyNativeOptions {
  clientId: string;
  redirectUri: string;
  issuer?: string;
  ephemeralSession?: boolean;
  /** Exact TinyCloud host expected by the app. Set this for non-default nodes. */
  tinycloudHost?: string;
  /** Test and host-app injection points. */
  plugin?: OpenKeyCapacitorPlugin;
  fetchFn?: NativeFetch;
  sleepFn?: SleepFn;
  verifyDelegation?: (delegation: TinyCloudDelegation) => Promise<void>;
}

export interface NativeTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn?: number;
  accessTokenExpiresAt?: number;
}

export interface NativeSession {
  tokens: NativeTokens;
  delegation: TinyCloudDelegation;
  sessionKey: NativeSessionKeypair;
}

interface StoredSession {
  version: 1;
  tokens: NativeTokens;
  delegation: TinyCloudDelegation;
  privateJwk: NativeSessionJwk & { d: string };
  permissions: NativeDelegationPermission[];
}

function asNativeError(error: unknown): OpenKeyNativeError {
  if (error instanceof OpenKeyNativeError) return error;
  if (error && typeof error === 'object' && 'code' in error) {
    if (error.code === 'USER_CANCELLED') return new OpenKeyNativeError('USER_CANCELLED', 'The sign-in sheet was closed');
    if (error.code === 'UNAVAILABLE') return new OpenKeyNativeError('UNAVAILABLE', 'Native authorization is unavailable');
  }
  return new OpenKeyNativeError('SERVER', 'Native OpenKey operation failed');
}

export class OpenKeyNative {
  private readonly issuer: string;
  private readonly plugin: OpenKeyCapacitorPlugin;
  private readonly fetchFn?: NativeFetch;
  private readonly sleepFn?: SleepFn;
  private readonly verifier: (delegation: TinyCloudDelegation) => Promise<void>;
  private readonly namespace: string;
  private readonly storage: NativeSessionStorage;
  private metadataPromise?: Promise<OpenKeyServerMetadata>;
  private renewal?: Promise<NativeSession>;

  constructor(private readonly options: OpenKeyNativeOptions) {
    this.issuer = options.issuer ?? 'https://api.openkey.so/api/auth';
    this.plugin = options.plugin ?? OpenKeyCapacitor;
    this.fetchFn = options.fetchFn;
    this.sleepFn = options.sleepFn;
    this.verifier = options.verifyDelegation ?? verifyTinyCloudDelegation;
    this.namespace = `openkey:${this.issuer}:${options.clientId}`;
    this.storage = new NativeSessionStorage(this.plugin, this.namespace);
    const redirect = new URL(options.redirectUri);
    if (redirect.protocol !== 'https:' && !redirect.hostname) {
      throw new OpenKeyNativeError('SERVER', 'Private-use redirect URI must have a host');
    }
  }

  private get recordKey(): string { return `${this.namespace}:session`; }
  private metadata(): Promise<OpenKeyServerMetadata> {
    return this.metadataPromise ??= discoverOpenKeyServer(this.issuer, this.fetchFn);
  }
  private expectedHost(): string {
    // The published Exo native ceiling uses this node; apps on another node
    // must declare it so core can perform an exact host check.
    return this.options.tinycloudHost ?? 'https://tee.node.tinycloud.xyz';
  }
  private async read(): Promise<StoredSession | null> {
    let value: string | null;
    try { ({ value } = await this.plugin.secureStoreGet({ key: this.recordKey })); }
    catch (error) { throw asNativeError(error); }
    if (value === null) return null;
    try {
      const stored = JSON.parse(value) as StoredSession;
      if (stored.version !== 1 || !stored.tokens?.refreshToken || !stored.delegation || !stored.privateJwk) throw new Error();
      sessionKeypairFromJwk(stored.privateJwk);
      return stored;
    } catch {
      throw new OpenKeyNativeError('SERVER', 'Stored OpenKey session is invalid');
    }
  }
  private async write(record: StoredSession): Promise<void> {
    try { await this.plugin.secureStoreSet({ key: this.recordKey, value: JSON.stringify(record) }); }
    catch (error) { throw asNativeError(error); }
  }
  private present(record: StoredSession): NativeSession {
    return { tokens: record.tokens, delegation: record.delegation, sessionKey: sessionKeypairFromJwk(record.privateJwk) };
  }

  async signIn(options: { capabilities: NativeDelegationPermission[]; ttlSeconds?: number; siweNonce?: string }): Promise<NativeSession> {
    const metadata = await this.metadata();
    const sessionKey = generateSessionKeypair();
    const state = generateState();
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const { requestUri } = await sendParRequest(metadata, {
      clientId: this.options.clientId, redirectUri: this.options.redirectUri, state,
      codeChallenge: challenge, sessionKey, permissions: options.capabilities,
      ttlSeconds: options.ttlSeconds, siweNonce: options.siweNonce,
    }, this.fetchFn);
    const url = buildNativeAuthorizeUrl({ authorizationEndpoint: metadata.authorizationEndpoint, clientId: this.options.clientId, requestUri });
    let callback: string;
    try {
      callback = (await this.plugin.openAuthSession({ url, callbackScheme: new URL(this.options.redirectUri).protocol.slice(0, -1), callbackUrl: this.options.redirectUri, ephemeral: this.options.ephemeralSession ?? true })).url;
    } catch (error) { throw asNativeError(error); }
    const returned = new URL(callback);
    const expected = new URL(this.options.redirectUri);
    if (returned.protocol !== expected.protocol || returned.host !== expected.host || returned.pathname !== expected.pathname) {
      throw new OpenKeyNativeError('STATE_MISMATCH', 'Callback destination does not match redirect URI');
    }
    const { code } = parseNativeCallback({ url: callback, expectedState: state, issuer: this.issuer });
    let result: NativeTokenResult | undefined;
    try {
      result = await exchangeDelegationCode({ metadata, code, redirectUri: this.options.redirectUri,
        clientId: this.options.clientId, codeVerifier: verifier, sessionKey,
        requestedPermissions: options.capabilities, expectedTinycloudHost: this.expectedHost(), fetchFn: this.fetchFn });
      await this.verifier(result.delegation);
    } catch (error) {
      // Exchange may have created a live grant. Use its exposed token only to
      // revoke; an unvalidated delegation is never persisted.
      const token = result?.refreshToken ?? (error instanceof OpenKeyNativeError ? error.rotatedRefreshToken : undefined);
      if (token) {
        try { await revokeDelegation({ metadata, clientId: this.options.clientId, refreshToken: token, sessionKey, fetchFn: this.fetchFn, sleepFn: this.sleepFn }); } catch { /* preserve the original failure */ }
      }
      throw asNativeError(error);
    }
    if (!result) throw new OpenKeyNativeError('SERVER', 'Code exchange returned no result');
    const record: StoredSession = {
      version: 1,
      tokens: { accessToken: result.accessToken, refreshToken: result.refreshToken, expiresIn: result.expiresIn, accessTokenExpiresAt: result.accessTokenExpiresAt },
      delegation: result.delegation, privateJwk: sessionKey.privateJwk,
      permissions: normalizeDelegationPermissions(options.capabilities),
    };
    await this.write(record);
    if (delegationNeedsRenewalNow(result.delegation)) return this.renew();
    return this.present(record);
  }

  async current(): Promise<NativeSession | null> {
    const record = await this.read();
    return record ? this.present(record) : null;
  }

  async getSessionKey(): Promise<NativeSessionKeypair | null> {
    return (await this.current())?.sessionKey ?? null;
  }

  renew(options: { siweNonce?: string; capabilities?: NativeDelegationPermission[] } = {}): Promise<NativeSession> {
    if (this.renewal) return this.renewal;
    const pending = this.renewOnce(options);
    this.renewal = pending;
    void pending.finally(() => { if (this.renewal === pending) this.renewal = undefined; }).catch(() => {});
    return pending;
  }

  private async renewOnce(options: { siweNonce?: string; capabilities?: NativeDelegationPermission[] }): Promise<NativeSession> {
    let record = await this.read();
    if (!record) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'No OpenKey session is stored');
    const metadata = await this.metadata();
    let conflictRetried = false;
    for (;;) {
      const key = sessionKeypairFromJwk(record.privateJwk);
      try {
        const renewed = await renewDelegation({ metadata, clientId: this.options.clientId,
          refreshToken: record.tokens.refreshToken, sessionKey: key,
          requestedPermissions: record.permissions, permissionsSubset: options.capabilities,
          siweNonce: options.siweNonce, expectedTinycloudHost: this.expectedHost(),
          fetchFn: this.fetchFn, sleepFn: this.sleepFn });
        // Rotation is durable before any verification or promise resolution.
        record.tokens.refreshToken = renewed.refreshToken;
        await this.write(record);
        await this.verifier(renewed.delegation);
        record.delegation = renewed.delegation;
        if (options.capabilities) record.permissions = normalizeDelegationPermissions(options.capabilities);
        await this.write(record);
        return this.present(record);
      } catch (error) {
        if (error instanceof OpenKeyNativeError && error.rotatedRefreshToken) {
          record.tokens.refreshToken = error.rotatedRefreshToken;
          await this.write(record);
        }
        if (error instanceof OpenKeyNativeError && error.code === 'RENEWAL_CONFLICT' && !conflictRetried) {
          conflictRetried = true;
          const reloaded = await this.read();
          if (reloaded && reloaded.tokens.refreshToken !== record.tokens.refreshToken) {
            record = reloaded;
            continue;
          }
        }
        throw asNativeError(error);
      }
    }
  }

  async signOut(): Promise<void> {
    const record = await this.read();
    try {
      if (record) await revokeDelegation({ metadata: await this.metadata(), clientId: this.options.clientId,
        refreshToken: record.tokens.refreshToken, sessionKey: sessionKeypairFromJwk(record.privateJwk),
        fetchFn: this.fetchFn, sleepFn: this.sleepFn });
    } finally {
      try { await this.plugin.secureStoreRemove({ key: this.recordKey }); }
      catch (error) { throw asNativeError(error); }
      if (record?.delegation.address) await this.storage.clear(record.delegation.address);
    }
  }

  sessionStorageAdapter(): NativeSessionStorage { return this.storage; }
}
