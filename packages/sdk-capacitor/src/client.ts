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

interface PendingRevokeGrant {
  privateJwk: NativeSessionJwk & { d: string };
  refreshToken: string;
  attempts: number;
  expiresAt: number;
}

interface PendingRevokeRecord {
  version: 1;
  grants: PendingRevokeGrant[];
}

function asNativeError(error: unknown): OpenKeyNativeError {
  if (error instanceof OpenKeyNativeError) return error;
  if (error && typeof error === 'object' && 'code' in error) {
    if (error.code === 'USER_CANCELLED') return new OpenKeyNativeError('USER_CANCELLED', 'The sign-in sheet was closed');
    if (error.code === 'UNAVAILABLE' || error.code === 'UNIMPLEMENTED') return new OpenKeyNativeError('UNAVAILABLE', 'Native authorization is unavailable');
    if (error.code === 'ALREADY_IN_PROGRESS') return new OpenKeyNativeError('UNAVAILABLE', 'An authorization session is already in progress');
  }
  return new OpenKeyNativeError('SERVER', 'Native OpenKey operation failed');
}

const TERMINAL_RENEW_CODES = new Set(['INVALID_GRANT', 'CONSENT_REQUIRED', 'ACCESS_DENIED', 'SPACE_UNAVAILABLE']);
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_REVOKE_ATTEMPTS = 20;

function transientRevoke(error: OpenKeyNativeError): boolean {
  return error.code === 'NETWORK' || error.code === 'TEMPORARILY_UNAVAILABLE' || error.status === 429 ||
    (error.status !== undefined && error.status >= 500 && error.status <= 599);
}

function refreshExpiry(delegation: TinyCloudDelegation): number {
  const until = delegation.renewableUntil;
  const absolute = typeof until === 'number' ? (until < 1e12 ? until * 1000 : until) :
    typeof until === 'string' ? Date.parse(until) : NaN;
  return Number.isFinite(absolute) ? Math.min(Date.now() + REFRESH_TTL_MS, absolute) : Date.now() + REFRESH_TTL_MS;
}

interface SessionCoordinator {
  epoch: number;
  signInAttempt: number;
  signedOut: boolean;
  /** A presented session key is bound to the generation that created it. */
  sessionEpochs: Map<string, number>;
  storageTail: Promise<void>;
  renewTail: Promise<void>;
  renewals: Map<string, Promise<NativeSession>>;
  signInFlight?: Promise<NativeSession>;
  signOutFlight?: Promise<void>;
  pendingRevokeFlight?: Promise<void>;
}

// Instances using the same native plugin and client share an epoch and storage
// queue. Separate test plugins and separate native clients remain isolated.
const coordinators = new WeakMap<OpenKeyCapacitorPlugin, Map<string, SessionCoordinator>>();
function coordinatorFor(plugin: OpenKeyCapacitorPlugin, namespace: string): SessionCoordinator {
  let byNamespace = coordinators.get(plugin);
  if (!byNamespace) { byNamespace = new Map(); coordinators.set(plugin, byNamespace); }
  let coordinator = byNamespace.get(namespace);
  if (!coordinator) {
    coordinator = { epoch: 0, signInAttempt: 0, signedOut: false, sessionEpochs: new Map(), storageTail: Promise.resolve(), renewTail: Promise.resolve(), renewals: new Map() };
    byNamespace.set(namespace, coordinator);
  }
  return coordinator;
}

export class OpenKeyNative {
  private readonly issuer: string;
  private readonly plugin: OpenKeyCapacitorPlugin;
  private readonly fetchFn?: NativeFetch;
  private readonly sleepFn?: SleepFn;
  private readonly verifier: (delegation: TinyCloudDelegation) => Promise<void>;
  private readonly namespace: string;
  private readonly storage: NativeSessionStorage;
  private readonly coordinator: SessionCoordinator;
  private metadataPromise?: Promise<OpenKeyServerMetadata>;

  constructor(private readonly options: OpenKeyNativeOptions) {
    this.issuer = options.issuer ?? 'https://api.openkey.so/api/auth';
    this.plugin = options.plugin ?? OpenKeyCapacitor;
    this.fetchFn = options.fetchFn;
    this.sleepFn = options.sleepFn;
    this.verifier = options.verifyDelegation ?? verifyTinyCloudDelegation;
    this.namespace = `openkey:${this.issuer}:${options.clientId}`;
    this.coordinator = coordinatorFor(this.plugin, this.namespace);
    this.storage = new NativeSessionStorage(this.plugin, this.namespace, (session, write) => {
      let privateJwk: NativeSessionJwk & { d: string };
      try {
        privateJwk = JSON.parse(session.sessionKey) as NativeSessionJwk & { d: string };
        sessionKeypairFromJwk(privateJwk);
      } catch { throw new OpenKeyNativeError('NOT_SIGNED_IN', 'TinyCloud session key is not an active OpenKey session'); }
      const epoch = this.coordinator.sessionEpochs.get(privateJwk.x);
      if (epoch === undefined) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'TinyCloud session key is not an active OpenKey session');
      return this.withStorage(async () => {
        this.assertEpoch(epoch);
        const record = await this.read();
        this.assertEpoch(epoch);
        if (!record || record.privateJwk.x !== privateJwk.x || record.privateJwk.d !== privateJwk.d ||
            record.delegation.address?.toLowerCase() !== session.address.toLowerCase()) {
          throw new OpenKeyNativeError('NOT_SIGNED_IN', 'TinyCloud session key is not an active OpenKey session');
        }
        await write();
      });
    }, () => !this.coordinator.signedOut, () => this.coordinator.epoch);
    const redirect = new URL(options.redirectUri);
    if (redirect.protocol !== 'https:' && !redirect.hostname) {
      throw new OpenKeyNativeError('SERVER', 'Private-use redirect URI must have a host');
    }
    // Initialization is synchronous for callers; cleanup runs in the background.
    // A transient retry remains in secure storage for the next opportunity.
    void this.retryPendingRevoke().catch(() => {});
  }

  private get recordKey(): string { return `${this.namespace}:session`; }
  private get pendingRevokeKey(): string { return `${this.namespace}:pending-revoke`; }
  private metadata(): Promise<OpenKeyServerMetadata> {
    if (!this.metadataPromise) {
      const pending = discoverOpenKeyServer(this.issuer, this.fetchFn);
      this.metadataPromise = pending;
      void pending.catch(() => {
        if (this.metadataPromise === pending) this.metadataPromise = undefined;
      });
    }
    return this.metadataPromise;
  }
  private expectedHost(): string {
    // The published Exo native ceiling uses this node; apps on another node
    // must declare it so core can perform an exact host check.
    return this.options.tinycloudHost ?? 'https://tee.node.tinycloud.xyz';
  }
  private async revokeRotatedBestEffort(metadata: OpenKeyServerMetadata, sessionKey: NativeSessionKeypair, token: string): Promise<boolean> {
    try {
      await revokeDelegation({ metadata, clientId: this.options.clientId, refreshToken: token,
        sessionKey, fetchFn: this.fetchFn, sleepFn: this.sleepFn });
      return true;
    } catch (caught) { return !transientRevoke(asNativeError(caught)); }
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
  private async readPending(): Promise<PendingRevokeRecord> {
    let value: string | null;
    try { ({ value } = await this.plugin.secureStoreGet({ key: this.pendingRevokeKey })); }
    catch (error) { throw asNativeError(error); }
    if (value === null) return { version: 1, grants: [] };
    try {
      const parsed = JSON.parse(value) as PendingRevokeRecord;
      if (parsed.version !== 1 || !Array.isArray(parsed.grants)) throw new Error();
      for (const grant of parsed.grants) {
        if (!grant || typeof grant.refreshToken !== 'string' || !grant.refreshToken) throw new Error();
        sessionKeypairFromJwk(grant.privateJwk);
        // Entries written by the previous SDK revision had neither bound.
        grant.attempts ??= 1;
        grant.expiresAt ??= Date.now() + REFRESH_TTL_MS;
        if (!Number.isInteger(grant.attempts) || grant.attempts < 0 || !Number.isFinite(grant.expiresAt)) throw new Error();
      }
      return parsed;
    } catch { throw new OpenKeyNativeError('SERVER', 'Stored pending revoke is invalid'); }
  }
  private appendPendingRevoke(grant: PendingRevokeGrant): Promise<void> {
    return this.withStorage(async () => {
      if (Date.now() >= grant.expiresAt || grant.attempts >= MAX_REVOKE_ATTEMPTS) return;
      const record = await this.readPending();
      if (record.grants.some((item) => item.refreshToken === grant.refreshToken)) return;
      record.grants.push(grant);
      try { await this.plugin.secureStoreSet({ key: this.pendingRevokeKey, value: JSON.stringify(record) }); }
      catch (error) { throw asNativeError(error); }
    });
  }
  private retryPendingRevoke(): Promise<void> {
    if (this.coordinator.pendingRevokeFlight) return this.coordinator.pendingRevokeFlight;
    const pending = this.retryPendingRevokeOnce();
    this.coordinator.pendingRevokeFlight = pending;
    void pending.finally(() => {
      if (this.coordinator.pendingRevokeFlight === pending) this.coordinator.pendingRevokeFlight = undefined;
    }).catch(() => {});
    return pending;
  }
  private async retryPendingRevokeOnce(): Promise<void> {
    const record = await this.withStorage(() => this.readPending());
    if (record.grants.length === 0) return;
    const settled = new Set<string>();
    const attempted = new Map<string, number>();
    let transient: OpenKeyNativeError | undefined;
    for (const grant of record.grants) {
      if (Date.now() >= grant.expiresAt || grant.attempts >= MAX_REVOKE_ATTEMPTS) {
        settled.add(grant.refreshToken);
        continue;
      }
      try {
        await revokeDelegation({ metadata: await this.metadata(), clientId: this.options.clientId,
          refreshToken: grant.refreshToken, sessionKey: sessionKeypairFromJwk(grant.privateJwk),
          fetchFn: this.fetchFn, sleepFn: this.sleepFn });
        settled.add(grant.refreshToken);
      } catch (caught) {
        const error = asNativeError(caught);
        if (!transientRevoke(error)) settled.add(grant.refreshToken);
        else {
          const attempts = grant.attempts + 1;
          if (attempts >= MAX_REVOKE_ATTEMPTS) settled.add(grant.refreshToken);
          else attempted.set(grant.refreshToken, attempts);
          transient ??= error;
        }
      }
    }
    if (settled.size > 0 || attempted.size > 0) {
      await this.withStorage(async () => {
        const latest = await this.readPending();
        const grants = latest.grants.filter((grant) => !settled.has(grant.refreshToken) && Date.now() < grant.expiresAt)
          .map((grant) => ({ ...grant, attempts: attempted.get(grant.refreshToken) ?? grant.attempts }));
        try {
          if (grants.length === 0) await this.plugin.secureStoreRemove({ key: this.pendingRevokeKey });
          else await this.plugin.secureStoreSet({ key: this.pendingRevokeKey, value: JSON.stringify({ version: 1, grants }) });
        } catch (error) { throw asNativeError(error); }
      });
    }
    if (transient) throw transient;
  }
  private withStorage<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.coordinator.storageTail.then(operation);
    this.coordinator.storageTail = pending.then(() => {}, () => {});
    return pending;
  }
  private assertEpoch(epoch: number): void {
    if (this.coordinator.epoch !== epoch) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'The OpenKey session changed');
  }
  private assertAttempt(attempt: number): void {
    if (this.coordinator.signInAttempt !== attempt) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'The sign-in attempt changed');
  }
  private commitSignIn(record: StoredSession, attempt: number): Promise<number> {
    return this.withStorage(async () => {
      this.assertAttempt(attempt);
      try { await this.plugin.secureStoreSet({ key: this.recordKey, value: JSON.stringify(record) }); }
      catch (error) { throw asNativeError(error); }
      this.assertAttempt(attempt);
      const epoch = ++this.coordinator.epoch;
      this.coordinator.sessionEpochs.clear();
      return epoch;
    });
  }
  private write(record: StoredSession, epoch: number): Promise<void> {
    return this.withStorage(async () => {
      this.assertEpoch(epoch); // immediately before the native write
      try { await this.plugin.secureStoreSet({ key: this.recordKey, value: JSON.stringify(record) }); }
      catch (error) { throw asNativeError(error); }
    });
  }
  private wipe(epoch?: number): Promise<void> {
    return this.withStorage(async () => {
      if (epoch !== undefined && this.coordinator.epoch !== epoch) return;
      let failure: OpenKeyNativeError | undefined;
      try { await this.plugin.secureStoreRemove({ key: this.recordKey }); }
      catch (error) { failure = asNativeError(error); }
      try { await this.storage.clearAll(); }
      catch (error) { failure ??= asNativeError(error); }
      this.coordinator.sessionEpochs.clear();
      if (failure) throw new OpenKeyNativeError('SERVER', 'Local secure-store wipe failed');
    });
  }
  private present(record: StoredSession): NativeSession {
    const sessionKey = sessionKeypairFromJwk(record.privateJwk);
    this.coordinator.sessionEpochs.set(record.privateJwk.x, this.coordinator.epoch);
    return { tokens: record.tokens, delegation: record.delegation, sessionKey };
  }

  signIn(options: { capabilities: NativeDelegationPermission[]; ttlSeconds?: number; siweNonce?: string }): Promise<NativeSession> {
    if (this.coordinator.signInFlight) return Promise.reject(new OpenKeyNativeError('UNAVAILABLE', 'A sign-in is already in progress'));
    const attempt = ++this.coordinator.signInAttempt;
    const pending = this.signInOnce(options, attempt);
    this.coordinator.signInFlight = pending;
    void pending.finally(() => { if (this.coordinator.signInFlight === pending) this.coordinator.signInFlight = undefined; }).catch(() => {});
    return pending;
  }

  private async signInOnce(options: { capabilities: NativeDelegationPermission[]; ttlSeconds?: number; siweNonce?: string }, attempt: number): Promise<NativeSession> {
    // Keep the existing session active until the replacement is ready to commit.
    await this.coordinator.signOutFlight?.catch(() => {});
    this.assertAttempt(attempt);
    await this.retryPendingRevoke().catch(() => {});
    this.assertAttempt(attempt);
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
      callback = (await this.plugin.openAuthSession({ url, callbackScheme: new URL(this.options.redirectUri).protocol.slice(0, -1), callbackUrl: this.options.redirectUri, expectedState: state, ephemeral: this.options.ephemeralSession ?? true })).url;
    } catch (error) { throw asNativeError(error); }
    let returned: URL;
    try { returned = new URL(callback); }
    catch { throw new OpenKeyNativeError('SERVER', 'Callback URL is not parseable'); }
    const expected = new URL(this.options.redirectUri);
    if (returned.protocol !== expected.protocol || returned.host !== expected.host || returned.pathname !== expected.pathname) {
      throw new OpenKeyNativeError('STATE_MISMATCH', 'Callback destination does not match redirect URI');
    }
    const { code } = parseNativeCallback({ url: callback, expectedState: state, issuer: this.issuer });
    let result: NativeTokenResult | undefined;
    let epoch: number | undefined;
    try {
      result = await exchangeDelegationCode({ metadata, code, redirectUri: this.options.redirectUri,
        clientId: this.options.clientId, codeVerifier: verifier, sessionKey,
        requestedPermissions: options.capabilities, expectedTinycloudHost: this.expectedHost(), fetchFn: this.fetchFn });
      await this.verifier(result.delegation);
      const record: StoredSession = {
        version: 1,
        tokens: { accessToken: result.accessToken, refreshToken: result.refreshToken, expiresIn: result.expiresIn, accessTokenExpiresAt: result.accessTokenExpiresAt },
        delegation: result.delegation, privateJwk: sessionKey.privateJwk,
        permissions: normalizeDelegationPermissions(options.capabilities),
      };
      await this.coordinator.renewTail;
      this.assertAttempt(attempt);
      epoch = await this.commitSignIn(record, attempt);
    } catch (caught) {
      // Exchange may have created a live grant. Use its exposed token only to
      // revoke; an unvalidated delegation is never persisted.
      const error = asNativeError(caught);
      const token = result?.refreshToken ?? error.rotatedRefreshToken;
      if (token) {
        try {
          await revokeDelegation({ metadata, clientId: this.options.clientId, refreshToken: token, sessionKey, fetchFn: this.fetchFn, sleepFn: this.sleepFn });
          error.rotatedRefreshToken = undefined; // the grant is no longer live
        } catch { error.rotatedRefreshToken = token; }
      }
      throw error;
    }
    if (!result) throw new OpenKeyNativeError('SERVER', 'Code exchange returned no result');
    if (epoch === undefined) throw new OpenKeyNativeError('SERVER', 'Sign-in session was not stored');
    if (delegationNeedsRenewalNow(result.delegation)) {
      try {
        const renewed = await this.renewOnce({}, epoch);
        this.coordinator.signedOut = false;
        return renewed;
      }
      catch (error) {
        // A rejected signIn never leaves a restorable session behind.
        await this.wipe(epoch);
        throw error;
      }
    }
    this.assertEpoch(epoch);
    const stored = await this.read();
    this.assertEpoch(epoch);
    if (!stored) throw new OpenKeyNativeError('SERVER', 'Sign-in session was not stored');
    this.coordinator.signedOut = false;
    return this.present(stored);
  }

  async current(): Promise<NativeSession | null> {
    if (this.coordinator.signedOut || this.coordinator.signOutFlight) return null;
    const epoch = this.coordinator.epoch;
    const record = await this.read();
    if (this.coordinator.epoch !== epoch || this.coordinator.signedOut || this.coordinator.signOutFlight) return null;
    return record ? this.present(record) : null;
  }

  async getSessionKey(): Promise<NativeSessionKeypair | null> {
    return (await this.current())?.sessionKey ?? null;
  }

  renew(options: { siweNonce?: string; capabilities?: NativeDelegationPermission[] } = {}): Promise<NativeSession> {
    if (this.coordinator.signedOut) return Promise.reject(new OpenKeyNativeError('NOT_SIGNED_IN', 'No OpenKey session is active'));
    if (this.coordinator.signOutFlight) return Promise.reject(new OpenKeyNativeError('NOT_SIGNED_IN', 'Sign-out is in progress'));
    if (this.coordinator.signInFlight) return Promise.reject(new OpenKeyNativeError('UNAVAILABLE', 'Sign-in is in progress'));
    const epoch = this.coordinator.epoch;
    const normalized = options.capabilities === undefined ? null : normalizeDelegationPermissions(options.capabilities);
    const sorted = normalized?.map((permission) => ({
      service: permission.service, space: permission.space, path: permission.path ?? '',
      actions: [...permission.actions].sort(),
    })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    const flightKey = `${epoch}:${JSON.stringify({ siweNonce: options.siweNonce ?? null, permissions: sorted })}`;
    const existing = this.coordinator.renewals.get(flightKey);
    if (existing) return existing;
    const pending = this.coordinator.renewTail.then(() => this.renewOnce(options, epoch));
    this.coordinator.renewTail = pending.then(() => {}, () => {});
    this.coordinator.renewals.set(flightKey, pending);
    void pending.finally(() => { if (this.coordinator.renewals.get(flightKey) === pending) this.coordinator.renewals.delete(flightKey); }).catch(() => {});
    return pending;
  }

  private async renewOnce(options: { siweNonce?: string; capabilities?: NativeDelegationPermission[] }, epoch: number): Promise<NativeSession> {
    this.assertEpoch(epoch);
    let record = await this.read();
    if (!record) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'No OpenKey session is stored');
    const metadata = await this.metadata();
    let conflictRetried = false;
    for (;;) {
      this.assertEpoch(epoch);
      const key = sessionKeypairFromJwk(record.privateJwk);
      let renewed: Awaited<ReturnType<typeof renewDelegation>>;
      try {
        renewed = await renewDelegation({ metadata, clientId: this.options.clientId,
          refreshToken: record.tokens.refreshToken, sessionKey: key,
          requestedPermissions: record.permissions, permissionsSubset: options.capabilities,
          siweNonce: options.siweNonce, expectedTinycloudHost: this.expectedHost(),
          fetchFn: this.fetchFn, sleepFn: this.sleepFn });
      } catch (caught) {
        if (this.coordinator.epoch !== epoch) {
          const stale = asNativeError(caught);
          if (stale.rotatedRefreshToken) await this.revokeRotatedBestEffort(metadata, key, stale.rotatedRefreshToken);
        }
        this.assertEpoch(epoch);
        const error = asNativeError(caught);
        if (error.code === 'RENEWAL_CONFLICT' && !conflictRetried) {
          conflictRetried = true;
          const reloaded = await this.read();
          this.assertEpoch(epoch);
          if (reloaded && reloaded.tokens.refreshToken !== record.tokens.refreshToken) {
            record = reloaded;
            continue;
          }
        }
        if (TERMINAL_RENEW_CODES.has(error.code)) {
          this.coordinator.epoch++;
          this.coordinator.signedOut = true;
          this.coordinator.sessionEpochs.clear();
          // Queue the wipe before any new sign-in can enqueue a write. Revoke
          // may take another network round trip and must not erase that flow.
          let wipeError: unknown;
          try { await this.wipe(); }
          catch (caught) { wipeError = caught; }
          if (error.rotatedRefreshToken && await this.revokeRotatedBestEffort(metadata, key, error.rotatedRefreshToken)) {
            error.rotatedRefreshToken = undefined;
          }
          if (wipeError) throw wipeError;
          throw error;
        }
        if (error.rotatedRefreshToken) {
          record.tokens.refreshToken = error.rotatedRefreshToken;
          try { await this.write(record, epoch); }
          catch { /* The original error still carries the rotated token. */ }
        }
        throw error;
      }
      if (this.coordinator.epoch !== epoch) {
        await this.revokeRotatedBestEffort(metadata, key, renewed.refreshToken);
        this.assertEpoch(epoch);
      }
      // Rotation is durable before verification or promise resolution. If a
      // write fails, the caller receives the live token in the typed error.
      record.tokens.refreshToken = renewed.refreshToken;
      try { await this.write(record, epoch); }
      catch (caught) {
        if (this.coordinator.epoch !== epoch) {
          await this.revokeRotatedBestEffort(metadata, key, renewed.refreshToken);
          this.assertEpoch(epoch);
        }
        const error = asNativeError(caught); error.rotatedRefreshToken = renewed.refreshToken; throw error;
      }
      try { await this.verifier(renewed.delegation); }
      catch {
        if (this.coordinator.epoch !== epoch) {
          await this.revokeRotatedBestEffort(metadata, key, renewed.refreshToken);
          this.assertEpoch(epoch);
        }
        const error = new OpenKeyNativeError('SERVER', 'Renewed TinyCloud delegation failed verification');
        error.rotatedRefreshToken = renewed.refreshToken;
        throw error;
      }
      if (this.coordinator.epoch !== epoch) {
        await this.revokeRotatedBestEffort(metadata, key, renewed.refreshToken);
        this.assertEpoch(epoch);
      }
      record.delegation = renewed.delegation;
      try { await this.write(record, epoch); }
      catch (caught) {
        if (this.coordinator.epoch !== epoch) {
          await this.revokeRotatedBestEffort(metadata, key, renewed.refreshToken);
          this.assertEpoch(epoch);
        }
        const error = asNativeError(caught); error.rotatedRefreshToken = renewed.refreshToken; throw error;
      }
      this.assertEpoch(epoch);
      return this.present(record);
    }
  }

  signOut(): Promise<void> {
    if (this.coordinator.signOutFlight) return this.coordinator.signOutFlight;
    this.coordinator.signInAttempt++;
    this.coordinator.epoch++;
    this.coordinator.signedOut = true;
    this.coordinator.sessionEpochs.clear();
    const pending = this.signOutOnce();
    this.coordinator.signOutFlight = pending;
    void pending.finally(() => { if (this.coordinator.signOutFlight === pending) this.coordinator.signOutFlight = undefined; }).catch(() => {});
    return pending;
  }

  private async signOutOnce(): Promise<void> {
    let record: StoredSession | null = null;
    let readError: OpenKeyNativeError | undefined;
    let revokeError: OpenKeyNativeError | undefined;
    let pendingError: OpenKeyNativeError | undefined;
    let pendingWriteError: OpenKeyNativeError | undefined;
    try { await this.retryPendingRevoke(); }
    catch (caught) { pendingError = asNativeError(caught); }
    try { record = await this.read(); }
    catch (caught) { readError = asNativeError(caught); }
    if (record) {
      try {
        await revokeDelegation({ metadata: await this.metadata(), clientId: this.options.clientId,
          refreshToken: record.tokens.refreshToken, sessionKey: sessionKeypairFromJwk(record.privateJwk),
          fetchFn: this.fetchFn, sleepFn: this.sleepFn });
      } catch (caught) { revokeError = asNativeError(caught); }
    }
    if (record && revokeError && transientRevoke(revokeError)) {
      try { await this.appendPendingRevoke({ privateJwk: record.privateJwk, refreshToken: record.tokens.refreshToken,
        attempts: 1, expiresAt: refreshExpiry(record.delegation) }); }
      catch (caught) { pendingWriteError = asNativeError(caught); }
    }
    // The wipe is independent of decryption and runs for every revoke outcome.
    await this.wipe();
    if (readError) throw new OpenKeyNativeError('SERVER', 'Local state was cleared; the server grant may still be active');
    if (pendingWriteError) {
      const error = new OpenKeyNativeError('SERVER', 'Local state was cleared; pending revoke could not be saved');
      error.rotatedRefreshToken = record?.tokens.refreshToken;
      throw error;
    }
    if (revokeError && transientRevoke(revokeError)) {
      throw new OpenKeyNativeError(revokeError.code, 'Local state was cleared; the server grant may still be active',
        revokeError.status, revokeError.serverError, revokeError.retryAfterSeconds);
    }
    if (pendingError && transientRevoke(pendingError)) {
      throw new OpenKeyNativeError(pendingError.code, 'Local state was cleared; the server grant may still be active',
        pendingError.status, pendingError.serverError, pendingError.retryAfterSeconds);
    }
  }

  sessionStorageAdapter(): NativeSessionStorage { return this.storage; }
}
