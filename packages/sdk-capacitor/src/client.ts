import {
  OpenKeyNativeError,
  buildNativeAuthorizeUrl,
  delegationNeedsRenewalNow,
  discoverOpenKeyServer,
  exchangeDelegationCode,
  exchangeStepUpCode,
  generateCodeChallenge,
  generateCodeVerifier,
  generateSessionKeypair,
  generateState,
  isNativeStepUpAppId,
  nativeStepUpHomeBinding,
  normalizeDelegationPermissions,
  parseNativeCallback,
  renewDelegation,
  requestStepUp,
  revokeDelegation,
  revokeStepUp,
  sendParRequest,
  sessionKeypairFromJwk,
  type NativeDelegationPermission,
  type NativeRenewalAsk,
  type NativeRenewalReceipt,
  type NativeStepUpPermission,
  type NativeStepUpRenewal,
  type NativeFetch,
  type NativeLoginMethod,
  type NativeSessionJwk,
  type NativeSessionKeypair,
  type NativeTokenResult,
  type OpenKeyServerMetadata,
  type SleepFn,
  type TinyCloudDelegation,
  type TinyCloudStepUp,
} from '@openkey/core';
import { OpenKeyCapacitor, type OpenKeyCapacitorPlugin } from './plugin';
import { NativeSessionStorage } from './storage';
import { verifyTinyCloudDelegation } from './verify';

export interface OpenKeyNativeOptions {
  clientId: string;
  redirectUri: string;
  /**
   * Redirect URI of the step-up browser step (TC-3569); it must be registered on
   * the client. Defaults to `redirectUri`, which every platform already routes
   * back to the app. A separate URI needs its own route (Android's intent filter
   * and plugin accept only `/callback` today).
   */
  stepUpRedirectUri?: string;
  issuer?: string;
  ephemeralSession?: boolean;
  /** Android Custom Tabs appearance. iOS ASWebAuthenticationSession ignores this option. */
  browserTheme?: { toolbarColor: string; colorScheme: 'dark' | 'light' | 'system' };
  /** Exact TinyCloud host expected by the app. Set this for non-default nodes. */
  tinycloudHost?: string;
  /** Test and host-app injection points. */
  plugin?: OpenKeyCapacitorPlugin;
  /** Shared identity for distinct plugin wrappers backed by one native secure store. */
  storageIdentity?: object;
  fetchFn?: NativeFetch;
  sleepFn?: SleepFn;
  verifyDelegation?: (delegation: TinyCloudDelegation) => Promise<void>;
}

export interface NativeSignInOptions {
  capabilities: NativeDelegationPermission[];
  ttlSeconds?: number;
  siweNonce?: string;
  loginHint?: string;
  loginMethod?: NativeLoginMethod;
  renewal?: NativeRenewalAsk;
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
  /** Use the node's effective expiry for this CID; OpenKey does not remint the grant. */
  renewalMode?: 'leased';
  /** New exchange only. Save the receipt separately only after successful node admission. */
  renewal?: NativeRenewalReceipt | null;
  /** Monotonic receipt arrival for the admission deadline. New exchange only. */
  renewalArrivedAt?: number;
  /** Step-ups held for this grant, by app id; absent when there are none. */
  stepUps?: Record<string, TinyCloudStepUp>;
}

interface StoredSession {
  version: 1;
  tokens: NativeTokens;
  delegation: TinyCloudDelegation;
  privateJwk: NativeSessionJwk & { d: string };
  permissions: NativeDelegationPermission[];
  /** Milliseconds when the current refresh token was issued or rotated. */
  refreshIssuedAt?: number;
  /** The device can use its bound token only to stop the standing lease after OAuth expiry. */
  standingRevokeUntil?: number;
  /** Step-ups held for this grant, by app id. Absent in sessions stored before TC-3569. */
  stepUps?: Record<string, TinyCloudStepUp>;
}

interface PendingRevokeGrant {
  privateJwk: NativeSessionJwk & { d: string };
  refreshToken: string;
  attempts: number;
  expiresAt: number;
  standing?: true;
}

interface PendingRevokeRecord {
  version: 1;
  grants: PendingRevokeGrant[];
}

interface ExchangeIntent {
  version: 1;
  /** OAuth state identifies this one attempted grant; the key identifies its server binding. */
  attemptId: string;
  privateJwk: NativeSessionJwk & { d: string };
  refreshToken?: string;
  expiresAt: number;
  standing?: true;
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

function storageFailure(message: string, cause?: OpenKeyNativeError): OpenKeyNativeError {
  const failure = new OpenKeyNativeError('STORAGE', message);
  if (cause) {
    cause.rotatedRefreshToken = undefined;
    failure.cause = cause;
  }
  return failure;
}

class SessionReadError extends OpenKeyNativeError {
  constructor(message: string, readonly corrupt: boolean) {
    super('STORAGE', message);
  }
}

/** The step-ups that have not expired, or `undefined` when none have. */
function liveStepUps(stepUps: Record<string, TinyCloudStepUp> | undefined, now = Date.now()): Record<string, TinyCloudStepUp> | undefined {
  if (!stepUps) return undefined;
  const live = Object.fromEntries(Object.entries(stepUps).filter(([, stepUp]) => Date.parse(stepUp.expiresAt) > now));
  return Object.keys(live).length > 0 ? live : undefined;
}

/** A stored `stepUps` of the wrong shape never invalidates the sign-in session around it. */
function sanitizeStepUps(value: unknown): Record<string, TinyCloudStepUp> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const clean: Record<string, TinyCloudStepUp> = {};
  for (const [appId, entry] of Object.entries(value)) {
    const candidate = entry as Partial<TinyCloudStepUp> | null;
    if (isNativeStepUpAppId(appId) && candidate && typeof candidate === 'object' && candidate.appId === appId &&
        typeof candidate.expiresAt === 'string' && Array.isArray(candidate.permissions)) {
      clean[appId] = candidate as TinyCloudStepUp;
    }
  }
  return Object.keys(clean).length > 0 ? clean : undefined;
}

const TERMINAL_RENEW_CODES = new Set(['INVALID_GRANT', 'CONSENT_REQUIRED', 'ACCESS_DENIED', 'SPACE_UNAVAILABLE']);
const MAX_STANDING_LEASE_MS = 365 * 24 * 60 * 60_000;
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_REVOKE_ATTEMPTS = 20;

function transientRevoke(error: OpenKeyNativeError): boolean {
  return error.code === 'NETWORK' || error.code === 'TEMPORARILY_UNAVAILABLE' || error.status === 429 ||
    (error.status !== undefined && error.status >= 500 && error.status <= 599);
}

function grantExpiry(issuedAt: number, delegation?: TinyCloudDelegation): number {
  const until = delegation?.renewableUntil;
  const absolute = typeof until === 'number' ? (until < 1e12 ? until * 1000 : until) :
    typeof until === 'string' ? Date.parse(until) : NaN;
  const expiry = issuedAt + REFRESH_TTL_MS;
  return Number.isFinite(absolute) ? Math.min(expiry, absolute + 300_000) : expiry;
}

function refreshExpiry(record: StoredSession): number {
  const issued = Number.isFinite(record.refreshIssuedAt) ? record.refreshIssuedAt! :
    record.delegation.issuedAt ? Date.parse(record.delegation.issuedAt) : NaN;
  return grantExpiry(Number.isFinite(issued) ? issued : Date.now(), record.delegation);
}

function pendingGrant(record: StoredSession): PendingRevokeGrant {
  return { privateJwk: record.privateJwk, refreshToken: record.tokens.refreshToken, attempts: 1,
    expiresAt: record.standingRevokeUntil ?? refreshExpiry(record),
    ...(record.standingRevokeUntil !== undefined && { standing: true }) };
}

type SessionMatch = { key: string; token?: string } | null;

function sessionMatch(record: StoredSession | null, expected: SessionMatch): boolean {
  return expected === null ? record === null : record?.privateJwk.x === expected.key &&
    (expected.token === undefined || record.tokens.refreshToken === expected.token);
}

function matchFor(record: StoredSession): SessionMatch {
  return { key: record.privateJwk.x, token: record.tokens.refreshToken };
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
  activeIntents: Set<string>;
  /** App ids with a step-up request in flight; one per app. */
  activeStepUps: Set<string>;
}

// One queue and epoch per physical secure-store identity and key prefix.
// Distinct wrappers of one backend must pass the same storageIdentity object.
const coordinators = new WeakMap<object, Map<string, SessionCoordinator>>();
function coordinatorFor(storeIdentity: object, namespace: string): SessionCoordinator {
  let byNamespace = coordinators.get(storeIdentity);
  if (!byNamespace) { byNamespace = new Map(); coordinators.set(storeIdentity, byNamespace); }
  let coordinator = byNamespace.get(namespace);
  if (!coordinator) {
    coordinator = { epoch: 0, signInAttempt: 0, signedOut: false, sessionEpochs: new Map(), storageTail: Promise.resolve(), renewTail: Promise.resolve(), renewals: new Map(), activeIntents: new Set(), activeStepUps: new Set() };
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
  private readonly stepUpRedirectUri: string;

  constructor(private readonly options: OpenKeyNativeOptions) {
    if (options.browserTheme && (!/^#[0-9a-fA-F]{6}$/.test(options.browserTheme.toolbarColor) ||
      !['dark', 'light', 'system'].includes(options.browserTheme.colorScheme))) {
      throw new OpenKeyNativeError('INVALID_REQUEST', 'Invalid browserTheme');
    }
    this.issuer = options.issuer ?? 'https://api.openkey.so/api/auth';
    this.stepUpRedirectUri = options.stepUpRedirectUri ?? options.redirectUri;
    this.plugin = options.plugin ?? OpenKeyCapacitor;
    this.fetchFn = options.fetchFn;
    this.sleepFn = options.sleepFn;
    this.verifier = options.verifyDelegation ?? verifyTinyCloudDelegation;
    this.namespace = `openkey:${this.issuer}:${options.clientId}`;
    this.coordinator = coordinatorFor(options.storageIdentity ?? this.plugin, this.namespace);
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
    const stepUpRedirect = new URL(this.stepUpRedirectUri);
    if (stepUpRedirect.protocol !== 'https:' && !stepUpRedirect.hostname) {
      throw new OpenKeyNativeError('SERVER', 'Private-use step-up redirect URI must have a host');
    }
    // Initialization is synchronous for callers; cleanup runs in the background.
    // A transient retry remains in secure storage for the next opportunity.
    void this.retryPendingRevoke().catch(() => {});
  }

  private get recordKey(): string { return `${this.namespace}:session`; }
  private get pendingRevokeKey(): string { return `${this.namespace}:pending-revoke`; }
  private get exchangeIntentKey(): string { return `${this.namespace}:exchange-intent`; }
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
  /** True once a grant is revoked or receives a terminal revoke response. */
  private async abandonGrant(grant: PendingRevokeGrant, metadata?: OpenKeyServerMetadata, surfaceStorageFailure = false): Promise<boolean> {
    try {
      await revokeDelegation({ metadata: metadata ?? await this.metadata(), clientId: this.options.clientId,
        refreshToken: grant.refreshToken, sessionKey: sessionKeypairFromJwk(grant.privateJwk),
        fetchFn: this.fetchFn, sleepFn: this.sleepFn });
      return true;
    } catch (caught) {
      if (!transientRevoke(asNativeError(caught))) return true;
      try { await this.appendPendingRevoke(grant); }
      catch (writeError) { if (surfaceStorageFailure) throw asNativeError(writeError); }
      return false;
    }
  }
  private abandonRotatedGrant(metadata: OpenKeyServerMetadata, record: StoredSession, token: string): Promise<boolean> {
    return this.abandonGrant({ privateJwk: record.privateJwk, refreshToken: token,
      attempts: 1, expiresAt: grantExpiry(Date.now(), record.delegation) }, metadata, true);
  }
  private async read(): Promise<StoredSession | null> {
    let value: string | null | undefined;
    try { ({ value } = await this.plugin.secureStoreGet({ key: this.recordKey })); }
    catch (error) {
      throw new SessionReadError(`OpenKey secure-store read failed: ${error instanceof Error ? error.message : 'native storage unavailable'}`, false);
    }
    if (value == null) return null;
    try {
      const stored = JSON.parse(value) as StoredSession;
      if (stored.version !== 1 || !stored.tokens?.refreshToken || !stored.delegation || !stored.privateJwk ||
          (stored.standingRevokeUntil !== undefined && !Number.isFinite(stored.standingRevokeUntil))) throw new Error();
      sessionKeypairFromJwk(stored.privateJwk);
      stored.stepUps = sanitizeStepUps(stored.stepUps);
      return stored;
    } catch {
      throw new SessionReadError('Stored OpenKey session is invalid', true);
    }
  }
  private async readPending(): Promise<PendingRevokeRecord> {
    let value: string | null | undefined;
    try { ({ value } = await this.plugin.secureStoreGet({ key: this.pendingRevokeKey })); }
    catch (error) { throw new OpenKeyNativeError('STORAGE', `Pending-revoke secure-store read failed: ${error instanceof Error ? error.message : 'native storage unavailable'}`); }
    if (value == null) return { version: 1, grants: [] };
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
    } catch { return this.clearCorruptPending(); }
  }
  private async clearCorruptPending(): Promise<PendingRevokeRecord> {
    try { await this.plugin.secureStoreRemove({ key: this.pendingRevokeKey }); }
    catch { throw new OpenKeyNativeError('STORAGE', 'Corrupt pending revoke could not be cleared'); }
    return { version: 1, grants: [] };
  }
  private async readExchangeIntent(): Promise<ExchangeIntent | null> {
    let value: string | null | undefined;
    try { ({ value } = await this.plugin.secureStoreGet({ key: this.exchangeIntentKey })); }
    catch (error) { throw new OpenKeyNativeError('STORAGE', `Exchange-intent secure-store read failed: ${error instanceof Error ? error.message : 'native storage unavailable'}`); }
    if (value == null) return null;
    try {
      const intent = JSON.parse(value) as ExchangeIntent;
      if (intent.version !== 1 || typeof intent.attemptId !== 'string' || !intent.attemptId ||
          !Number.isFinite(intent.expiresAt) ||
          (intent.refreshToken !== undefined && (typeof intent.refreshToken !== 'string' || !intent.refreshToken))) throw new Error();
      sessionKeypairFromJwk(intent.privateJwk);
      return intent;
    } catch {
      try { await this.plugin.secureStoreRemove({ key: this.exchangeIntentKey }); }
      catch { throw new OpenKeyNativeError('STORAGE', 'Corrupt exchange intent could not be cleared'); }
      return null;
    }
  }
  private writeExchangeIntent(intent: ExchangeIntent): Promise<void> {
    return this.withStorage(async () => {
      try { await this.plugin.secureStoreSet({ key: this.exchangeIntentKey, value: JSON.stringify(intent) }); }
      catch { throw new OpenKeyNativeError('STORAGE', 'Exchange intent could not be saved'); }
    });
  }
  private markExchangeToken(attemptId: string, token: string, standingLeaseExpiresAt?: number): Promise<void> {
    return this.withStorage(async () => {
      const intent = await this.readExchangeIntent();
      if (!intent || intent.attemptId !== attemptId) throw new OpenKeyNativeError('STORAGE', 'Exchange intent was lost before its token could be saved');
      intent.refreshToken = token;
      if (standingLeaseExpiresAt !== undefined && Number.isFinite(standingLeaseExpiresAt)) {
        intent.standing = true;
        intent.expiresAt = Math.max(intent.expiresAt, Math.min(standingLeaseExpiresAt, Date.now() + MAX_STANDING_LEASE_MS));
      }
      try { await this.plugin.secureStoreSet({ key: this.exchangeIntentKey, value: JSON.stringify(intent) }); }
      catch { throw new OpenKeyNativeError('STORAGE', 'Exchanged refresh token could not be saved'); }
    });
  }
  private clearExchangeIntent(attemptId: string): Promise<void> {
    return this.withStorage(async () => {
      const intent = await this.readExchangeIntent();
      if (!intent || intent.attemptId !== attemptId) return;
      try { await this.plugin.secureStoreRemove({ key: this.exchangeIntentKey }); }
      catch { throw new OpenKeyNativeError('STORAGE', 'Exchange intent could not be cleared'); }
    });
  }
  private async retryExchangeIntentOnce(): Promise<void> {
    const state = await this.withStorage(async () => {
      const intent = await this.readExchangeIntent();
      return { intent, session: intent ? await this.read() : null };
    });
    const { intent, session } = state;
    if (!intent || this.coordinator.activeIntents.has(intent.attemptId)) return;
    // A committed session is authoritative even if the app died between the
    // session write and removal of its intent.
    if (!intent.refreshToken || Date.now() >= intent.expiresAt || session?.privateJwk.x === intent.privateJwk.x) {
      await this.clearExchangeIntent(intent.attemptId);
      return;
    }
    try {
      await revokeDelegation({ metadata: await this.metadata(), clientId: this.options.clientId,
        refreshToken: intent.refreshToken, sessionKey: sessionKeypairFromJwk(intent.privateJwk),
        fetchFn: this.fetchFn, sleepFn: this.sleepFn });
    } catch (caught) {
      const error = asNativeError(caught);
      if (transientRevoke(error)) {
        await this.appendPendingRevoke({ privateJwk: intent.privateJwk, refreshToken: intent.refreshToken,
          attempts: 1, expiresAt: intent.expiresAt, ...(intent.standing && { standing: true }) });
        await this.clearExchangeIntent(intent.attemptId);
        throw error;
      }
    }
    await this.clearExchangeIntent(intent.attemptId);
  }
  private appendPendingRevoke(grant: PendingRevokeGrant): Promise<void> {
    return this.withStorage(async () => {
      if (Date.now() >= grant.expiresAt || (!grant.standing && grant.attempts >= MAX_REVOKE_ATTEMPTS)) return;
      const record = await this.readPending();
      if (record.grants.some((item) => item.refreshToken === grant.refreshToken)) return;
      record.grants.push(grant);
      try { await this.plugin.secureStoreSet({ key: this.pendingRevokeKey, value: JSON.stringify(record) }); }
      catch { throw new OpenKeyNativeError('STORAGE', 'Pending revoke could not be saved'); }
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
    let intentError: OpenKeyNativeError | undefined;
    try { await this.retryExchangeIntentOnce(); }
    catch (caught) { intentError = asNativeError(caught); }
    const record = await this.withStorage(() => this.readPending());
    if (record.grants.length === 0) {
      if (intentError) throw intentError;
      return;
    }
    const settled = new Set<string>();
    const attempted = new Map<string, number>();
    let transient: OpenKeyNativeError | undefined;
    for (const grant of record.grants) {
      if (Date.now() >= grant.expiresAt || (!grant.standing && grant.attempts >= MAX_REVOKE_ATTEMPTS)) {
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
          if (!grant.standing && attempts >= MAX_REVOKE_ATTEMPTS) settled.add(grant.refreshToken);
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
        } catch { throw storageFailure('Pending revoke retry could not be saved', transient); }
      });
    }
    if (transient) throw transient;
    if (intentError) throw intentError;
  }
  private withStorage<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.coordinator.storageTail.then(operation);
    this.coordinator.storageTail = pending.then(() => {}, () => {});
    return pending;
  }
  private readQueued(): Promise<StoredSession | null> { return this.withStorage(() => this.read()); }
  private assertEpoch(epoch: number): void {
    if (this.coordinator.epoch !== epoch) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'The OpenKey session changed');
  }
  private assertAttempt(attempt: number): void {
    if (this.coordinator.signInAttempt !== attempt) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'The sign-in attempt changed');
  }
  private commitSignIn(record: StoredSession, attempt: number, previousKey: string | null, intentId: string): Promise<{ epoch: number; replaced: StoredSession | null }> {
    return this.withStorage(async () => {
      this.assertAttempt(attempt);
      const current = await this.read();
      this.assertAttempt(attempt);
      if ((current?.privateJwk.x ?? null) !== previousKey) {
        throw new OpenKeyNativeError('NOT_SIGNED_IN', 'The stored OpenKey session changed during sign-in');
      }
      try { await this.plugin.secureStoreSet({ key: this.recordKey, value: JSON.stringify(record) }); }
      catch { throw new OpenKeyNativeError('STORAGE', 'OpenKey session could not be saved'); }
      if (this.coordinator.signInAttempt !== attempt) {
        // A sign-out can start while the native set is in flight. Put the
        // previous grant back before its queued read so it can revoke A;
        // signIn's catch separately revokes the newly exchanged grant B.
        try {
          if (current) await this.plugin.secureStoreSet({ key: this.recordKey, value: JSON.stringify(current) });
          else await this.plugin.secureStoreRemove({ key: this.recordKey });
        } catch { throw new OpenKeyNativeError('STORAGE', 'Cancelled sign-in could not restore the prior session'); }
        this.assertAttempt(attempt);
      }
      // These two native writes share one process-wide storage step. If the
      // process stops after the session write, recovery sees the matching key.
      try {
        const intent = await this.readExchangeIntent();
        if (intent?.attemptId === intentId) await this.plugin.secureStoreRemove({ key: this.exchangeIntentKey });
      } catch { /* The matching committed session makes a leftover intent safe to clear on restart. */ }
      const epoch = ++this.coordinator.epoch;
      this.coordinator.sessionEpochs.clear();
      return { epoch, replaced: current };
    });
  }
  private write(record: StoredSession, epoch: number, expected: SessionMatch): Promise<void> {
    return this.withStorage(async () => {
      this.assertEpoch(epoch);
      const current = await this.read();
      this.assertEpoch(epoch);
      if (!sessionMatch(current, expected)) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'The stored OpenKey session changed');
      try { await this.plugin.secureStoreSet({ key: this.recordKey, value: JSON.stringify(record) }); }
      catch { throw new OpenKeyNativeError('STORAGE', 'OpenKey session could not be saved'); }
    });
  }
  private wipe(epoch?: number, expected?: SessionMatch): Promise<{ removed: boolean; record: StoredSession | null }> {
    return this.withStorage(async () => {
      if (epoch !== undefined && this.coordinator.epoch !== epoch) return { removed: false, record: null };
      let current: StoredSession | null = null;
      if (expected !== undefined) {
        current = await this.read();
        if (epoch !== undefined && this.coordinator.epoch !== epoch) return { removed: false, record: null };
        if (!sessionMatch(current, expected)) return { removed: false, record: null };
      }
      let failure: OpenKeyNativeError | undefined;
      try { await this.plugin.secureStoreRemove({ key: this.recordKey }); }
      catch { failure = new OpenKeyNativeError('STORAGE', 'OpenKey secure-store wipe failed'); }
      try { await this.storage.clearAll(); }
      catch (error) { failure ??= asNativeError(error); }
      this.coordinator.sessionEpochs.clear();
      if (failure) throw new OpenKeyNativeError('STORAGE', 'Local secure-store wipe failed');
      return { removed: true, record: current };
    });
  }
  private present(record: StoredSession): NativeSession {
    const sessionKey = sessionKeypairFromJwk(record.privateJwk);
    this.coordinator.sessionEpochs.set(record.privateJwk.x, this.coordinator.epoch);
    const stepUps = liveStepUps(record.stepUps);
    return { tokens: record.tokens, delegation: record.delegation, sessionKey,
      ...(record.standingRevokeUntil !== undefined && { renewalMode: 'leased' as const }), ...(stepUps ? { stepUps } : {}) };
  }

  signIn(options: NativeSignInOptions): Promise<NativeSession> {
    if (this.coordinator.signInFlight) return Promise.reject(new OpenKeyNativeError('UNAVAILABLE', 'A sign-in is already in progress'));
    const attempt = ++this.coordinator.signInAttempt;
    const pending = this.signInOnce(options, attempt);
    this.coordinator.signInFlight = pending;
    void pending.finally(() => { if (this.coordinator.signInFlight === pending) this.coordinator.signInFlight = undefined; }).catch(() => {});
    return pending;
  }

  private async signInOnce(options: NativeSignInOptions, attempt: number): Promise<NativeSession> {
    // Keep the existing session active until the replacement is ready to commit.
    await this.coordinator.signOutFlight?.catch(() => {});
    this.assertAttempt(attempt);
    await this.retryPendingRevoke().catch((caught) => {
      const error = asNativeError(caught);
      if (error.code === 'STORAGE') throw error;
    });
    this.assertAttempt(attempt);
    const previous = await this.readQueued();
    const previousKey = previous?.privateJwk.x ?? null;
    this.assertAttempt(attempt);
    const metadata = await this.metadata();
    const sessionKey = generateSessionKeypair();
    const state = generateState();
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const { requestUri } = await sendParRequest(metadata, {
      clientId: this.options.clientId, redirectUri: this.options.redirectUri, state,
      codeChallenge: challenge, sessionKey, permissions: options.capabilities,
      ttlSeconds: options.ttlSeconds, siweNonce: options.siweNonce, renewal: options.renewal,
      loginHint: options.loginHint, loginMethod: options.loginMethod,
    }, this.fetchFn);
    const url = buildNativeAuthorizeUrl({ authorizationEndpoint: metadata.authorizationEndpoint, clientId: this.options.clientId, requestUri });
    const code = await this.authorize(url, this.options.redirectUri, state);
    const intent: ExchangeIntent = { version: 1, attemptId: state, privateJwk: sessionKey.privateJwk,
      expiresAt: Date.now() + REFRESH_TTL_MS };
    this.coordinator.activeIntents.add(state);
    try { await this.writeExchangeIntent(intent); }
    catch (error) { this.coordinator.activeIntents.delete(state); throw error; }
    let result: NativeTokenResult | undefined;
    let epoch: number | undefined;
    try {
      result = await exchangeDelegationCode({ metadata, code, redirectUri: this.options.redirectUri,
        clientId: this.options.clientId, codeVerifier: verifier, sessionKey,
        requestedPermissions: options.capabilities, expectedTinycloudHost: this.expectedHost(), fetchFn: this.fetchFn,
        onRefreshToken: async (token, standingLeaseExpiresAt) => {
          try { await this.markExchangeToken(state, token, standingLeaseExpiresAt); }
          catch (caught) {
            const error = asNativeError(caught);
            error.rotatedRefreshToken = token;
            throw error;
          }
        } });
      await this.verifier(result.delegation);
      const refreshIssuedAt = Date.now();
      const standingLeaseExpiry = result.renewal ? Date.parse(result.renewal.receipt.leaseExpiresAt) : 0;
      const standingRevokeUntil = result.renewalMode === 'leased'
        ? Math.max(refreshIssuedAt + REFRESH_TTL_MS, Math.min(standingLeaseExpiry, refreshIssuedAt + MAX_STANDING_LEASE_MS))
        : undefined;
      const record: StoredSession = {
        version: 1,
        tokens: { accessToken: result.accessToken, refreshToken: result.refreshToken, expiresIn: result.expiresIn, accessTokenExpiresAt: result.accessTokenExpiresAt },
        delegation: result.delegation, privateJwk: sessionKey.privateJwk,
        permissions: normalizeDelegationPermissions(options.capabilities),
        refreshIssuedAt,
        ...(standingRevokeUntil !== undefined && { standingRevokeUntil }),
      };
      await this.coordinator.renewTail;
      this.assertAttempt(attempt);
      const committed = await this.commitSignIn(record, attempt, previousKey, state);
      epoch = committed.epoch;
      if (committed.replaced && committed.replaced.privateJwk.x !== record.privateJwk.x) {
        await this.abandonGrant(pendingGrant(committed.replaced), metadata);
      }
    } catch (caught) {
      // Exchange may have created a live grant. Use its exposed token only to
      // revoke; an unvalidated delegation is never persisted.
      const error = asNativeError(caught);
      const token = result?.refreshToken ?? error.rotatedRefreshToken;
      if (token) {
        const intent = await this.withStorage(() => this.readExchangeIntent()).catch(() => null);
        const settled = await this.abandonGrant({ privateJwk: sessionKey.privateJwk, refreshToken: token, attempts: 1,
          expiresAt: intent?.standing ? intent.expiresAt : grantExpiry(Date.now(), result?.delegation),
          ...(intent?.standing && { standing: true }) }, metadata, true);
        error.rotatedRefreshToken = undefined;
        if (settled) await this.clearExchangeIntent(state).catch(() => {});
        // A transient revoke keeps the token in pending revoke. The intent
        // stays as a second recovery copy until startup reconciles it.
        if (previous && error.code === 'NOT_SIGNED_IN') {
          const current = await this.readQueued().catch(() => null);
          if (current?.privateJwk.x !== previous.privateJwk.x) {
            await this.abandonGrant(pendingGrant(previous), metadata, true);
          }
        }
      } else {
        await this.clearExchangeIntent(state).catch(() => {});
      }
      throw error;
    } finally {
      this.coordinator.activeIntents.delete(state);
    }
    if (!result) throw new OpenKeyNativeError('SERVER', 'Code exchange returned no result');
    if (epoch === undefined) throw new OpenKeyNativeError('SERVER', 'Sign-in session was not stored');
    if (result.renewalMode !== 'leased' && delegationNeedsRenewalNow(result.delegation)) {
      try {
        const renewed = await this.renewOnce({}, epoch);
        this.coordinator.signedOut = false;
        return renewed;
      }
      catch (error) {
        // A rejected signIn never leaves a restorable session behind.
        const wiped = await this.wipe(epoch, { key: sessionKey.privateJwk.x });
        if (wiped.record) {
          await this.abandonGrant(pendingGrant(wiped.record), metadata, true);
          if (error instanceof OpenKeyNativeError) error.rotatedRefreshToken = undefined;
        }
        throw error;
      }
    }
    this.assertEpoch(epoch);
    const stored = await this.readQueued();
    this.assertEpoch(epoch);
    if (!stored) throw new OpenKeyNativeError('SERVER', 'Sign-in session was not stored');
    this.coordinator.signedOut = false;
    return { ...this.present(stored),
      ...(result.renewalMode === 'leased' && { renewal: result.renewal, renewalArrivedAt: result.renewalArrivedAt }) };
  }

  async current(): Promise<NativeSession | null> {
    if (this.coordinator.signedOut || this.coordinator.signOutFlight) return null;
    const epoch = this.coordinator.epoch;
    const record = await this.readQueued();
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
    const pending = this.inRenewQueue(() => this.renewOnce(options, epoch));
    this.coordinator.renewals.set(flightKey, pending);
    void pending.finally(() => { if (this.coordinator.renewals.get(flightKey) === pending) this.coordinator.renewals.delete(flightKey); }).catch(() => {});
    return pending;
  }

  private async renewOnce(options: { siweNonce?: string; capabilities?: NativeDelegationPermission[] }, epoch: number): Promise<NativeSession> {
    this.assertEpoch(epoch);
    let record = await this.readQueued();
    if (!record) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'No OpenKey session is stored');
    if (record.standingRevokeUntil !== undefined) throw new OpenKeyNativeError('CONSENT_REQUIRED', 'This delegation uses node renewal.');
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
          heldStepUps: record.stepUps,
          fetchFn: this.fetchFn, sleepFn: this.sleepFn });
      } catch (caught) {
        if (this.coordinator.epoch !== epoch) {
          const stale = asNativeError(caught);
          if (stale.rotatedRefreshToken) await this.abandonRotatedGrant(metadata, record, stale.rotatedRefreshToken);
        }
        this.assertEpoch(epoch);
        const error = asNativeError(caught);
        if (error.code === 'RENEWAL_CONFLICT' && !conflictRetried) {
          conflictRetried = true;
          const reloaded = await this.readQueued();
          this.assertEpoch(epoch);
          if (reloaded && reloaded.tokens.refreshToken !== record.tokens.refreshToken) {
            record = reloaded;
            continue;
          }
        }
        if (TERMINAL_RENEW_CODES.has(error.code)) {
          let wipeError: unknown;
          try {
            const wiped = await this.wipe(epoch, matchFor(record));
            if (wiped.removed) {
              this.coordinator.epoch++;
              this.coordinator.signedOut = true;
            }
            if (wiped.record) await this.abandonGrant(pendingGrant(wiped.record), metadata, true);
          }
          catch (caught) { wipeError = caught; }
          if (error.rotatedRefreshToken) {
            await this.abandonRotatedGrant(metadata, record, error.rotatedRefreshToken);
            error.rotatedRefreshToken = undefined;
          }
          if (wipeError) throw wipeError;
          throw error;
        }
        if (error.rotatedRefreshToken) {
          const expected = matchFor(record);
          record.tokens.refreshToken = error.rotatedRefreshToken;
          record.refreshIssuedAt = Date.now();
          try { await this.write(record, epoch, expected); }
          catch (writeError) {
            await this.abandonRotatedGrant(metadata, record, error.rotatedRefreshToken);
            error.rotatedRefreshToken = undefined;
            const failure = asNativeError(writeError);
            if (failure.code === 'NOT_SIGNED_IN') throw failure;
            throw storageFailure('Rotated refresh token could not be saved; its grant was abandoned', error);
          }
        }
        throw error;
      }
      if (this.coordinator.epoch !== epoch) {
        await this.abandonRotatedGrant(metadata, record, renewed.refreshToken);
        this.assertEpoch(epoch);
      }
      // Rotation is durable before verification or promise resolution. A
      // failed write abandons the new grant before returning an error.
      const expected = matchFor(record);
      record.tokens.refreshToken = renewed.refreshToken;
      record.refreshIssuedAt = Date.now();
      try { await this.write(record, epoch, expected); }
      catch (caught) {
        if (this.coordinator.epoch !== epoch) {
          await this.abandonRotatedGrant(metadata, record, renewed.refreshToken);
          this.assertEpoch(epoch);
        }
        const error = asNativeError(caught);
        await this.abandonRotatedGrant(metadata, record, renewed.refreshToken);
        if (error.code === 'NOT_SIGNED_IN') throw error;
        throw storageFailure('Rotated refresh token could not be saved; its grant was abandoned', error);
      }
      try { await this.verifier(renewed.delegation); }
      catch {
        if (this.coordinator.epoch !== epoch) {
          await this.abandonRotatedGrant(metadata, record, renewed.refreshToken);
          this.assertEpoch(epoch);
        }
        const error = new OpenKeyNativeError('SERVER', 'Renewed TinyCloud delegation failed verification');
        error.rotatedRefreshToken = renewed.refreshToken;
        throw error;
      }
      if (this.coordinator.epoch !== epoch) {
        await this.abandonRotatedGrant(metadata, record, renewed.refreshToken);
        this.assertEpoch(epoch);
      }
      record.delegation = renewed.delegation;
      record.stepUps = await this.mergeStepUps(record.stepUps, renewed.stepUps);
      try { await this.write(record, epoch, { key: record.privateJwk.x, token: renewed.refreshToken }); }
      catch (caught) {
        if (this.coordinator.epoch !== epoch) {
          await this.abandonRotatedGrant(metadata, record, renewed.refreshToken);
          this.assertEpoch(epoch);
        }
        const error = asNativeError(caught);
        if (error.code === 'NOT_SIGNED_IN') {
          await this.abandonRotatedGrant(metadata, record, renewed.refreshToken);
          throw error;
        }
        // The first write already made this token durable. Report the failed
        // delegation update without revoking the stored grant.
        throw storageFailure('Renewed delegation could not be saved', error);
      }
      this.assertEpoch(epoch);
      return this.present(record);
    }
  }

  private inRenewQueue<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.coordinator.renewTail.then(operation);
    this.coordinator.renewTail = pending.then(() => {}, () => {});
    return pending;
  }

  /** Open the authorization sheet and return the code of the callback for `state`; the callback must land on `redirectUri`. */
  private async authorize(url: string, redirectUri: string, state: string): Promise<string> {
    let callback: string;
    try {
      callback = (await this.plugin.openAuthSession({ url, callbackScheme: new URL(redirectUri).protocol.slice(0, -1), callbackUrl: redirectUri, expectedState: state, ephemeral: this.options.ephemeralSession ?? true, browserTheme: this.options.browserTheme })).url;
    } catch (error) { throw asNativeError(error); }
    let returned: URL;
    try { returned = new URL(callback); }
    catch { throw new OpenKeyNativeError('SERVER', 'Callback URL is not parseable'); }
    const expected = new URL(redirectUri);
    if (returned.protocol !== expected.protocol || returned.host !== expected.host || returned.pathname !== expected.pathname) {
      throw new OpenKeyNativeError('STATE_MISMATCH', 'Callback destination does not match redirect URI');
    }
    return parseNativeCallback({ url: callback, expectedState: state, issuer: this.issuer }).code;
  }

  private assertStepUpAllowed(appId: string): void {
    if (!isNativeStepUpAppId(appId)) throw new OpenKeyNativeError('INVALID_REQUEST', 'Invalid step-up app id');
    if (this.coordinator.signedOut) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'No OpenKey session is active');
    if (this.coordinator.signOutFlight) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'Sign-out is in progress');
    if (this.coordinator.signInFlight) throw new OpenKeyNativeError('UNAVAILABLE', 'Sign-in is in progress');
  }

  /**
   * Add one framed app's read-only step-up to the current Home grant (TC-3569):
   * request, system-browser consent, code exchange, then store the signed
   * delegation with the session. The Home session, its refresh token and its
   * stored record are untouched when any step fails.
   */
  async requestStepUp(options: { appId: string; capabilities: NativeStepUpPermission[] }): Promise<TinyCloudStepUp> {
    this.assertStepUpAllowed(options.appId);
    if (this.coordinator.activeStepUps.has(options.appId)) {
      throw new OpenKeyNativeError('UNAVAILABLE', 'A step-up for this app is already in progress');
    }
    this.coordinator.activeStepUps.add(options.appId);
    try { return await this.requestStepUpOnce(options, this.coordinator.epoch); }
    finally { this.coordinator.activeStepUps.delete(options.appId); }
  }

  private async requestStepUpOnce(options: { appId: string; capabilities: NativeStepUpPermission[] }, epoch: number): Promise<TinyCloudStepUp> {
    const metadata = await this.metadata();
    const state = generateState();
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    // The request is made with the grant's current refresh token, which a
    // renewal rotates: it runs in the renew queue so it never sees a dead one.
    const { home, binding, requestUri } = await this.inRenewQueue(async () => {
      this.assertEpoch(epoch);
      const stored = await this.readQueued();
      if (!stored) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'No OpenKey session is stored');
      // Fail closed before the user is asked: a Home delegation that cannot bind a step-up gets none.
      const homeBinding = nativeStepUpHomeBinding(stored.delegation);
      const pushed = await requestStepUp({ metadata, clientId: this.options.clientId, refreshToken: stored.tokens.refreshToken,
        sessionKey: sessionKeypairFromJwk(stored.privateJwk), appId: options.appId, redirectUri: this.stepUpRedirectUri,
        state, codeChallenge: challenge, permissions: options.capabilities, fetchFn: this.fetchFn, sleepFn: this.sleepFn });
      return { home: stored, binding: homeBinding, requestUri: pushed.requestUri };
    });
    const url = buildNativeAuthorizeUrl({ authorizationEndpoint: metadata.authorizationEndpoint, clientId: this.options.clientId, requestUri });
    const code = await this.authorize(url, this.stepUpRedirectUri, state);
    // A sign-out or a new sign-in during the consent screen ends this step-up.
    this.assertEpoch(epoch);
    const sessionKey = sessionKeypairFromJwk(home.privateJwk);
    try {
      const stepUp = await exchangeStepUpCode({ metadata, code, redirectUri: this.stepUpRedirectUri, clientId: this.options.clientId,
        codeVerifier: verifier, sessionKey, appId: options.appId, requestedPermissions: options.capabilities,
        expectedTinycloudHost: this.expectedHost(), ...binding, fetchFn: this.fetchFn });
      try { await this.verifier(stepUp); }
      catch { throw new OpenKeyNativeError('SERVER', 'Step-up delegation failed verification'); }
      // Persist on top of whatever a renewal stored meanwhile; a renewal and this write never interleave.
      await this.inRenewQueue(async () => {
        this.assertEpoch(epoch);
        const current = await this.readQueued();
        if (!current || current.privateJwk.x !== home.privateJwk.x) {
          throw new OpenKeyNativeError('NOT_SIGNED_IN', 'The stored OpenKey session changed');
        }
        const expected = matchFor(current);
        current.stepUps = liveStepUps({ ...current.stepUps, [stepUp.appId]: stepUp });
        await this.write(current, epoch, expected);
      });
      return stepUp;
    } catch (error) {
      // The code was redeemed, so the server may hold a step-up this client refused or could not store.
      // A server refusal of the exchange itself (an OAuth error) created nothing.
      if (!(error instanceof OpenKeyNativeError && error.serverError !== undefined)) {
        await this.discardStepUp(options.appId, home.privateJwk.x, epoch);
      }
      throw error;
    }
  }

  /**
   * End one app's step-up on the server and drop it from the stored session.
   * The Home grant and every other app's step-up are untouched. The local copy
   * is removed only after the server confirms; a failure leaves it in place.
   */
  async revokeStepUp(appId: string): Promise<void> {
    this.assertStepUpAllowed(appId);
    const epoch = this.coordinator.epoch;
    const metadata = await this.metadata();
    await this.inRenewQueue(() => this.revokeStepUpQueued(metadata, appId, epoch));
  }

  /** Runs in the renew queue. `onlyKeyX` limits it to the grant whose session key has that public `x`. */
  private async revokeStepUpQueued(metadata: OpenKeyServerMetadata, appId: string, epoch: number, onlyKeyX?: string): Promise<void> {
    this.assertEpoch(epoch);
    const record = await this.readQueued();
    if (!record) throw new OpenKeyNativeError('NOT_SIGNED_IN', 'No OpenKey session is stored');
    if (onlyKeyX !== undefined && record.privateJwk.x !== onlyKeyX) return;
    await revokeStepUp({ metadata, clientId: this.options.clientId, refreshToken: record.tokens.refreshToken,
      sessionKey: sessionKeypairFromJwk(record.privateJwk), appId, fetchFn: this.fetchFn, sleepFn: this.sleepFn });
    // The session was replaced while the server answered: that grant's step-ups are not this record's.
    if (this.coordinator.epoch !== epoch || !record.stepUps || !Object.hasOwn(record.stepUps, appId)) return;
    const expected = matchFor(record);
    const remaining = { ...record.stepUps };
    delete remaining[appId];
    record.stepUps = liveStepUps(remaining);
    await this.write(record, epoch, expected);
  }

  /**
   * Best effort after a step-up the server may have created was refused here:
   * end it on the server and drop any local copy for the app. It never throws,
   * so it cannot mask the error that caused it.
   */
  private async discardStepUp(appId: string, keyX: string, epoch: number): Promise<void> {
    try {
      const metadata = await this.metadata();
      await this.inRenewQueue(() => this.revokeStepUpQueued(metadata, appId, epoch, keyX));
    } catch {
      // The server row stays until the app calls revokeStepUp or the grant ends.
    }
  }

  /**
   * Fold a renewal's step-up fields into the held ones: renewed ones replace,
   * `removed` ones go, and `dropped`, `failed` and rejected ones stay as they
   * were until their own expiry. A renewed step-up the verifier refuses is
   * treated like a rejected one.
   */
  private async mergeStepUps(held: Record<string, TinyCloudStepUp> | undefined, renewal: NativeStepUpRenewal | undefined): Promise<Record<string, TinyCloudStepUp> | undefined> {
    const next: Record<string, TinyCloudStepUp> = { ...held };
    if (renewal) {
      for (const appId of renewal.removed) delete next[appId];
      for (const stepUp of renewal.renewed) {
        if (renewal.removed.includes(stepUp.appId)) continue;
        try { await this.verifier(stepUp); next[stepUp.appId] = stepUp; }
        catch { /* the held copy stays until it expires */ }
      }
    }
    return liveStepUps(next);
  }

  signOut(): Promise<void> {
    if (this.coordinator.signOutFlight) return this.coordinator.signOutFlight;
    this.coordinator.signedOut = true;
    const pending = this.signOutOnce();
    this.coordinator.signOutFlight = pending;
    void pending.finally(() => { if (this.coordinator.signOutFlight === pending) this.coordinator.signOutFlight = undefined; }).catch(() => {});
    return pending;
  }

  private async signOutOnce(): Promise<void> {
    let revokeError: OpenKeyNativeError | undefined;
    let pendingError: OpenKeyNativeError | undefined;
    let started = false;
    try { await this.retryPendingRevoke(); }
    catch (caught) { pendingError = asNativeError(caught); }
    if (pendingError?.code === 'STORAGE') {
      this.coordinator.signedOut = false;
      throw pendingError;
    }
    for (;;) {
      let record: StoredSession | null;
      try { record = await this.readQueued(); }
      catch (caught) {
        if (caught instanceof SessionReadError && !caught.corrupt) {
          this.coordinator.signedOut = false;
          throw caught;
        }
        // A record that was read but cannot be parsed has no usable grant.
        await this.wipe();
        throw asNativeError(caught);
      }
      if (!started) {
        started = true;
        this.coordinator.signInAttempt++;
        this.coordinator.epoch++;
        this.coordinator.sessionEpochs.clear();
      }
      if (record) {
        try {
          await revokeDelegation({ metadata: await this.metadata(), clientId: this.options.clientId,
            refreshToken: record.tokens.refreshToken, sessionKey: sessionKeypairFromJwk(record.privateJwk),
            fetchFn: this.fetchFn, sleepFn: this.sleepFn });
        } catch (caught) {
          const error = asNativeError(caught);
          if (transientRevoke(error)) {
            revokeError ??= error;
            try { await this.appendPendingRevoke(pendingGrant(record)); }
            catch {
              this.coordinator.signedOut = false;
              throw storageFailure('Pending revoke could not be saved; session remains stored', revokeError);
            }
          }
        }
      }
      let removed: boolean;
      try { removed = (await this.wipe(undefined, record ? matchFor(record) : null)).removed; }
      catch (caught) {
        if (!(caught instanceof SessionReadError)) {
          const failure = asNativeError(caught);
          if (failure.code === 'STORAGE' && revokeError) throw storageFailure(failure.message, revokeError);
          throw failure;
        }
        if (!caught.corrupt) {
          this.coordinator.signedOut = false;
          throw revokeError ? storageFailure(caught.message, revokeError) : caught;
        }
        await this.wipe();
        throw caught;
      }
      if (removed) break;
      // A different session was stored during revoke. Revoke the session that
      // is current at the eventual removal point.
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
