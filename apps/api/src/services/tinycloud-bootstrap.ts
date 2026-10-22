import {
  ACCOUNT_REGISTRY_SPACE,
  BOOTSTRAP_ALLOWLIST,
  BOOTSTRAP_ENCRYPTION_NETWORK_NAME,
  BOOTSTRAP_MANIFEST,
  CAPABILITIES,
  ENCRYPTION,
  KV,
  SECRETS_SPACE,
  SQL,
  bootstrapSteps,
  type BootstrapSpaceName,
  type BootstrapSpaceStep,
  type BootstrapStep,
  type ComposedManifestRequest,
  type Manifest,
} from '@tinycloud/bootstrap';
import {
  TCWSessionManager,
  completeSessionSetup,
  ensureEip55,
  generateHostSIWEMessage,
  invoke,
  invokeAny,
  parseRecapFromSiwe,
  prepareSession,
  siweToDelegationHeaders,
  vault_sha256,
} from '@tinycloud/node-sdk-wasm';
import type { PrismaClient } from '@openkey/db';
import { DEFAULT_TINYCLOUD_BOOTSTRAP_HOST, TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS } from './tinycloud-hosts';
import { tinyCloudBootstrapNodeCallTimeoutMs, tinyCloudBootstrapNodeInvokeTimeoutMs } from './tinycloud-node-timeouts';
import { kvSpaceRegistryStore, registerMissingBootstrapSpaces } from './tinycloud-space-registry';
import { SWEEP_RETRYABLE_CODES } from './tinycloud-bootstrap-budget';
import { decryptRefusalForSignedSiwe } from '../routes/delegate-session';

import { log } from '../log';
export const TINYCLOUD_BOOTSTRAP_VERSION = `@tinycloud/bootstrap:${canonicalHashHex({
  allowlist: BOOTSTRAP_ALLOWLIST,
  manifest: BOOTSTRAP_MANIFEST,
})}`;
const SUPPORTED_TINYCLOUD_CHAIN_IDS = new Set([1]);
const BOOTSTRAP_LOCK_TTL_MS = 2 * 60 * 1000;
const BOOTSTRAP_LOCK_REFRESH_MS = 30 * 1000;
const BOOTSTRAP_WAIT_MS = 500;
const MIN_USEFUL_SIWE_TTL_MS = 5_000;
const BOOTSTRAP_DOMAIN = 'cli.tinycloud.xyz';
const NETWORK_CREATE_ACTION = ENCRYPTION.NETWORK_CREATE;
const NETWORK_ADMIN_TYPE = 'tinycloud.encryption.network-admin/v1';

type PrismaLike = Pick<PrismaClient, 'user' | 'tinyCloudBootstrapState'>;

interface BootstrapStateRecord {
  id: string;
  status: string;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
}

export interface TinyCloudBootstrapKey {
  id: string;
  address: string;
  keyType: string;
}

export interface EnsureTinyCloudBootstrapInput {
  prisma: PrismaLike;
  userId: string;
  key: TinyCloudBootstrapKey;
  privateKey: string;
  message: string;
  format: 'raw' | 'personal_sign';
}

export interface EnsureTinyCloudBootstrapInputCore {
  prisma: PrismaLike;
  userId: string;
  key: TinyCloudBootstrapKey;
  /** Resolved inside the lock, so a sweep claim that loses never unseals the key. */
  privateKey: string | (() => Promise<string>);
  host?: string;
  /** The space this run is for: hosted first, inside the lock, and reported as soon as the node confirms it. */
  requestedSpace?: TinyCloudBootstrapRequestedSpace;
  /** Set by the background sweep: the lock is taken only if the row still matches what it observed. */
  sweepClaim?: TinyCloudBootstrapSweepClaim;
}

/** A sweep's claim on one row: the state it observed, and a hook fired only once the lock is won. */
export interface TinyCloudBootstrapSweepClaim {
  observed: {
    status: 'failed' | 'in_progress';
    sweepAttempts: number;
    checkedAt: Date;
    attemptId: string | null;
  };
  onClaimed: () => void;
}

export class TinyCloudBootstrapError extends Error {
  constructor(
    message: string,
    public readonly code = 'tinycloud_bootstrap_failed',
    public readonly retryable = true,
  ) {
    super(message);
  }
}

export type TinyCloudBootstrapOutcome =
  | { status: 'complete' }
  | { status: 'skipped' }
  | { status: 'failed'; errorCode: string; errorMessage: string };

interface RecapEntry {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

interface ParsedTinyCloudSiwe {
  address: string;
  chainId: number;
  expirationTime?: Date;
  entries: RecapEntry[];
}

interface BootstrapSession {
  space: BootstrapSpaceName;
  spaceId: string;
  session: {
    delegationHeader: { Authorization: string };
    delegationCid: string;
    spaceId: string;
    verificationMethod: string;
    jwk: Record<string, unknown>;
  };
}

export interface TinyCloudBootstrapRequestedSpaceFailure {
  status: 'failed';
  errorCode: string;
  errorMessage: string;
}

export type TinyCloudBootstrapRequestedSpaceReport = { status: 'hosted' } | TinyCloudBootstrapRequestedSpaceFailure;

/**
 * The space the client's approval is for. The run hosts it first, inside its own lock,
 * before the remaining spaces and the seeding (TC-1608).
 */
export interface TinyCloudBootstrapRequestedSpace {
  /** Canonical bootstrap space name, already checked against the approved space id. */
  space: BootstrapSpaceName;
  /** An earlier attempt of this approval already had the node confirm the space: do not host it again. */
  alreadyHosted?: boolean;
  /** Called once per attempt that hosts the space: the node confirmed it, or hosting it failed. */
  report: (report: TinyCloudBootstrapRequestedSpaceReport) => void;
}

interface TinyCloudBootstrapRunInput {
  address: string;
  chainId: number;
  privateKey: string;
  tinycloudHost: string;
  /** Spaces already hosted by the requested-space step. The run neither signs nor submits their host delegation. */
  skipHostSpaces?: readonly BootstrapSpaceName[];
}

type TinyCloudBootstrapExecutor = (input: TinyCloudBootstrapRunInput) => Promise<void>;

type TinyCloudBootstrapProbe = TinyCloudBootstrapExecutor;

let bootstrapExecutor: TinyCloudBootstrapExecutor = runTinyCloudBootstrap;
let bootstrapProbe: TinyCloudBootstrapProbe = probeTinyCloudBootstrap;

export function setTinyCloudBootstrapExecutorForTests(executor?: TinyCloudBootstrapExecutor): void {
  bootstrapExecutor = executor ?? runTinyCloudBootstrap;
}

export function setTinyCloudBootstrapProbeForTests(probe?: TinyCloudBootstrapProbe): void {
  bootstrapProbe = probe ?? probeTinyCloudBootstrap;
}

export function trustedTinyCloudBootstrapHost(): string {
  const host = (process.env.TINYCLOUD_BOOTSTRAP_HOST || DEFAULT_TINYCLOUD_BOOTSTRAP_HOST).replace(/\/+$/, '');
  if (TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(host)) {
    return host;
  }

  let parsed: URL;
  try {
    parsed = new URL(host);
  } catch {
    throw new TinyCloudBootstrapError(
      'TinyCloud bootstrap host is not a valid URL.',
      'tinycloud_bootstrap_untrusted_host',
      false,
    );
  }
  const isLocalDevHost = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (process.env.NODE_ENV !== 'production' && isLocalDevHost) {
    return host;
  }

  throw new TinyCloudBootstrapError(
    'TinyCloud bootstrap host is not trusted.',
    'tinycloud_bootstrap_untrusted_host',
    false,
  );
}

export function parseTinyCloudSiwe(message: string): ParsedTinyCloudSiwe | null {
  const header = message.match(/^.+ wants you to sign in with your Ethereum account:\n(0x[a-fA-F0-9]{40})\n/);
  if (!header?.[1]) {
    return null;
  }

  const chainIdMatch = message.match(/^Chain ID:\s*(\d+)\s*$/m);
  if (!chainIdMatch?.[1]) {
    return null;
  }

  let entries: RecapEntry[];
  try {
    entries = parseRecapFromSiwe(message) as RecapEntry[];
  } catch {
    return null;
  }

  if (!Array.isArray(entries) || entries.length === 0) {
    return null;
  }

  const expirationMatch = message.match(/^Expiration Time:\s*(.+)\s*$/m);
  const expirationTime = expirationMatch?.[1] ? new Date(expirationMatch[1]) : undefined;

  return {
    address: ensureEip55(header[1]),
    chainId: Number(chainIdMatch[1]),
    expirationTime: expirationTime && !Number.isNaN(expirationTime.getTime())
      ? expirationTime
      : undefined,
    entries,
  };
}

export function isTinyCloudSiweForSigner(
  parsed: ParsedTinyCloudSiwe,
  keyAddress: string,
): boolean {
  const address = ensureEip55(keyAddress);
  if (ensureEip55(parsed.address) !== address) {
    return false;
  }

  const accountSpace = `tinycloud:pkh:eip155:${parsed.chainId}:${address}:account`;
  const ownerDid = `did:pkh:eip155:${parsed.chainId}:${address}`;
  const defaultEncryptionNetwork = `urn:tinycloud:encryption:${ownerDid}:default`;

  return parsed.entries.some((entry) => isAccountBootstrapEntry(entry, accountSpace, defaultEncryptionNetwork));
}

function isAccountBootstrapEntry(
  entry: RecapEntry,
  accountSpace: string,
  defaultEncryptionNetwork: string,
): boolean {
  if (entry.path === defaultEncryptionNetwork) {
    return entry.actions.includes(NETWORK_CREATE_ACTION);
  }
  if (entry.space !== accountSpace) {
    return false;
  }

  return (
    entry.service === 'capabilities' &&
    (entry.path === '' || entry.path === 'capabilities') &&
    entry.actions.includes(CAPABILITIES.READ)
  ) || (
    entry.service === 'kv' &&
    (entry.path === 'applications/' || entry.path === 'spaces/') &&
    hasAnyAction(entry.actions, [KV.GET, KV.LIST, KV.PUT])
  ) || (
    entry.service === 'sql' &&
    entry.path === 'account' &&
    hasAnyAction(entry.actions, [SQL.READ, SQL.SCHEMA, SQL.WRITE])
  );
}

function hasAnyAction(actions: string[], expected: string[]): boolean {
  return expected.some((action) => actions.includes(action));
}

function isSupportedTinyCloudChainId(chainId: number): boolean {
  return SUPPORTED_TINYCLOUD_CHAIN_IDS.has(chainId);
}

export async function ensureTinyCloudBootstrapForApprovedSign(
  input: EnsureTinyCloudBootstrapInput,
): Promise<TinyCloudBootstrapOutcome> {
  // Kill-switch: clients on the SDK auto-sign strategy bootstrap through
  // POST /api/delegate/sign instead; this hook only compensates for older
  // clients. Disable once /delegate/sign traffic replaces widget signs.
  if (process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN === 'off') {
    return { status: 'skipped' };
  }

  if (input.format === 'raw') {
    return { status: 'skipped' };
  }

  const parsed = parseTinyCloudSiwe(input.message);
  if (!parsed || !isTinyCloudSiweForSigner(parsed, input.key.address)) {
    return { status: 'skipped' };
  }

  if (!isSupportedTinyCloudChainId(parsed.chainId)) {
    return { status: 'skipped' };
  }

  const preference = await input.prisma.user.findUnique({
    where: { id: input.userId },
    select: { autoSignEnabled: true },
  });
  if (!preference?.autoSignEnabled) {
    return { status: 'skipped' };
  }

  const expirationTime = parsed.expirationTime?.getTime();
  if (expirationTime !== undefined && expirationTime - Date.now() < MIN_USEFUL_SIWE_TTL_MS) {
    return {
      status: 'failed',
      errorCode: 'tinycloud_bootstrap_expired_request',
      errorMessage: 'TinyCloud sign-in request is expired or too close to expiry.',
    };
  }

  let tinycloudHost: string;
  try {
    tinycloudHost = trustedTinyCloudBootstrapHost();
  } catch (error) {
    const bootstrapErr = error instanceof TinyCloudBootstrapError ? error : null;
    return {
      status: 'failed',
      errorCode: bootstrapErr?.code ?? 'tinycloud_bootstrap_untrusted_host',
      errorMessage: bootstrapErr?.message ?? String(error),
    };
  }

  return ensureTinyCloudBootstrap({ ...input, host: tinycloudHost, chainId: parsed.chainId });
}

export async function isTinyCloudBootstrapComplete(
  prisma: PrismaLike,
  input: { keyId: string; chainId: number; host: string },
): Promise<boolean> {
  const state = await prisma.tinyCloudBootstrapState.findUnique({
    where: {
      keyId_chainId_tinycloudHost_bootstrapVersion: {
        keyId: input.keyId,
        chainId: input.chainId,
        tinycloudHost: input.host,
        bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
      },
    },
  });
  return state?.status === 'complete';
}

export async function ensureTinyCloudBootstrap(
  input: EnsureTinyCloudBootstrapInputCore & { chainId?: number },
): Promise<TinyCloudBootstrapOutcome> {
  if (process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN === 'off') return { status: 'skipped' };
  const chainId = input.chainId ?? 1;
  if (!isSupportedTinyCloudChainId(chainId)) return { status: 'skipped' };
  let tinycloudHost: string;
  try {
    tinycloudHost = input.host ?? trustedTinyCloudBootstrapHost();
    if (!TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS.has(tinycloudHost)) {
      // Keep local development support consistent with the host resolver.
      if (input.host && input.host === trustedTinyCloudBootstrapHost()) {
        tinycloudHost = input.host;
      } else {
        throw new TinyCloudBootstrapError('TinyCloud bootstrap host is not trusted.', 'tinycloud_bootstrap_untrusted_host', false);
      }
    }
  } catch (error) {
    const bootstrapErr = error instanceof TinyCloudBootstrapError ? error : null;
    return { status: 'failed', errorCode: bootstrapErr?.code ?? 'tinycloud_bootstrap_untrusted_host', errorMessage: bootstrapErr?.message ?? String(error) };
  }

  const cacheKey = {
    keyId: input.key.id,
    chainId,
    tinycloudHost,
    bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
  };

  const state = await input.prisma.tinyCloudBootstrapState.findUnique({
    where: { keyId_chainId_tinycloudHost_bootstrapVersion: cacheKey },
  });
  if (state?.status === 'complete') {
    return { status: 'complete' };
  }

  const attemptId = crypto.randomUUID();
  const locked = await acquireBootstrapLock(input.prisma, {
    state,
    attemptId,
    userId: input.userId,
    keyId: input.key.id,
    address: ensureEip55(input.key.address),
    chainId,
    tinycloudHost,
    sweep: input.sweepClaim?.observed,
  });

  if (!locked) {
    if (input.sweepClaim) {
      // A sweep that loses the claim is not a failed run and does not wait: the holder owns the row.
      return {
        status: 'failed',
        errorCode: 'tinycloud_bootstrap_in_progress',
        errorMessage: 'TinyCloud account bootstrap is already in progress for this key.',
      };
    }
    await wait(BOOTSTRAP_WAIT_MS);
    const refreshed = await input.prisma.tinyCloudBootstrapState.findUnique({
      where: { keyId_chainId_tinycloudHost_bootstrapVersion: cacheKey },
    });
    if (refreshed?.status === 'complete') {
      return { status: 'complete' };
    }
    return {
      status: 'failed',
      errorCode: 'tinycloud_bootstrap_in_progress',
      errorMessage: 'TinyCloud account bootstrap is already in progress for this key.',
    };
  }
  input.sweepClaim?.onClaimed();

  try {
    await withBootstrapLockHeartbeat(input.prisma, cacheKey, attemptId, async () => {
      const privateKey = await resolvePrivateKey(input.privateKey);
      const runInput: TinyCloudBootstrapRunInput = {
        address: ensureEip55(input.key.address),
        chainId,
        privateKey,
        tinycloudHost,
      };
      const requested = input.requestedSpace;
      if (requested) {
        // Before the probe and the other spaces: the client waits for this space only.
        if (!requested.alreadyHosted) await hostRequestedSpaceFirst(runInput, requested);
        runInput.skipHostSpaces = [requested.space];
      }

      await bootstrapProbe(runInput);
      await bootstrapExecutor(runInput);
    });

    const completed = await input.prisma.tinyCloudBootstrapState.updateMany({
      where: { ...cacheKey, attemptId },
      data: {
        status: 'complete',
        checkedAt: new Date(),
        completedAt: new Date(),
        failureCode: null,
        failureReason: null,
        attemptId: null,
        lockExpiresAt: null,
      },
    });
    if (completed.count !== 1) {
      throw new Error('TinyCloud bootstrap lock was lost before completion');
    }

    return { status: 'complete' };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    const errorCode = bootstrapFailureCode(error);
    await input.prisma.tinyCloudBootstrapState.updateMany({
      where: { ...cacheKey, attemptId },
      data: {
        status: 'failed',
        checkedAt: new Date(),
        failureCode: errorCode,
        failureReason: reason,
        lockExpiresAt: null,
      },
    });
    return {
      status: 'failed',
      errorCode,
      errorMessage: reason,
    };
  }
}

async function acquireBootstrapLock(
  prisma: PrismaLike,
  input: {
    state: BootstrapStateRecord | null;
    attemptId: string;
    userId: string;
    keyId: string;
    address: string;
    chainId: number;
    tinycloudHost: string;
    sweep?: TinyCloudBootstrapSweepClaim['observed'];
  },
): Promise<boolean> {
  const now = new Date();
  const lockExpiresAt = new Date(now.getTime() + BOOTSTRAP_LOCK_TTL_MS);
  const key = {
    keyId: input.keyId,
    chainId: input.chainId,
    tinycloudHost: input.tinycloudHost,
    bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
  };
  if (input.sweep) {
    // The claim matches only the state the sweep observed: a row changed by an approval or another tick matches nothing.
    const observed = input.sweep;
    const claimed = await prisma.tinyCloudBootstrapState.updateMany({
      where: {
        ...key,
        status: observed.status,
        sweepAttempts: observed.sweepAttempts,
        checkedAt: observed.checkedAt,
        attemptId: observed.attemptId,
        failureCode: { in: [...SWEEP_RETRYABLE_CODES] },
        ...(observed.status === 'in_progress' ? { lockExpiresAt: { lt: now } } : {}),
        user: { is: { autoSignEnabled: true } },
        key: { is: { keyType: 'MANAGED', archivedAt: null } },
      },
      data: {
        status: 'in_progress',
        attemptId: input.attemptId,
        lockExpiresAt,
        checkedAt: now,
        sweepAttempts: { increment: 1 },
      },
    });
    return claimed.count === 1;
  }

  if (!input.state) {
    try {
      await prisma.tinyCloudBootstrapState.create({
        data: {
          ...key,
          userId: input.userId,
          address: input.address,
          status: 'in_progress',
          attemptId: input.attemptId,
          lockExpiresAt,
          checkedAt: now,
        },
      });
      return true;
    } catch {
      return false;
    }
  }

  if (
    input.state.status === 'in_progress' &&
    input.state.lockExpiresAt &&
    input.state.lockExpiresAt.getTime() > now.getTime()
  ) {
    return false;
  }

  const result = await prisma.tinyCloudBootstrapState.updateMany({
    where: {
      ...key,
      OR: [
        { status: { not: 'in_progress' } },
        { lockExpiresAt: null },
        { lockExpiresAt: { lt: now } },
      ],
    },
    // A failed state keeps its failureCode/failureReason while it is retried: they stay
    // observable until the run completes (which clears them) or fails again.
    data: {
      status: 'in_progress',
      attemptId: input.attemptId,
      lockExpiresAt,
      checkedAt: now,
      // Approval claims start a fresh sweep budget.
      sweepAttempts: 0,
    },
  });

  return result.count === 1;
}

const PRIVATE_KEY_RESOLVE_TIMEOUT_MS = 5_000;

/** Resolves a lazily unsealed key with a bound, so a stuck unseal fails the run instead of holding the lock. */
async function resolvePrivateKey(privateKey: string | (() => Promise<string>)): Promise<string> {
  if (typeof privateKey === 'string') return privateKey;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      privateKey(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('TinyCloud bootstrap key unseal timed out')), PRIVATE_KEY_RESOLVE_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function withBootstrapLockHeartbeat<T>(
  prisma: PrismaLike,
  cacheKey: {
    keyId: string;
    chainId: number;
    tinycloudHost: string;
    bootstrapVersion: string;
  },
  attemptId: string,
  run: () => Promise<T>,
): Promise<T> {
  const refresh = () => refreshBootstrapLock(prisma, cacheKey, attemptId);
  let heartbeatError: Error | null = null;
  const interval = setInterval(() => {
    void refresh().catch((error) => {
      heartbeatError = error instanceof Error ? error : new Error(String(error));
    });
  }, BOOTSTRAP_LOCK_REFRESH_MS);
  try {
    await refresh();
    const result = await run();
    if (heartbeatError) {
      throw heartbeatError;
    }
    return result;
  } finally {
    clearInterval(interval);
  }
}

async function refreshBootstrapLock(
  prisma: PrismaLike,
  cacheKey: {
    keyId: string;
    chainId: number;
    tinycloudHost: string;
    bootstrapVersion: string;
  },
  attemptId: string,
): Promise<void> {
  const refreshed = await prisma.tinyCloudBootstrapState.updateMany({
    where: { ...cacheKey, attemptId },
    data: {
      lockExpiresAt: new Date(Date.now() + BOOTSTRAP_LOCK_TTL_MS),
      checkedAt: new Date(),
    },
  });
  if (refreshed.count !== 1) {
    throw new Error('TinyCloud bootstrap lock was lost');
  }
}

async function probeTinyCloudBootstrap(input: TinyCloudBootstrapRunInput): Promise<void> {
  const accountStep = bootstrapSteps(input.address, input.chainId)
    .find((step): step is BootstrapSpaceStep => step.kind === 'session' && step.space === ACCOUNT_REGISTRY_SPACE);
  if (!accountStep) {
    throw new Error('TinyCloud bootstrap account session policy is missing');
  }

  const session = await createBootstrapSession(input, accountStep);
  const activation = await nodeActivateSession(input.tinycloudHost, session.session.delegationHeader);
  if (!activation.success || activation.skipped?.includes(session.spaceId)) {
    return;
  }

  await invokeRaw(input.tinycloudHost, session, 'capabilities', '', CAPABILITIES.READ);
}

async function runTinyCloudBootstrap(input: TinyCloudBootstrapRunInput): Promise<void> {
  const skipHostSpaces = new Set<string>(input.skipHostSpaces ?? []);
  const steps = bootstrapSteps(input.address, input.chainId);
  // Requests inside each Promise.all fire in array order — put the spaces
  // apps check first (applications, account) at the front so they are the
  // most likely to be hosted before the /sign sync budget expires.
  const sessionSteps = steps.filter(isSessionStep).sort(bySpacePriority);
  const hostSteps = steps
    .filter((step): step is BootstrapSpaceStep => step.kind === 'host' && !skipHostSpaces.has(step.space))
    .sort(bySpacePriority);

  const [sessions, hostDelegations] = await Promise.all([
    Promise.all(sessionSteps.map((step) => createBootstrapSession(input, step))),
    Promise.all(hostSteps.map((step) => createHostDelegation(input, step))),
  ]);

  await Promise.all(hostDelegations.map((headers) => submitRequiredHostDelegation(input.tinycloudHost, headers)));
  await Promise.all(sessions.map((session) => activateRequiredSession(input.tinycloudHost, session)));

  const sessionBySpace = new Map(sessions.map((session) => [session.space, session]));
  const accountSession = requiredSession(sessionBySpace, ACCOUNT_REGISTRY_SPACE);
  const secretsSession = requiredSession(sessionBySpace, SECRETS_SPACE);

  // Schema first: seedBootstrapSpaces now writes account-index rows and
  // needs the spaces table to exist.
  await runAccountSchema(input.tinycloudHost, accountSession, steps);
  await Promise.all([
    seedBootstrapSpaces(input.tinycloudHost, accountSession, steps, input.address, input.chainId),
    seedBootstrapApplications(input.tinycloudHost, accountSession, steps),
  ]);

  await Promise.all([
    ensureEncryptionNetwork(input.tinycloudHost, accountSession, input.address, input.chainId),
    runSecretRecordsSchema(input.tinycloudHost, secretsSession, steps),
  ]);
}

/**
 * Host the space the client asked for, before anything else in the run: peer id, the host SIWE
 * signed by the managed key (the same createHostDelegation the full run uses), then submit it.
 * The node confirms by listing the space under `activated` in its response to that host
 * delegation. (Re-sending the client's session delegation would not confirm anything: a
 * delegation the node already holds is answered with an empty `skipped`.) No other signature and
 * no other ability is involved. Reports once.
 */
async function hostRequestedSpaceFirst(
  input: TinyCloudBootstrapRunInput,
  requested: TinyCloudBootstrapRequestedSpace,
): Promise<void> {
  try {
    const step = bootstrapSteps(input.address, input.chainId)
      .find((candidate): candidate is BootstrapSpaceStep => candidate.kind === 'host' && candidate.space === requested.space);
    if (!step) {
      throw new Error(`TinyCloud bootstrap host policy for ${requested.space} is missing`);
    }
    const activated = await submitRequiredHostDelegation(input.tinycloudHost, await createHostDelegation(input, step));
    if (!activated?.includes(step.spaceId)) {
      throw new TinyCloudBootstrapError(
        `TinyCloud node accepted the host delegation for ${requested.space} but did not report the space as hosted.`,
        'tinycloud_bootstrap_space_not_hosted',
      );
    }
  } catch (error) {
    requested.report({
      status: 'failed',
      errorCode: bootstrapFailureCode(error),
      errorMessage: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
  requested.report({ status: 'hosted' });
}

function bootstrapFailureCode(error: unknown): string {
  if (error instanceof TinyCloudBootstrapError) return error.code;
  // A node call aborted by its AbortSignal.timeout while its body was still being read.
  return error instanceof Error && error.name === 'TimeoutError'
    ? 'tinycloud_bootstrap_node_timeout'
    : 'tinycloud_bootstrap_failed';
}

function isSessionStep(step: BootstrapStep): step is BootstrapSpaceStep {
  return step.kind === 'session';
}

const BOOTSTRAP_SPACE_PRIORITY: Record<string, number> = {
  applications: 0,
  account: 1,
};

function bySpacePriority(a: BootstrapSpaceStep, b: BootstrapSpaceStep): number {
  return (BOOTSTRAP_SPACE_PRIORITY[a.space] ?? 9) - (BOOTSTRAP_SPACE_PRIORITY[b.space] ?? 9);
}

async function createBootstrapSession(
  input: { address: string; chainId: number; privateKey: string },
  step: BootstrapSpaceStep,
): Promise<BootstrapSession> {
  const manager = new TCWSessionManager();
  const keyId = manager.createSessionKey(`bootstrap:${step.space}`);
  const jwkText = manager.jwk(keyId);
  if (!jwkText) {
    throw new Error(`Failed to create bootstrap session key for ${step.space}`);
  }
  const jwk = JSON.parse(jwkText) as Record<string, unknown>;
  const issuedAt = new Date();
  const expirationTime = new Date(issuedAt.getTime() + 60 * 60 * 1000);
  const prepared = prepareSession({
    address: input.address,
    chainId: input.chainId,
    domain: BOOTSTRAP_DOMAIN,
    issuedAt: issuedAt.toISOString(),
    expirationTime: expirationTime.toISOString(),
    spaceId: step.spaceId,
    jwk,
    abilities: abilitiesFromRequest(step.request),
    ...(step.rawAbilities ? { rawAbilities: step.rawAbilities } : {}),
  });
  const sessionDecryptRefusal = decryptRefusalForSignedSiwe(prepared.siwe);
  if (sessionDecryptRefusal) throw new Error(sessionDecryptRefusal.error);
  const signature = await signEthereumMessage(input.privateKey, prepared.siwe);
  const session = completeSessionSetup({ ...prepared, signature });
  return { space: step.space, spaceId: step.spaceId, session };
}

async function createHostDelegation(
  input: { address: string; chainId: number; privateKey: string; tinycloudHost: string },
  step: BootstrapSpaceStep,
): Promise<Record<string, string>> {
  const peerId = await nodeFetchPeerId(input.tinycloudHost, step.spaceId);
  const siwe = generateHostSIWEMessage({
    address: input.address,
    chainId: input.chainId,
    domain: BOOTSTRAP_DOMAIN,
    issuedAt: new Date().toISOString(),
    spaceId: step.spaceId,
    peerId,
  });
  const hostDecryptRefusal = decryptRefusalForSignedSiwe(siwe);
  if (hostDecryptRefusal) throw new Error(hostDecryptRefusal.error);
  const signature = await signEthereumMessage(input.privateKey, siwe);
  return siweToDelegationHeaders({ siwe, signature }) as Record<string, string>;
}

async function signEthereumMessage(privateKey: string, message: string): Promise<string> {
  const teePackage = '@openkey/tee';
  const { createWalletFromPrivateKey } = await import(teePackage);
  const account = createWalletFromPrivateKey(privateKey);
  return account.signMessage({ message });
}

function abilitiesFromRequest(request?: ComposedManifestRequest): Record<string, Record<string, string[]>> {
  const abilities: Record<string, Record<string, string[]>> = {};
  for (const resource of request?.resources ?? []) {
    const service = shortService(resource.service);
    abilities[service] ??= {};
    abilities[service]![resource.path] = [...resource.actions];
  }
  return abilities;
}

function shortService(service: string): string {
  return service.startsWith('tinycloud.') ? service.slice('tinycloud.'.length) : service;
}

/**
 * POST a host delegation. Returns the spaces the node lists as `activated`, or undefined when a
 * 2xx response carries no readable list. A fresh host SIWE is a new delegation, so a node that
 * hosted its space lists that space as activated.
 */
async function submitRequiredHostDelegation(host: string, headers: Record<string, string>): Promise<string[] | undefined> {
  const response = await nodeFetch(`${host}/delegate`, { method: 'POST', headers }, tinyCloudBootstrapNodeCallTimeoutMs());
  if (!response.ok) {
    const error = await response.text().catch(() => response.statusText);
    throw new Error(`Failed to submit host delegation: ${error || 'unknown error'}`);
  }
  // Read the body outside the parse guard: a timeout while reading must fail the call, not look like "nothing activated".
  const text = await response.text();
  try {
    const body = JSON.parse(text) as { activated?: unknown };
    return Array.isArray(body.activated) ? body.activated.map(String) : undefined;
  } catch {
    return undefined;
  }
}

async function activateRequiredSession(host: string, session: BootstrapSession): Promise<void> {
  const result = await nodeActivateSession(host, session.session.delegationHeader);
  if (!result.success || result.skipped?.includes(session.spaceId)) {
    throw new Error(
      `Failed to activate bootstrap session for ${session.space}: ${result.error ?? 'space was skipped'}`,
    );
  }
}

async function nodeFetchPeerId(host: string, spaceId: string): Promise<string> {
  const response = await nodeFetch(
    `${host}/peer/generate/${encodeURIComponent(spaceId)}`,
    {},
    tinyCloudBootstrapNodeCallTimeoutMs(),
  );
  if (!response.ok) {
    const error = await response.text().catch(() => response.statusText);
    throw new Error(`Failed to get peer ID: ${response.status} - ${error}`);
  }
  return response.text();
}

interface NodeActivation {
  success: boolean;
  /** Absent when a successful response carried no readable `skipped` list: the outcome is unconfirmed. */
  skipped?: string[];
  error?: string;
}

/** POST /delegate with a session delegation. The node lists spaces it does not host under `skipped`. */
async function nodeActivateSession(host: string, delegationHeader: Record<string, string>): Promise<NodeActivation> {
  const response = await nodeFetch(
    `${host}/delegate`,
    { method: 'POST', headers: delegationHeader },
    tinyCloudBootstrapNodeCallTimeoutMs(),
  );
  if (!response.ok) {
    return { success: false, error: await response.text().catch(() => response.statusText) };
  }
  // Read the body outside the parse guard: a timeout while reading must fail the call, not look like "nothing skipped".
  const text = await response.text();
  try {
    const body = JSON.parse(text) as { skipped?: unknown };
    return { success: true, skipped: Array.isArray(body.skipped) ? body.skipped.map(String) : [] };
  } catch {
    return { success: true };
  }
}

async function nodeFetch(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    return await fetch(url, { ...init, signal });
  } catch (error) {
    if (signal.aborted) {
      throw new TinyCloudBootstrapError(
        `TinyCloud node request timed out after ${timeoutMs} ms.`,
        'tinycloud_bootstrap_node_timeout',
      );
    }
    throw error;
  }
}

async function runAccountSchema(
  host: string,
  session: BootstrapSession,
  steps: BootstrapStep[],
): Promise<void> {
  const schemaStep = steps.find((step) => step.kind === 'account-index-schema');
  if (!schemaStep || !('schema' in schemaStep)) return;
  await executeSqlSchema(host, session, schemaStep.database, schemaStep.schema);
}

async function runSecretRecordsSchema(
  host: string,
  session: BootstrapSession,
  steps: BootstrapStep[],
): Promise<void> {
  const schemaStep = steps.find((step) => step.kind === 'secret-records-schema');
  if (!schemaStep || !('schema' in schemaStep)) return;
  await executeSqlSchema(host, session, schemaStep.database, schemaStep.schema);
}

async function executeSqlSchema(
  host: string,
  session: BootstrapSession,
  database: string,
  schema: readonly string[],
): Promise<void> {
  await invokeJsonWithActions(host, session, [
    {
      spaceId: session.spaceId,
      service: 'sql',
      path: database,
      action: SQL.SCHEMA,
    },
    {
      spaceId: session.spaceId,
      service: 'sql',
      path: database,
      action: SQL.WRITE,
    },
  ], {
    action: 'execute',
    // The carrier statement runs under `execute`, which rejects statements
    // that return rows ("Execute returned results - did you mean to call
    // query?"). Re-run the last schema statement: idempotent, row-free, and
    // authorized by the same tinycloud.sql/schema ability.
    sql: schema[schema.length - 1] ?? 'CREATE TABLE IF NOT EXISTS _bootstrap_noop (id INTEGER PRIMARY KEY)',
    params: [],
    schema: [...schema],
  });
}

async function seedBootstrapSpaces(
  host: string,
  session: BootstrapSession,
  steps: BootstrapStep[],
  address: string,
  chainId: number,
): Promise<void> {
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
  const now = new Date().toISOString();
  const seedStep = steps.find((step) => step.kind === 'seed-spaces');
  if (!seedStep) throw new Error('TinyCloud bootstrap seed-spaces step is missing');

  const store = kvSpaceRegistryStore(
    ({ path, action, body, headers }) => invokeResponse(host, session, 'kv', path, action, body, headers),
    async (rows) => {
      if (rows.length === 0) return;
      const columns = '(space_id, name, owner_did, type, permissions_json, status, registered_at, updated_at, expires_at)';
      const values = rows.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
      await invokeJsonWithActions(host, session, [{
        spaceId: session.spaceId,
        service: 'sql',
        path: 'account',
        action: SQL.WRITE,
      }], {
        action: 'batch',
        statements: [{
          sql: `INSERT OR REPLACE INTO spaces ${columns} VALUES ${values}`,
          params: rows.flatMap((row) => [
            row.spaceId,
            row.name,
            row.ownerDid,
            row.type,
            row.permissionsJson,
            row.status,
            row.registeredAt,
            row.updatedAt,
            row.expiresAt,
          ]),
        }],
      });
    },
  );
  await registerMissingBootstrapSpaces(store, seedStep.spaces, ownerDid, now);
  log('info', 'tinycloud_bootstrap_space_registry_completed');
}

async function seedBootstrapApplications(
  host: string,
  session: BootstrapSession,
  steps: BootstrapStep[],
): Promise<void> {
  const seedStep = steps.find((step) => step.kind === 'seed-applications');
  if (!seedStep || !('manifests' in seedStep)) return;
  await Promise.all(seedStep.manifests.map((manifest) => putApplicationManifest(host, session, manifest)));
}

async function putApplicationManifest(host: string, session: BootstrapSession, manifest: Manifest): Promise<void> {
  await invokeRaw(
    host,
    session,
    'kv',
    `applications/${manifest.app_id}`,
    KV.PUT,
    JSON.stringify({
      app_id: manifest.app_id,
      name: manifest.name,
      description: manifest.description,
      manifest,
      updated_at: new Date().toISOString(),
    }),
  );
}

async function ensureEncryptionNetwork(
  host: string,
  session: BootstrapSession,
  address: string,
  chainId: number,
): Promise<void> {
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
  const networkId = `urn:tinycloud:encryption:${ownerDid}:${BOOTSTRAP_ENCRYPTION_NETWORK_NAME}`;
  const existing = await nodeFetch(
    `${host}/encryption/networks/${encodeURIComponent(networkId)}`,
    {},
    tinyCloudBootstrapNodeInvokeTimeoutMs(),
  );
  if (existing.ok) {
    return;
  }
  if (existing.status !== 404) {
    throw new Error(`Failed to check encryption network ${networkId}: HTTP ${existing.status}`);
  }

  const info = await nodeFetch(`${host}/info`, {}, tinyCloudBootstrapNodeInvokeTimeoutMs());
  if (!info.ok) {
    throw new Error(`Failed to fetch TinyCloud node info: HTTP ${info.status}`);
  }
  const { nodeId } = await info.json() as { nodeId?: unknown };
  if (typeof nodeId !== 'string' || nodeId.length === 0) {
    throw new Error('TinyCloud node /info response did not include nodeId');
  }

  const body = {
    name: BOOTSTRAP_ENCRYPTION_NETWORK_NAME,
    ownerDid,
    threshold: { n: 1, t: 1 },
  };
  const facts = {
    type: NETWORK_ADMIN_TYPE,
    targetNode: nodeId,
    networkId,
    bodyHash: canonicalHashHex(body),
    action: NETWORK_CREATE_ACTION,
  };
  const headers = invokeAny(
    session.session,
    [{
      resource: networkId,
      service: 'encryption',
      path: networkId,
      action: NETWORK_CREATE_ACTION,
    }],
    [facts],
  ) as Record<string, string>;
  const authorization = await rewriteInvocationAudience(authorizationHeader(headers), nodeId, session.session.jwk);
  const created = await nodeFetch(`${host}/encryption/networks`, {
    method: 'POST',
    headers: {
      Authorization: authorization,
      'Content-Type': 'application/json',
    },
    body: canonicalizeJson(body),
  }, tinyCloudBootstrapNodeInvokeTimeoutMs());
  if (!created.ok && created.status !== 409) {
    throw new Error(`Failed to create encryption network ${networkId}: HTTP ${created.status} ${await created.text()}`);
  }
}

async function invokeJson(
  host: string,
  session: BootstrapSession,
  service: string,
  path: string,
  action: string,
  body: Record<string, unknown>,
): Promise<void> {
  await invokeRaw(host, session, service, path, action, JSON.stringify(body), {
    'Content-Type': 'application/json',
  });
}

async function invokeJsonWithActions(
  host: string,
  session: BootstrapSession,
  entries: Array<{
    spaceId: string;
    service: string;
    path: string;
    action: string;
  }>,
  body: Record<string, unknown>,
): Promise<void> {
  const headers = invokeAny(session.session, entries, undefined) as Record<string, string>;
  const response = await nodeFetch(`${host}/invoke`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, tinyCloudBootstrapNodeInvokeTimeoutMs());
  if (!response.ok) {
    throw new Error(`TinyCloud multi-action invocation failed: HTTP ${response.status} ${await response.text()}`);
  }
}

async function invokeRaw(
  host: string,
  session: BootstrapSession,
  service: string,
  path: string,
  action: string,
  body?: BodyInit,
  extraHeaders: Record<string, string> = {},
): Promise<void> {
  const response = await invokeResponse(host, session, service, path, action, body, extraHeaders);
  if (!response.ok) {
    throw new Error(`TinyCloud ${service}/${path} ${action} failed: HTTP ${response.status} ${await response.text()}`);
  }
}

async function invokeResponse(
  host: string,
  session: BootstrapSession,
  service: string,
  path: string,
  action: string,
  body?: BodyInit,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  const headers = invoke(session.session, service, path, action, undefined) as Record<string, string>;
  return nodeFetch(`${host}/invoke`, {
    method: 'POST',
    headers: { ...headers, ...extraHeaders },
    body,
  }, tinyCloudBootstrapNodeInvokeTimeoutMs());
}

function requiredSession(
  sessions: Map<BootstrapSpaceName, BootstrapSession>,
  space: BootstrapSpaceName,
): BootstrapSession {
  const session = sessions.get(space);
  if (!session) {
    throw new Error(`Missing bootstrap session for ${space}`);
  }
  return session;
}

function authorizationHeader(headers: Record<string, string>): string {
  const value = headers.Authorization ?? headers.authorization;
  if (!value) {
    throw new Error('Invocation headers did not include Authorization');
  }
  return value;
}

async function rewriteInvocationAudience(
  authorization: string,
  audience: string,
  jwk: Record<string, unknown> | Map<string, unknown>,
): Promise<string> {
  const [headerPart, payloadPart] = authorization.split('.');
  if (!headerPart || !payloadPart) {
    throw new Error('Invalid invocation authorization');
  }
  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerPart)));
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadPart)));
  payload.aud = audience;
  const signingInput = `${base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)))}.${base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(payload)),
  )}`;
  const signature = await signWithJwk(signingInput, jwk);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export function sessionJwkForSigning(
  jwk: Record<string, unknown> | Map<string, unknown>,
): Record<string, unknown> {
  return jwk instanceof Map ? Object.fromEntries(jwk) : jwk;
}

async function signWithJwk(
  signingInput: string,
  sessionJwk: Record<string, unknown> | Map<string, unknown>,
): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(signingInput);
  const jwk = sessionJwkForSigning(sessionJwk);
  try {
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, key, bytes));
  } catch {
    const nodeCrypto = await import('node:crypto');
    const key = nodeCrypto.createPrivateKey({ key: jwk as any, format: 'jwk' });
    return new Uint8Array(nodeCrypto.sign(null, Buffer.from(bytes), key));
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function canonicalHashHex(value: unknown): string {
  return Buffer.from(vault_sha256(new TextEncoder().encode(canonicalizeJson(value)))).toString('hex');
}

function canonicalizeJson(value: unknown): string {
  return JSON.stringify(sortJsonValue(value));
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }
  if (!value || typeof value !== 'object') {
    return value;
  }

  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = sortJsonValue((value as Record<string, unknown>)[key]);
  }
  return sorted;
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
