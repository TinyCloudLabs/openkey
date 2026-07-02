import {
  ACCOUNT_REGISTRY_SPACE,
  BOOTSTRAP_ALLOWLIST,
  BOOTSTRAP_ENCRYPTION_NETWORK_NAME,
  BOOTSTRAP_MANIFEST,
  BOOTSTRAP_SPACE_NAMES,
  SECRETS_SPACE,
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
import {
  activateSessionWithHost,
  fetchPeerId,
  submitHostDelegation,
} from '@tinycloud/sdk-core';

export const TINYCLOUD_BOOTSTRAP_VERSION = `@tinycloud/bootstrap:${canonicalHashHex({
  allowlist: BOOTSTRAP_ALLOWLIST,
  manifest: BOOTSTRAP_MANIFEST,
})}`;
const DEFAULT_TINYCLOUD_BOOTSTRAP_HOST = 'https://node.tinycloud.xyz';
const TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS = new Set([
  DEFAULT_TINYCLOUD_BOOTSTRAP_HOST,
  'https://tee.node.tinycloud.xyz',
]);
const SUPPORTED_TINYCLOUD_CHAIN_IDS = new Set([1]);
const BOOTSTRAP_LOCK_TTL_MS = 2 * 60 * 1000;
const BOOTSTRAP_LOCK_REFRESH_MS = 30 * 1000;
const BOOTSTRAP_WAIT_MS = 500;
const MIN_USEFUL_SIWE_TTL_MS = 5_000;
const BOOTSTRAP_DOMAIN = 'cli.tinycloud.xyz';
const NETWORK_CREATE_ACTION = 'tinycloud.encryption/network.create';
const NETWORK_ADMIN_TYPE = 'tinycloud.encryption.network-admin/v1';

type PrismaLike = {
  user: {
    findUnique(args: unknown): Promise<{ autoSignEnabled: boolean } | null>;
  };
  tinyCloudBootstrapState: {
    findUnique(args: unknown): Promise<BootstrapStateRecord | null>;
    create(args: unknown): Promise<BootstrapStateRecord>;
    updateMany(args: unknown): Promise<{ count: number }>;
  };
};

interface BootstrapStateRecord {
  id: string;
  status: string;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
}

export interface TinyCloudBootstrapKey {
  id: string;
  address: string;
  keyType?: string;
}

export interface EnsureTinyCloudBootstrapInput {
  prisma: PrismaLike;
  userId: string;
  key: TinyCloudBootstrapKey;
  privateKey: string;
  message: string;
  format: 'raw' | 'personal_sign';
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

type TinyCloudBootstrapExecutor = (input: {
  address: string;
  chainId: number;
  privateKey: string;
  tinycloudHost: string;
}) => Promise<void>;

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
    entry.actions.includes('tinycloud.capabilities/read')
  ) || (
    entry.service === 'kv' &&
    (entry.path === 'applications/' || entry.path === 'spaces/') &&
    hasAnyAction(entry.actions, ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/put'])
  ) || (
    entry.service === 'sql' &&
    entry.path === 'account' &&
    hasAnyAction(entry.actions, ['tinycloud.sql/read', 'tinycloud.sql/schema', 'tinycloud.sql/write'])
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

  const cacheKey = {
    keyId: input.key.id,
    chainId: parsed.chainId,
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
    chainId: parsed.chainId,
    tinycloudHost,
  });

  if (!locked) {
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

  try {
    await withBootstrapLockHeartbeat(input.prisma, cacheKey, attemptId, async () => {
      await bootstrapProbe({
        address: ensureEip55(input.key.address),
        chainId: parsed.chainId,
        privateKey: input.privateKey,
        tinycloudHost,
      });

      await bootstrapExecutor({
        address: ensureEip55(input.key.address),
        chainId: parsed.chainId,
        privateKey: input.privateKey,
        tinycloudHost,
      });
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
    await input.prisma.tinyCloudBootstrapState.updateMany({
      where: { ...cacheKey, attemptId },
      data: {
        status: 'failed',
        checkedAt: new Date(),
        failureCode: 'tinycloud_bootstrap_failed',
        failureReason: reason,
        lockExpiresAt: null,
      },
    });
    return {
      status: 'failed',
      errorCode: 'tinycloud_bootstrap_failed',
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
    data: {
      status: 'in_progress',
      attemptId: input.attemptId,
      lockExpiresAt,
      checkedAt: now,
      failureCode: null,
      failureReason: null,
    },
  });

  return result.count === 1;
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

async function probeTinyCloudBootstrap(input: {
  address: string;
  chainId: number;
  privateKey: string;
  tinycloudHost: string;
}): Promise<void> {
  const accountStep = bootstrapSteps(input.address, input.chainId)
    .find((step): step is BootstrapSpaceStep => step.kind === 'session' && step.space === ACCOUNT_REGISTRY_SPACE);
  if (!accountStep) {
    throw new Error('TinyCloud bootstrap account session policy is missing');
  }

  const session = await createBootstrapSession(input, accountStep);
  const activation = await activateSessionWithHost(input.tinycloudHost, session.session.delegationHeader);
  if (!activation.success || activation.skipped?.includes(session.spaceId)) {
    return;
  }

  await invokeRaw(input.tinycloudHost, session, 'capabilities', '', 'tinycloud.capabilities/read');
}

async function runTinyCloudBootstrap(input: {
  address: string;
  chainId: number;
  privateKey: string;
  tinycloudHost: string;
}): Promise<void> {
  const steps = bootstrapSteps(input.address, input.chainId);
  const sessionSteps = steps.filter(isSessionStep);
  const hostSteps = steps.filter((step): step is BootstrapSpaceStep => step.kind === 'host');

  const [sessions, hostDelegations] = await Promise.all([
    Promise.all(sessionSteps.map((step) => createBootstrapSession(input, step))),
    Promise.all(hostSteps.map((step) => createHostDelegation(input, step))),
  ]);

  await Promise.all(hostDelegations.map((headers) => submitRequiredHostDelegation(input.tinycloudHost, headers)));
  await Promise.all(sessions.map((session) => activateRequiredSession(input.tinycloudHost, session)));

  const sessionBySpace = new Map(sessions.map((session) => [session.space, session]));
  const accountSession = requiredSession(sessionBySpace, ACCOUNT_REGISTRY_SPACE);
  const secretsSession = requiredSession(sessionBySpace, SECRETS_SPACE);

  await Promise.all([
    runAccountSchema(input.tinycloudHost, accountSession, steps),
    seedBootstrapSpaces(input.tinycloudHost, accountSession, input.address, input.chainId),
    seedBootstrapApplications(input.tinycloudHost, accountSession, steps),
  ]);

  await Promise.all([
    ensureEncryptionNetwork(input.tinycloudHost, accountSession, input.address, input.chainId),
    runSecretRecordsSchema(input.tinycloudHost, secretsSession, steps),
  ]);
}

function isSessionStep(step: BootstrapStep): step is BootstrapSpaceStep {
  return step.kind === 'session';
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
  const signature = await signEthereumMessage(input.privateKey, prepared.siwe);
  const session = completeSessionSetup({ ...prepared, signature });
  return { space: step.space, spaceId: step.spaceId, session };
}

async function createHostDelegation(
  input: { address: string; chainId: number; privateKey: string; tinycloudHost: string },
  step: BootstrapSpaceStep,
): Promise<Record<string, string>> {
  const peerId = await fetchPeerId(input.tinycloudHost, step.spaceId);
  const siwe = generateHostSIWEMessage({
    address: input.address,
    chainId: input.chainId,
    domain: BOOTSTRAP_DOMAIN,
    issuedAt: new Date().toISOString(),
    spaceId: step.spaceId,
    peerId,
  });
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

async function submitRequiredHostDelegation(host: string, headers: Record<string, string>): Promise<void> {
  const result = await submitHostDelegation(host, headers);
  if (!result.success) {
    throw new Error(`Failed to submit host delegation: ${result.error ?? 'unknown error'}`);
  }
}

async function activateRequiredSession(host: string, session: BootstrapSession): Promise<void> {
  const result = await activateSessionWithHost(host, session.session.delegationHeader);
  if (!result.success || result.skipped?.includes(session.spaceId)) {
    throw new Error(
      `Failed to activate bootstrap session for ${session.space}: ${result.error ?? 'space was skipped'}`,
    );
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
      action: 'tinycloud.sql/schema',
    },
    {
      spaceId: session.spaceId,
      service: 'sql',
      path: database,
      action: 'tinycloud.sql/write',
    },
  ], {
    action: 'execute',
    sql: 'SELECT 1',
    params: [],
    schema: [...schema],
  });
}

async function seedBootstrapSpaces(
  host: string,
  session: BootstrapSession,
  address: string,
  chainId: number,
): Promise<void> {
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
  await Promise.all(BOOTSTRAP_SPACE_NAMES.map((name) => invokeRaw(
    host,
    session,
    'kv',
    `spaces/${name}`,
    'tinycloud.kv/put',
    JSON.stringify({
      name,
      space_id: `tinycloud:pkh:eip155:${chainId}:${address}:${name}`,
      owner_did: ownerDid,
      type: name === 'public' ? 'public' : 'private',
      status: 'active',
      updated_at: new Date().toISOString(),
    }),
  )));
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
    'tinycloud.kv/put',
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
  const existing = await fetch(`${host}/encryption/networks/${encodeURIComponent(networkId)}`);
  if (existing.ok) {
    return;
  }
  if (existing.status !== 404) {
    throw new Error(`Failed to check encryption network ${networkId}: HTTP ${existing.status}`);
  }

  const info = await fetch(`${host}/info`);
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
  const created = await fetch(`${host}/encryption/networks`, {
    method: 'POST',
    headers: {
      Authorization: authorization,
      'Content-Type': 'application/json',
    },
    body: canonicalizeJson(body),
  });
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
  const response = await fetch(`${host}/invoke`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
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
  const headers = invoke(session.session, service, path, action, undefined) as Record<string, string>;
  const response = await fetch(`${host}/invoke`, {
    method: 'POST',
    headers: { ...headers, ...extraHeaders },
    body,
  });
  if (!response.ok) {
    throw new Error(`TinyCloud ${service}/${path} ${action} failed: HTTP ${response.status} ${await response.text()}`);
  }
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
  jwk: Record<string, unknown>,
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

async function signWithJwk(signingInput: string, jwk: Record<string, unknown>): Promise<Uint8Array> {
  const bytes = new TextEncoder().encode(signingInput);
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
