import { HTTPException } from 'hono/http-exception';
import { currentReviewerDelegate, reviewerSessionDid, assertReviewerSignedDelegation } from '../services/reviewer-delegation';
import { reviewerForUser } from '../services/reviewer-accounts';
import { isAccountOriginAllowed } from '../origin-policy';
// Delegate route - creates TinyCloud delegation for CLI auth flow
import { randomBytes, randomUUID } from 'node:crypto';
import { Hono, type Context } from 'hono';
import { routePath } from 'hono/route';
import { createPrismaClient } from '@openkey/db';
import { createTeeClient } from '@openkey/tee';
import { bearerFromAccountOriginError } from '../middleware/bearer-origin';
import { requireSession } from '../middleware/session';
import {
  createDelegateSignerAuth,
  type DelegateSignerContext,
} from '../middleware/delegate-signer-auth';
import { withTinyCloudManageKeySigningPolicy } from '../services/tinycloud-manage-key-control';
import type { Hex } from 'viem';
import { verifyMessage } from 'ethers';
import {
  prepareSession,
  completeSessionSetup,
  ensureEip55,
  generateHostSIWEMessage,
  makeSpaceId,
  siweToDelegationHeaders,
} from '@tinycloud/node-sdk-wasm';
import { buildOwnerRevocationSiwe, parseSiweFields, siweExpirationTime } from '@openkey/capability-review';
import {
  canonicalizeServiceName,
  entriesForSelectedActions,
  permissionKey as computePermissionKey,
} from './delegate-session';
import { activateSessionWithinTimeout } from '../services/tinycloud-node-timeouts';
import { isTinyCloudSiweForSigner, ownBootstrapSpaceName, parseTinyCloudSiwe, requestedOwnSpaceForSiwe, spaceHostRequest } from '../services/tinycloud-siwe';
import { HOST_SIGNING_FIRST_PARTY_ONLY, HOST_SIGNING_FIRST_PARTY_ONLY_MESSAGE, refusesThirdPartySpaceHost } from '../services/space-host-signing';
import type { SpaceHostResult } from '@tinycloud/sdk-core';
import { BOOTSTRAP_SPACE_NAMES, CAPABILITIES } from '@tinycloud/bootstrap';
import {
  DelegateRequestError,
  delegateErrorResponse,
  normalizeDelegateReason,
} from './delegate-validation';
import {
  ownFolderSessionAbilities,
  SIWE_DOMAIN,
  sessionAbilitiesFromPermissions,
  validatePermissions,
  actionKey as computeActionKey,
  assertBaselineSubset,
  assertRequiredActions,
  isRequiredAction,
  normalizeStringArray,
  parsePreparedRecap,
  reportedEntry,
  prepareDelegationSession,
  type DelegationJwk,
  delegationSpaces,
  primaryRoutingSpace,
  type RequestedDelegationSpace,
  type DelegationPermissionEntry,
  type RecapEntry,
  type SessionAbilities,
} from './delegate-session';
import { countPrivateSessionJwk, log, logError, logMetric, logSessionJwk, recordAccountOriginRefused } from '../log';

// Re-export the pure delegation helpers so existing external test files
// (e.g. delegate-oauth-route.test.ts) that import them from this module
// keep working.
export {
  prepareDelegationSession,
  assertBaselineSubset,
} from './delegate-session';
import {
  evaluateAutoSignPolicy,
  evaluateBootstrapSigningScope,
} from './delegate-autosign';
import {
  checkAuthorizationContext,
  consumeCheckedAuthorizationContext,
  checkPreviewApproval,
  digestAbilities,
  digestFullRecapAttenuation,
  digestImmutableFields,
  extractRecapAttenuationFromSiwe,
  issueAuthorizationContext,
  issuePreviewApproval,
  peekAuthorizationContext,
  peekPreviewApprovalExpiry,
  hasPrivateJwkMember,
  publicJwk,
  type AuthorizationContextToken,
  type AuthorizationContextClaim,
  type BoundRenewalChoice,
} from '../services/authorization-signing';
import { MIN_DELEGATION_EXPIRY_MS, MIN_EXPIRATION_LEAD_MS, siweBroadOnceTier, validateExpirationOverride, withExpirationTime } from '../services/approval-expiry';
import { narrowSiwePreservingImmutable } from '../services/siwe-narrow';
import { checkSignedSubset, parseStrictSiwe, SIGNED_SUBSET_REFUSAL_CODE } from '../services/signed-subset';
import { checkSiweOrigin } from '../services/siwe-origin';
import { invalidSiweMessage } from '../services/siwe-message-refusal';
import {
  APP_KEY_GROUP_PARTIAL_CODE,
  APP_KEY_GROUP_PARTIAL_MESSAGE,
  admittedAppKeyActionIds,
  appKeyGroupPartial,
  appKeyRefusalBody,
  appKeyRefusalCode,
  appKeyRefusalForSiwe,
  blockResourcesOutsideApps,
  exactShareKeyRefusal,
  appKeyRefusalMessage,
  appKeyRefusalStatus,
  appKeyResourcesOf,
  type AdmittedAppKey,
  UNREADABLE_RECAP_MESSAGE,
} from '../services/app-key-refusal';
import {
  SECRET_GRANT_MAX_MS,
  SECRET_LIFETIME_CODE,
  clampSecretExpiryMs,
  exceedsSecretLifetime,
  secretCapExpirationTime,
  secretLifetimeBody,
  secretLifetimeMessage,
} from '../services/secret-lifetime';
import { allowedElevatedIds, elevatedDecided, elevatedNotDecidedBody } from '../services/elevated-decision';
import { elevatedActionsOf } from '@openkey/capability-review';
import { admitAppKeys, appIdForOrigin, appKeyAdmissionRefusal, type ManifestKeys } from '../services/app-key-gate';
import { fetchAndBindWellKnownManifest } from '../services/manifest-origin-fetch';
import { signManagedKey, unsealManagedKey } from '../services/managed-key-signing';
import {
  canonicalizeCoordinationosOrigin,
  evaluateCoordinationosSessionRequest,
  sha256Hex,
  type CoordinationosPolicyEvidence,
} from '../services/coordinationos-session-policy';
import {
  consumeCoordinationosGrant,
  coordinationosDenialResponse,
  coordinationosStatus,
  recordCoordinationosDenial,
  recordCoordinationosSignerError,
  sparseCoordinationosEvidence,
  type CoordinationosDenialCode,
} from '../services/coordinationos-signing-audit';
import { MAX_ISSUED_AT_SKEW_MS, validateTinyCloudManageKeyRequest } from '../services/tinycloud-manage-key-policy';
import { canonicalTrustedTinyCloudHost, LOCAL_HOSTNAMES } from '../services/tinycloud-hosts';
import { awaitTinyCloudBootstrapWithinBudget, hostRequestedSpaceWithinBudget, OWN_TIMEOUT_BUDGET_MS } from '../services/tinycloud-bootstrap-budget';
import {
  mayProvision,
  oauthClientProvisionAuthority,
  originProvisionAuthority,
  ownPageProvisionAuthority,
  UNATTRIBUTED_PROVISION_AUTHORITY,
  type ProvisionAuthority,
} from '../services/provision-authority';
import { classifyDelegateLinkDelivery, type DelegateLinkDelivery } from '../services/delegate-link-delivery';
import { checkDeviceDelegationWindow, deviceDelegationWindowError, deviceTransactionUnsupportedError } from './device-delegation-window';
import { isPrimaryKey, primaryKeyWhere } from '../services/primary-key';
import { PreparedHandoffError } from '../services/prepared-handoff';
import { preparedHandoffService } from './prepared-handoffs';
import { normalizeAppOrigin, recordAppSignIn } from '../services/app-sign-in';
import type { PreparedHandoffService } from '../services/prepared-handoff';
import { admitApprovalDelegation, bindApprovalRenewal, checkApprovalDelegation, checkApprovalLeaseGrant, confirmBoundRenewal, releaseApprovalDelegation, saveApprovalDelegation } from './approval-requests';
import { ApprovalResultError } from '../services/approval-results';
import { bindSignInRenewalRequest, recordedSignInLease, setUpSignInLease, signInRenewalFailure, takePendingSignInLease, type SignInLease } from '../services/signin-renewal';
import type { SignInRenewalRequest } from '../services/authorization-signing';
import { assertLeaseableGrant, parseRenewalChoice, RenewalLeaseError, renewalLeasesEnabled, renewalUnavailableMessage, signLease } from '../services/renewal-lease';
import {
  approvalPasskeyOffer,
  approvalPasskeyOfferInFlow,
  approvalRequestDigest,
  checkApprovalPasskey,
  checkApprovalPasskeySpendingFlow,
  clearFlowPasskey,
  FLOW_PASSKEY_HEADER,
  messageApprovalSensitivity,
  passkeyApprovalModes,
  releaseFlowPasskey,
  webFlowIdFromHeader,
  type ApprovalBinding,
} from '../services/approval-passkey';

/**
 * TC-3442: a passkey on an authorize-sign approval confirms this authorization context, these exact bytes and the
 * preview-approval token, which seals everything else the approval acts on (selection, elevated choices, renewal).
 */
function authorizeSignPasskeyBinding(
  authorizationContextToken: string, previewApprovalToken: string, keyAddress: string, signedMessage: string,
): ApprovalBinding {
  return {
    purpose: 'authorize_sign',
    requestDigest: approvalRequestDigest(authorizationContextToken, previewApprovalToken, keyAddress.toLowerCase(), signedMessage),
  };
}

/** TC-3442: a passkey on a managed approval (POST /api/delegate) confirms the context /prepare bound and its bytes. */
function delegatePasskeyBinding(authorizationContextToken: string, keyAddress: string, originalSiwe: string): ApprovalBinding {
  return {
    purpose: 'delegate',
    requestDigest: approvalRequestDigest(authorizationContextToken, keyAddress.toLowerCase(), originalSiwe),
  };
}

let activePreparedHandoffService: PreparedHandoffService = preparedHandoffService;
async function revokeActivatedManagedDelegation(
  host: string,
  key: Parameters<typeof signManagedKey>[0],
  sealedBlob: string,
  ownerDid: string,
  delegationCid: string,
): Promise<void> {
  const now = new Date();
  try {
    const siwe = buildOwnerRevocationSiwe({
      kind: 'owner-revocation',
      ownerDid,
      cid: delegationCid,
      nonce: randomBytes(16).toString('hex'),
      expiresAt: new Date(now.getTime() + 600_000).toISOString(),
    }, SIWE_DOMAIN, now);
    const signature = await signManagedKey(key, sealedBlob, siwe);
    const response = await fetch(`${host.replace(/\/+$/, '')}/revoke`, {
      method: 'POST',
      headers: siweToDelegationHeaders({ siwe, signature }) as Record<string, string>,
      redirect: 'error',
      signal: AbortSignal.timeout(5_000),
    });
    if (!response.ok) {
      logMetric('warn', 'delegate_session_revoke_failed', { status: response.status });
      return;
    }
    const result: unknown = await response.json().catch(() => null);
    if (!result || typeof result !== 'object' ||
        !('revoked' in result) || result.revoked !== true ||
        !('cid' in result) || result.cid !== delegationCid) {
      logMetric('warn', 'delegate_session_revoke_failed', { status: response.status });
    }
  } catch (error) {
    logError('warn', 'delegate_session_revoke_failed', error);
  }
}

export function setPreparedHandoffServiceForTests(service: PreparedHandoffService): void {
  activePreparedHandoffService = service;
}

const prisma = createPrismaClient();
const tee = createTeeClient();

type SpaceSetupPlan = 'setup' | 'auto-sign-off' | 'external-wallet';
type BootstrapSpaceName = (typeof BOOTSTRAP_SPACE_NAMES)[number];
type ManagedSpaceSetup = { space: BootstrapSpaceName; plan: SpaceSetupPlan; bootstrapHost: string };

async function managedSpaceSetupPlan(input: {
  userId: string;
  keyType: string;
  host: string;
  address: string;
  chainId: number;
  spaceId: string;
}): Promise<ManagedSpaceSetup | null> {
  const name = ownBootstrapSpaceName(input.spaceId, input.address, input.chainId);
  if (!name) return null;

  const { trustedTinyCloudBootstrapHost } = await import('../services/tinycloud-bootstrap');
  // TC-943: Courier and node-sdk send the tee.node alias of the configured node.
  const bootstrapHost = canonicalTrustedTinyCloudHost(input.host, trustedTinyCloudBootstrapHost());
  if (!bootstrapHost) return null;
  if (input.keyType !== 'MANAGED') return { space: name, plan: 'external-wallet', bootstrapHost };

  const preference = await prisma.user.findUnique({
    where: { id: input.userId },
    select: { autoSignEnabled: true },
  });
  return { space: name, plan: preference?.autoSignEnabled ? 'setup' : 'auto-sign-off', bootstrapHost };
}

/**
 * Hosts a managed account at the node for the sign-in message the owner approved: the same hook, with the same
 * budget, as POST /api/keys/:id/sign (TC-1608). web-sdk 3.13 does not bootstrap an interactive signer, so nothing
 * else would host a brand-new account. The hook decides what is hosted (the account space's own entries, or the
 * signer's own space the message names) and is idempotent: a complete account answers `complete`. It never
 * withholds the signature: a failure is logged and the setup sweep retries it.
 */
async function bootstrapApprovedManagedSignIn(input: {
  userId: string;
  key: { id: string; userId: string | null; address: string; keyType: string; sealedBlob: string | null; sealingContext?: string | null };
  message: string;
  /** Who asked, as the server bound it to the approved request. */
  authority: ProvisionAuthority;
}): Promise<void> {
  try {
    if (process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN === 'off' || !input.key.sealedBlob) return;
    // The cheap refusals come first, so a message the hook would skip does not unseal the key.
    const siwe = parseTinyCloudSiwe(input.message);
    if (siwe === null || !isTinyCloudSiweForSigner(siwe, input.key.address)) return;
    const { ensureTinyCloudBootstrapForApprovedSign } = await import('../services/tinycloud-bootstrap');
    const sealedBlob = input.key.sealedBlob;
    // A sign-in that names one of the signer's own spaces (and no account-space entry) waits for that space instead,
    // bounded by the requested-space timeout inside the bootstrap.
    const waitsForOwnSpace = requestedOwnSpaceForSiwe(siwe, input.key.address) !== null;
    const bootstrap = await awaitTinyCloudBootstrapWithinBudget(
      ensureTinyCloudBootstrapForApprovedSign({
        prisma,
        userId: input.userId,
        key: { id: input.key.id, address: input.key.address, keyType: input.key.keyType },
        privateKey: () => unsealManagedKey(input.key, sealedBlob),
        message: input.message,
        format: 'personal_sign',
        authority: input.authority,
      }),
      waitsForOwnSpace ? { budgetMs: OWN_TIMEOUT_BUDGET_MS, ownLogsBackground: true } : {},
    );
    if (bootstrap.status === 'failed') {
      log('error', 'tinycloud_bootstrap_failed', bootstrap.errorCode);
    }
  } catch {
    // The signature is already made and any lease recorded: nothing here may turn it into an error.
    log('error', 'tinycloud_bootstrap_failed', 'tinycloud_bootstrap_crashed');
  }
}

type SpaceReadiness = { spaceReady: boolean | null; spaceError?: string; spacePending?: true };
type RequestedSpaceReadiness = RequestedDelegationSpace & SpaceReadiness;
type DelegationReadiness = SpaceReadiness & { requestedSpaces: RequestedSpaceReadiness[] };
type SpaceActivation = SpaceHostResult & { hostNotKnown?: true };

function aggregateSpaceReadiness(requestedSpaces: RequestedSpaceReadiness[]): DelegationReadiness {
  const spaceReady = requestedSpaces.some(space => space.spaceReady === false) ? false
    : requestedSpaces.some(space => space.spaceReady === null) ? null : true;
  const error = requestedSpaces.find(space => space.spaceError)?.spaceError;
  return {
    requestedSpaces, spaceReady,
    ...(requestedSpaces.some(space => space.spacePending) ? { spacePending: true as const } : {}),
    ...(error ? { spaceError: error } : {}),
  };
}

/** An empty activation receipt (already-known delegation) is not proof of hosting. */
function activationReadiness(spaces: RequestedDelegationSpace[], entries: RecapEntry[], activation?: SpaceActivation): DelegationReadiness {
  const granted = new Set(delegationSpaces(entries).map(space => space.spaceId));
  return aggregateSpaceReadiness(spaces.map(space => ({
    ...space,
    spaceReady: !granted.has(space.spaceId) || activation?.hostNotKnown ? false
      : activation?.success && activation.activated?.includes(space.spaceId) ? true
      : activation?.success && activation.skipped?.includes(space.spaceId) ? false : null,
  })));
}

/** `spaceError` when the approval's space was still being hosted at the timeout. */
const REQUESTED_SPACE_TIMEOUT_ERROR = 'tinycloud_requested_space_timeout';

function setupFailureMessage(failure: { errorCode: string; errorMessage: string }): string {
  return failure.errorCode === 'tinycloud_bootstrap_crashed'
    ? `TinyCloud account setup failed: ${failure.errorMessage}.`
    : `TinyCloud account setup failed (${failure.errorCode}): ${failure.errorMessage}.`;
}

/**
 * Who asked, for an approval whose context this session's user spent just before this call. The sealed
 * `requestOrigin` counts when it is first-party. Otherwise the three approvals the owner makes on OpenKey's own page
 * count, and only from state the server holds: the context is bound to the same user as the session, and the
 * approval request, the device request or the sealed link delivery is read again here, not trusted from the body.
 * Any failure to confirm one is the same as not being first-party.
 */
async function boundProvisionAuthority(input: {
  bound: {
    userId: string;
    originalSiwe: string;
    requestOrigin?: string;
    approvalRequestId?: string;
    deviceTransactionId?: string;
    linkDelivery?: DelegateLinkDelivery;
  };
  sessionUserId: string;
  body: { approvalRequestId?: unknown; deviceTransactionId?: unknown; jwk: unknown; host: unknown; permissions?: unknown };
  host: string;
}): Promise<ProvisionAuthority> {
  const { bound, body } = input;
  const byOrigin = originProvisionAuthority(bound.requestOrigin);
  if (mayProvision(byOrigin)) return byOrigin;
  if (bound.userId !== input.sessionUserId) return UNATTRIBUTED_PROVISION_AUTHORITY;
  try {
    if (bound.approvalRequestId !== undefined) {
      if (body.approvalRequestId !== bound.approvalRequestId) return UNATTRIBUTED_PROVISION_AUTHORITY;
      // Still pending, unexpired and bound to this session key, node and permissions.
      await checkApprovalDelegation(body, { signedSiwe: bound.originalSiwe });
      return ownPageProvisionAuthority('approval-request');
    }
    if (bound.deviceTransactionId !== undefined) {
      if (body.deviceTransactionId !== bound.deviceTransactionId) return UNATTRIBUTED_PROVISION_AUTHORITY;
      const refusal = await deviceDelegationWindowError(body, { host: input.host, signedSiwe: bound.originalSiwe });
      return refusal ? UNATTRIBUTED_PROVISION_AUTHORITY : ownPageProvisionAuthority('device-approval');
    }
    return bound.linkDelivery ? ownPageProvisionAuthority('delegate-link-local') : UNATTRIBUTED_PROVISION_AUTHORITY;
  } catch (error) {
    logError('warn', 'delegate_own_page_authority_unconfirmed', error);
    return UNATTRIBUTED_PROVISION_AUTHORITY;
  }
}

/**
 * The authority of an approval, asked at /prepare for a request that has just been validated: an expired, denied or
 * changed approval request or device request was refused before this point, so what is left to decide is which case
 * this is. Every other link is unattributed. `boundProvisionAuthority` ends in the same decision at approval.
 */
function approvalProvisionAuthority(input: { approvalRequest: boolean; device: boolean; linkDelivery: boolean }): ProvisionAuthority {
  const approval = input.approvalRequest ? 'approval-request' : input.device ? 'device-approval' : input.linkDelivery ? 'delegate-link-local' : null;
  return approval === null ? UNATTRIBUTED_PROVISION_AUTHORITY : ownPageProvisionAuthority(approval);
}

/** Will approving this request set the account up? Only for the approvals that are on (`approvalProvisionAuthority`). */
function approvalSetsUpAccount(input: { approvalRequest: boolean; device: boolean; linkDelivery: boolean }): boolean {
  return mayProvision(approvalProvisionAuthority(input));
}

const HOST_SIGNING_REFUSAL_BODY = { error: HOST_SIGNING_FIRST_PARTY_ONLY_MESSAGE, code: HOST_SIGNING_FIRST_PARTY_ONLY } as const;

/**
 * The rule of POST /api/keys/:id/sign for a message this route has OpenKey's managed key sign (`refusesThirdPartySpaceHost`).
 * An external wallet signs its own message, so there is nothing for OpenKey to refuse. The authority is read only for a
 * message that hosts a space: every other approval reads nothing more than it did before.
 */
async function refusesSpaceHost(input: {
  message: string;
  key: { id: string; address: string; keyType: string };
  authority: () => ProvisionAuthority | Promise<ProvisionAuthority>;
  noBoundContext?: true;
}): Promise<boolean> {
  if (input.key.keyType !== 'MANAGED' || spaceHostRequest(input.message).kind === 'none') return false;
  return refusesThirdPartySpaceHost({
    prisma, message: input.message, key: input.key, authorities: [await input.authority()],
    ...(input.noBoundContext ? { noBoundContext: true as const } : {}),
  });
}

async function finishManagedSpaceOnboarding(input: {
  userId: string;
  key: {
    id: string;
    userId: string | null;
    address: string;
    keyType: string;
    sealedBlob: string | null;
    sealingContext?: string | null;
  };
  privateKey?: string;
  host: string;
  address: string;
  chainId: number;
  requestedSpaces: RequestedDelegationSpace[];
  entries: RecapEntry[];
  activation: SpaceActivation;
  /** Who asked, as the server bound it to the approved request. */
  authority: ProvisionAuthority;
}): Promise<DelegationReadiness> {
  const initial = activationReadiness(input.requestedSpaces, input.entries, input.activation);
  const granted = new Set(delegationSpaces(input.entries).map(space => space.spaceId));
  const awaiting = initial.requestedSpaces.filter(space => granted.has(space.spaceId) && space.spaceReady !== true);
  if (awaiting.length === 0) return initial;
  // Only TinyCloud's own apps make OpenKey set up the account on the node here; the node is not asked for anyone else.
  if (!mayProvision(input.authority)) return initial;
  const setupSpaces = new Set<string>();
  let readiness: SpaceReadiness;

  try {
    const { ensureTinyCloudBootstrap } = await import('../services/tinycloud-bootstrap');
    const setups: ManagedSpaceSetup[] = [];
    for (const space of awaiting) {
      const setup = await managedSpaceSetupPlan({
        userId: input.userId, keyType: input.key.keyType, host: input.host,
        address: input.address, chainId: input.chainId, spaceId: space.spaceId,
      });
      if (setup?.plan === 'setup') {
        setups.push(setup);
        setupSpaces.add(space.spaceId);
      }
    }
    if (setups.length === 0) return initial;
    if (!input.privateKey && !input.key.sealedBlob) {
      throw new Error('Managed key has no sealed key data');
    }
    // The first run uses this key and drops it; each background retry unseals again, so the
    // plaintext key is never held across a retry's wait.
    let firstRunKey: string | undefined = input.privateKey ?? await unsealManagedKey(input.key, input.key.sealedBlob!);
    const result = await hostRequestedSpaceWithinBudget(async ({ alreadyHosted, report }) => {
      const privateKey = firstRunKey ?? await unsealManagedKey(input.key, input.key.sealedBlob!);
      firstRunKey = undefined;
      return ensureTinyCloudBootstrap({
        prisma,
        userId: input.userId,
        key: { id: input.key.id, address: input.key.address, keyType: input.key.keyType },
        privateKey,
        host: setups[0]!.bootstrapHost,
        chainId: input.chainId,
        // Confirm every unresolved requested space before replying. Seeding and other spaces follow.
        requestedSpaces: { spaces: setups.map(setup => setup.space), alreadyHosted, nodeReportedUnhosted: true, report },
        authority: input.authority,
      });
    });
    switch (result.status) {
      case 'hosted':
      case 'complete':
        readiness = { spaceReady: true }; break;
      // Another run holds the lock (an approval's or the sweep's) and will host the space: keep waiting.
      case 'pending':
        readiness = { spaceReady: null, spacePending: true, spaceError: result.errorCode }; break;
      case 'timeout':
        readiness = { spaceReady: null, spacePending: true, spaceError: REQUESTED_SPACE_TIMEOUT_ERROR }; break;
      case 'skipped':
        readiness = { spaceReady: false, spaceError: 'TinyCloud account setup failed.' }; break;
      // The first run failed and a background retry is scheduled: keep the client waiting with the reason.
      case 'retrying':
        readiness = { spaceReady: null, spacePending: true, spaceError: setupFailureMessage(result) }; break;
      case 'failed':
        readiness = { spaceReady: false, spaceError: setupFailureMessage(result) }; break;
    }
  } catch (error) {
    for (const space of awaiting) setupSpaces.add(space.spaceId);
    readiness = {
      spaceReady: false,
      spaceError: `TinyCloud account setup failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
  return aggregateSpaceReadiness(initial.requestedSpaces.map(space =>
    setupSpaces.has(space.spaceId) ? { ...space, ...readiness } : space,
  ));
}

// A session that has not accepted the current Terms gets the session check's own 403 `terms_required`, so the
// page signing with it sends the account to the Terms screen; no session falls through to missing_authorization.
async function resolveBetterAuthSession(c: any): Promise<boolean | Response> {
  let resolved = false;
  const refusal = await (requireSession as any)(c, async () => {
    resolved = true;
  });
  if (resolved) return true;
  return refusal instanceof Response && refusal.status === 403 ? refusal : false;
}

const defaultDelegateSignerAuth = createDelegateSignerAuth({
  database: prisma,
  resolveSession: resolveBetterAuthSession,
});
let activeDelegateSignerAuth = defaultDelegateSignerAuth;

export function setDelegateSignerAuthMiddlewareForTests(
  middleware = defaultDelegateSignerAuth,
): void {
  activeDelegateSignerAuth = middleware;
}

export const delegateRouter = new Hono<DelegateSignerContext>();
delegateRouter.onError((error, c) => {
  if (error instanceof HTTPException) return error.getResponse();
  if (error instanceof PreparedHandoffError) return c.json({ code: error.code, error: error.message }, error.status);
  if (error instanceof ApprovalResultError) return c.json({ code: error.code, error: error.message }, error.status);
  throw error;
});

const DEVICE_RENEWAL_UNAVAILABLE = "Renewal isn't available for this sign-in. You can approve it without renewal.";

function assertDevicePreviewTransaction(boundId: string | undefined, suppliedId: unknown) {
  if (boundId !== suppliedId) {
    throw new ApprovalResultError('request_binding', 'The device request must match the consent preview.', 400);
  }
}

function handoffTicket(body: { ticket?: unknown; transportVersion?: unknown; callback?: unknown; delivery?: unknown; state?: unknown }): string | null {
  if (body.transportVersion !== undefined && body.transportVersion !== 2) {
    throw new PreparedHandoffError('invalid_transport_version', 'Unsupported handoff transport version', 400);
  }
  if (body.ticket === undefined) {
    if (body.transportVersion === 2) throw new PreparedHandoffError('missing_ticket', 'Prepared handoff ticket is required', 400);
    return null;
  }
  if (typeof body.ticket !== 'string' || !body.ticket) {
    throw new PreparedHandoffError('missing_ticket', 'Prepared handoff ticket is required', 400);
  }
  if (body.callback !== undefined || body.delivery !== undefined || body.state !== undefined) {
    throw new PreparedHandoffError('binding_mismatch', 'Delivery target is bound to the handoff', 403);
  }
  return body.ticket;
}

async function assertHandoffContext(ticket: string | null, userId: string, token: string, ticketHash?: string): Promise<void> {
  if (!ticket && ticketHash) throw new PreparedHandoffError('missing_ticket', 'Prepared handoff ticket is required', 400);
  if (!ticket) return;
  const record = await activePreparedHandoffService.assertContext(ticket, userId, token);
  if (!ticketHash || record.ticketHash !== ticketHash) {
    throw new PreparedHandoffError('binding_mismatch', 'Authorization context does not belong to handoff', 403);
  }
}

// Only the signer route accepts the narrow CoordinationOS OAuth principal.
// Every other delegate endpoint retains the existing Better Auth session gate,
// and accepts a bearer session token only from an OpenKey web origin (TC-688).
delegateRouter.use('*', async (c, next) => {
  if (c.req.path.endsWith('/sign')) {
    // The cookie-session origin check runs inside the signer middleware once
    // a session resolves; OAuth bearers stay open to any origin.
    return activeDelegateSignerAuth(c, next);
  }
  const authorization = c.req.header('authorization');
  const origin = c.req.header('origin');
  const originError = origin !== undefined
    ? (isAccountOriginAllowed(origin, 'http://localhost:5173,http://localhost:3000')
      ? null
      : 'Requests are accepted only from the OpenKey account origin')
    : bearerFromAccountOriginError(authorization, origin);
  if (originError) {
    recordAccountOriginRefused(routePath(c, -1), origin === undefined ? 'missing' : 'foreign');
    return c.json({ error: originError }, 403);
  }
  // session.ts answers `{ error: 'Unauthorized' }` to every route that uses it;
  // the delegate routes add a stable code the widget can match on.
  const refusal = await (requireSession as any)(c, next);
  if (refusal instanceof Response && refusal.status === 401) {
    return c.json({ error: 'Unauthorized', code: 'session_required' }, 401);
  }
  return refusal;
});

// Route-layer alias for the CLI permission entry shape. Keeps existing route
// bodies using their historical local type name while the actual definition
// lives in delegate-session.ts.
// This policy runs after the common session resolver and before any delegate handler.
delegateRouter.use('*', async (c, next) => {
  const user = c.get('user');
  if (!user || !await reviewerForUser(prisma, user.id)) return next();
  const binding = await currentReviewerDelegate(prisma, user.id);
  if (!binding) throw new HTTPException(403);
  const key = await prisma.ethereumKey.findFirst({
    where: { id: binding.keyId!, userId: user.id, archivedAt: null, isCanonicalTinyCloud: true },
  });
  if (!key) throw new HTTPException(403);
  if (c.req.method === 'GET' && c.req.path.endsWith('/prepare')) {
    return c.json({ key: { address: key.address, did: `did:pkh:eip155:1:${key.address}` } });
  }
  if (c.req.method !== 'POST' || !['/api/delegate', '/api/delegate/prepare', '/api/delegate/complete'].includes(c.req.path.replace(/\/$/, ''))) {
    throw new HTTPException(403);
  }
  const body = await c.req.json<Record<string, any>>();
  if (body.host !== binding.nodeHost || reviewerSessionDid(body.jwk) !== binding.sessionDid
    || (body.keyId && body.keyId !== 'reviewer' && body.keyId !== binding.keyId)
    || body.deviceTransactionId || body.approvalRequestId !== undefined || body.ticket || body.relay) {
    throw new HTTPException(403);
  }
  body.keyId = binding.keyId;
  body.prefix = 'applications';
  body.expiry = '1h';
  delete body.expiryChosen;
  delete body.linkExpiry;
  delete body.expiryChangeable;
  if (c.req.path.endsWith('/complete')) {
    await assertReviewerSignedDelegation(prisma, user.id, body.prepared?.siwe ?? '');
  } else {
    if (!Array.isArray(body.permissions) || body.permissions.length === 0) throw new HTTPException(403);
    try {
      const prepared = prepareDelegationSession({
        address: key.address, chainId: 1, prefix: 'applications', jwk: body.jwk,
        permissions: validatePermissions(body.permissions), expiryMs: 3600_000,
      });
      await assertReviewerSignedDelegation(prisma, user.id, prepared.prepared.siwe);
    } catch {
      throw new HTTPException(403);
    }
  }
  c.req.addValidatedData('json', body);
  await next();
});
delegateRouter.get('/prepare', (c) => c.json({ error: 'Forbidden' }, 403));

async function readDelegateBody<T>(c: Context): Promise<T> {
  return (c.req.valid('json' as never) as T | undefined) ?? c.req.json<T>();
}

type PermissionEntry = DelegationPermissionEntry;

interface OpenKeySigningRequestBody {
  address: string;
  chainId: number;
  message: string;
  type: 'siwe' | 'message';
  keyId?: string;
  purpose?: string;
}

/**
 * Default lifetime when callers don't specify one. Tuned to match the
 * client-side default in `@tinycloud/cli` so an agent can run unattended
 * for the same window whether it's signing locally or coming through
 * OpenKey.
 */
const DEFAULT_DELEGATION_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
/**
 * Upper bound on a link-supplied expiry for `/api/delegate` and
 * `/api/delegate/prepare` (TC-547). These routes back the `/delegate` page,
 * whose link parameters (including `expiry`) come from whoever made the link,
 * so a longer request is clamped to this ceiling; longer-lived access is
 * renewed by approving a new link. A signed approval request or device request
 * states its own maximum and is held to it by its window check instead (TC-2274).
 */
const MAX_DELEGATION_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

const MS_UNIT_FACTORS: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 60 * 60 * 1000,
  d: 24 * 60 * 60 * 1000,
  w: 7 * 24 * 60 * 60 * 1000,
};
/** The last second a SIWE timestamp (four-digit year) can name. */
const LATEST_SIWE_TIME_MS = Date.UTC(9999, 11, 31, 23, 59, 59);

/**
 * Parse a caller-provided expiry into a clamped ms count.
 *  - missing → default (7d)
 *  - number → treated as raw milliseconds
 *  - "604800000" → numeric milliseconds
 *  - "7d", "30m", "12h", "1w" → ms-format string (small subset of
 *    the popular `ms` package, inlined to avoid a new dep)
 *
 * Result is clamped to [MIN, MAX]. Bad input throws a 400-friendly Error.
 * A link-supplied value is clamped to [MIN, MAX] (TC-547: link parameters come
 * from whoever made the link). A value the user picked on the approval screen
 * (`userChosen`) is not clamped to MAX; the approval-request and device
 * windows still bound it to what the requester signed.
 */
function resolveDelegationExpiryMs(input: unknown, userChosen = false): number {
  if (input === undefined || input === null || input === '') {
    return DEFAULT_DELEGATION_EXPIRY_MS;
  }
  let raw: number;
  if (typeof input === 'number') {
    raw = input;
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (/^\d+$/.test(trimmed)) {
      raw = Number(trimmed);
    } else {
      const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)$/i);
      if (!match) {
        throw new Error(`Invalid expiry "${input}" — use ms-format ("7d", "30m") or a millisecond integer.`);
      }
      const valueText = match[1];
      const unit = match[2]?.toLowerCase();
      const factor = unit ? MS_UNIT_FACTORS[unit] : undefined;
      if (!valueText || factor === undefined) {
        throw new Error(`Invalid expiry "${input}" — use ms-format ("7d", "30m") or a millisecond integer.`);
      }
      const value = Number(valueText);
      raw = value * factor;
    }
  } else {
    throw new Error(`expiry must be a string or number, got ${typeof input}`);
  }
  if (!Number.isFinite(raw) || raw <= 0) {
    throw new Error(`expiry must be a positive number, got ${input}`);
  }
  if (userChosen) {
    // A time the user picked is their own choice: no 30-day link clamp, only
    // the minimum and the last date a SIWE timestamp can hold.
    if (Date.now() + raw > LATEST_SIWE_TIME_MS) throw new Error('expiry is too far in the future');
    return Math.max(MIN_DELEGATION_EXPIRY_MS, raw);
  }
  return Math.min(MAX_DELEGATION_EXPIRY_MS, Math.max(MIN_DELEGATION_EXPIRY_MS, raw));
}

/**
 * The lifetime a /prepare or /api/delegate body asks for. A link's own `expiry` is clamped to 30 days
 * (TC-547). A time the user picked on the screen (`expiryChosen`) skips that clamp, but on a plain link
 * it may not be longer than the link's own expiry (`linkExpiry`, after the clamp) unless the link opted
 * in with `expiryChangeable: true`: a CLI that built the link refuses a delegation longer than it asked
 * for (OPENKEY_EXPIRY_EXCEEDED) and saves nothing. Signed approval requests and device transactions are
 * held to what the requester signed by their own window checks.
 */
function resolveRequestExpiryMs(body: {
  expiry?: unknown;
  expiryChosen?: unknown;
  linkExpiry?: unknown;
  expiryChangeable?: unknown;
  approvalRequestId?: unknown;
  deviceTransactionId?: unknown;
}): number {
  const picked = body.expiryChosen === true;
  // `null` and '' are not a signed request: only a real id puts the request under its own window check.
  const plainLink = !body.approvalRequestId && !body.deviceTransactionId;
  // A signed approval request or device transaction states its own longest lifetime and is held to it by
  // its window check; only a bare link's `expiry` gets the 30-day link clamp (TC-547).
  const expiryMs = resolveDelegationExpiryMs(body.expiry, picked || !plainLink);
  if (picked && plainLink && body.expiryChangeable !== true) {
    const linkMs = resolveDelegationExpiryMs(body.linkExpiry);
    if (expiryMs > linkMs) {
      const days = linkMs / 86_400_000;
      const allowed = Number.isInteger(days) ? `${days}d` : `${Math.round(linkMs / 60_000)}m`;
      throw new DelegateRequestError(
        'expiry_exceeds_link',
        `This link allows an approval of up to ${allowed}. To allow longer, start again with a longer expiry.`,
      );
    }
  }
  return expiryMs;
}

/**
 * Extract the immutable SIWE header fields whose digest binds the /prepare
 * context to /complete. Any change in any of these fields between prepare
 * and complete indicates tampering — reject.
 *
 * Fields covered (Sol MAJOR-5):
 *   - address, chainId, domain, spaceId — bind the relying party + signer
 *   - issuedAt, expirationTime — bind the temporal window
 *   - nonce — bind session-key identity
 *   - uri — bind the callback URI (protects against RP substitution)
 *   - version — bind SIWE protocol version
 *   - notBefore — when present, must not drift (early activation)
 *   - requestId — when present, opaque correlation id
 *   - statement — the non-ReCap SIWE statement line (statements added AFTER
 *     the ReCap block are permitted to change with narrowing, but the
 *     original SIWE `statement` field before Resources: must not drift)
 *   - nonRecapResources — any resource line that is NOT a urn:recap: block
 *     (these are the caller's application-specific resource URIs and MUST
 *     be preserved byte-for-byte).
 */
function extractImmutableSiweFields(
  siwe: string,
  fallback: {
    chainId: number;
    spaceId: string;
  },
): {
  address: string;
  chainId: number;
  domain: string;
  issuedAt: string;
  expirationTime: string;
  spaceId: string;
  nonce: string;
  uri: string;
  version: string;
  notBefore: string;
  requestId: string;
  statement: string;
  nonRecapResources: string;
} {
  // TC-3826: the fields as the node reads them (`parseSiweFields`). A message
  // that does not parse yields empty fields and no address, so it binds to
  // nothing a real message has and every check against it refuses.
  const parsed = parseSiweFields(siwe);
  const fields = parsed.ok ? parsed.fields : undefined;
  return {
    address: fields?.address ?? '',
    chainId: fields ? Number(fields.chainId) : fallback.chainId,
    domain: fields ? `${fields.scheme !== undefined ? `${fields.scheme}://` : ''}${fields.domain}` : '',
    issuedAt: fields?.issuedAt ?? '',
    expirationTime: fields?.expirationTime ?? '',
    spaceId: fallback.spaceId,
    nonce: fields?.nonce ?? '',
    uri: fields?.uri ?? '',
    version: fields?.version ?? '',
    notBefore: fields?.notBefore ?? '',
    requestId: fields?.requestId ?? '',
    statement: fields?.statement ?? '',
    nonRecapResources: (fields?.resources ?? []).filter((r) => !r.startsWith('urn:recap:')).join('\n'),
  };
}

/**
 * Collect the set of action IDs classifier says are required for the given
 * ReCap entries. These IDs are the ones the server MUST see in the final
 * completed selection or the delegation fails.
 */
function requiredActionIdSet(entries: RecapEntry[]): Set<string> {
  const set = new Set<string>();
  for (const entry of entries) {
    for (const action of entry.actions) {
      if (isRequiredAction(entry, action)) {
        set.add(computeActionKey(entry, action));
      }
    }
  }
  return set;
}

/**
 * Digest of a delegation's request baseline: the ability maps derived from
 * the request's `permissions` (or the own folder when it names none). `/prepare` binds it to the
 * authorization context; `/complete` and the managed approval recompute it
 * from the `permissions` they receive and consume refuses a mismatch, so the
 * subset check at completion runs against the request that was prepared.
 * Each resource's actions are sorted and deduplicated first, so the same
 * grants in another order (or split across entries) digest the same.
 * Each resolved space remains in the digest, independently of routing.
 */
function digestDelegationBaseline({ spaceAbilities, rawAbilities }: SessionAbilities): string {
  const canonical = (byResource: Record<string, string[]>) => Object.fromEntries(
    Object.entries(byResource).map(([resource, actions]) => [resource, [...new Set(actions)].sort()]),
  );
  const canonicalSpaces = Object.fromEntries(
    Object.entries(spaceAbilities).map(([space, abilities]) => [space, Object.fromEntries(
      Object.entries(abilities).map(([service, byPath]) => [service, canonical(byPath)]),
    )]),
  );
  return digestAbilities({ spaceAbilities: canonicalSpaces, rawAbilities: canonical(rawAbilities) });
}

/**
 * Detect whether the SIWE's `urn:recap:` payload carries MEANINGFUL
 * caveats — i.e. any (resource, ability) pair whose caveat array
 * contains a non-empty object. The ReCap canonical shape is `[{}]` for
 * "no caveats", which every real TinyCloud-emitted recap uses; treating
 * `[{}]` as a real caveat would refuse to narrow every request.
 *
 * We inspect the raw ReCap JSON because the WASM `parseRecapFromSiwe`
 * strips caveats. If any (resource, action) has a meaningful caveat
 * list, the caller must not narrow via /authorize-sign — the regenerated
 * SIWE would drop the caveats and broaden authority.
 *
 * Returns true when at least one meaningful caveat is present; false
 * when the SIWE has no ReCap block, no caveats at all, or only the
 * vacuous `[{}]` placeholder. Silently returns false on decode failure
 * so parsing bugs cannot bypass this guard — the outer parse step
 * already rejected malformed ReCap payloads.
 */
/**
 * Sol MAJOR-4: build a candidate ReCap attenuation from a set of selected
 * action IDs, pairing each surviving (resource, ability) pair with the
 * caveats it carries in the BASELINE attenuation. Because the baseline was
 * extracted from the ORIGINAL SIWE and we never fabricate caveats, this
 * guarantees the candidate is at MOST as broad as the baseline before the
 * subset check runs — the subset check remains authoritative but the
 * candidate we hand it is always well-formed.
 */
function buildCandidateAttenuation(
  originalEntries: RecapEntry[],
  selectedActionIds: Set<string>,
  baselineAttenuation: Record<string, Record<string, unknown[]>>,
): Record<string, Record<string, unknown[]>> {
  // Build an index of baseline resource keys so we can find the correct
  // full resource URI (which the WASM emits as `<space>/<serviceShort>/<path>`)
  // for each (service, space, path) tuple that `parseRecapFromSiwe`
  // surfaces. We match by:
  //   - key STARTS WITH `entry.space` (either exact or `<space>/...`), AND
  //   - the ability with matching service+verb is present on that key.
  // For paths, the key's trailing segment is `<serviceShort>/<path>` OR
  // `<serviceShort>` when the path is empty. We choose the FIRST match
  // that has ALL selected actions for the entry.
  const candidate: Record<string, Record<string, unknown[]>> = {};
  for (const entry of originalEntries) {
    const selectedActions = entry.actions.filter((action) =>
      selectedActionIds.has(computeActionKey(entry, action)),
    );
    if (selectedActions.length === 0) continue;

    // Find the baseline attenuation key whose ability map contains all
    // selected actions for this entry AND whose URI matches the shape
    // `<entry.space>/<any-service-prefix>/<entry.path>` or
    // `<entry.space>/<any-service-prefix>` when entry.path is empty.
    let matchedKey: string | null = null;
    for (const key of Object.keys(baselineAttenuation)) {
      if (!key.startsWith(entry.space)) continue;
      const remainder = key.slice(entry.space.length);
      // Expected shape: "" (whole-space grant), or "/<serviceShort>[/<path>]".
      if (remainder === '' || remainder.startsWith('/')) {
        const abilityMap = baselineAttenuation[key];
        if (!abilityMap) continue;
        // The remainder (after the leading "/") is either "<service>" or
        // "<service>/<path>". We require the trailing part after the
        // first "/" to equal entry.path.
        const rest = remainder.startsWith('/') ? remainder.slice(1) : remainder;
        const slashIdx = rest.indexOf('/');
        const restPath = slashIdx >= 0 ? rest.slice(slashIdx + 1) : '';
        if (restPath !== entry.path) continue;
        // All selected actions must be present in this ability map.
        if (selectedActions.every((a) => abilityMap[a] !== undefined)) {
          matchedKey = key;
          break;
        }
      }
    }
    if (matchedKey === null) {
      // Nothing matched — the caller supplied an entry not derivable from
      // the baseline. Skip; subset check will fail closed.
      continue;
    }
    const candidateSlot = candidate[matchedKey] ?? (candidate[matchedKey] = {});
    for (const action of selectedActions) {
      const baselineCaveats = baselineAttenuation[matchedKey]?.[action] ?? [];
      candidateSlot[action] = [...baselineCaveats];
    }
  }
  return candidate;
}

/**
 * Sol MAJOR-4 (final): return null when the CANDIDATE's caveat multiset on
 * every (resource, ability) pair EXACTLY matches the BASELINE's caveat
 * multiset for the same pair, else a short message describing the first
 * violation. Whole-resource and whole-ability removals are permitted (the
 * candidate simply omits those keys). Adding, changing, removing, or
 * changing the duplicate count of a caveat on a surviving (resource,
 * ability) pair is a violation.
 */
function attenuationSubsetOrFailure(
  candidate: Record<string, Record<string, unknown[]>>,
  baseline: Record<string, Record<string, unknown[]>>,
): string | null {
  const stably = (v: unknown): string => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(stably).join(',')}]`;
    const entries = Object.entries(v as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return `{${entries.map(([k, val]) => `${JSON.stringify(k)}:${stably(val)}`).join(',')}}`;
  };
  for (const [resource, candidateAbilityMap] of Object.entries(candidate)) {
    const baselineAbilityMap = baseline[resource];
    if (!baselineAbilityMap) return `resource ${resource} not in baseline`;
    for (const [ability, candidateCaveats] of Object.entries(candidateAbilityMap)) {
      const baselineCaveats = baselineAbilityMap[ability];
      if (!baselineCaveats) return `ability ${ability} on ${resource} not in baseline`;
      const baselineCounts = new Map<string, number>();
      for (const c of baselineCaveats) {
        const key = stably(c);
        baselineCounts.set(key, (baselineCounts.get(key) ?? 0) + 1);
      }
      const candidateCounts = new Map<string, number>();
      for (const c of candidateCaveats) {
        const key = stably(c);
        candidateCounts.set(key, (candidateCounts.get(key) ?? 0) + 1);
      }
      if (baselineCounts.size !== candidateCounts.size) {
        return `caveats on ${ability}@${resource} differ (baseline distinct=${baselineCounts.size}, candidate distinct=${candidateCounts.size})`;
      }
      for (const [key, baselineN] of baselineCounts) {
        const candidateN = candidateCounts.get(key) ?? 0;
        if (candidateN !== baselineN) {
          const preview = key.length > 80 ? `${key.slice(0, 80)}...` : key;
          if (candidateN === 0) {
            return `caveat ${preview} was removed from ${ability}@${resource} (surviving abilities must preserve caveats byte-for-byte)`;
          }
          if (candidateN < baselineN) {
            return `caveat ${preview} duplicate count decreased from ${baselineN} to ${candidateN} on ${ability}@${resource}`;
          }
          return `caveat ${preview} duplicate count increased from ${baselineN} to ${candidateN} on ${ability}@${resource}`;
        }
      }
      for (const [key, candidateN] of candidateCounts) {
        if (!baselineCounts.has(key)) {
          const preview = key.length > 80 ? `${key.slice(0, 80)}...` : key;
          return `caveat ${preview} was added to ${ability}@${resource} (candidate count ${candidateN}, baseline count 0)`;
        }
      }
    }
  }
  return null;
}

/**
 * Collect the set of action IDs present in a set of ReCap entries. This is
 * the "allowed" set the /prepare context binds — /complete cannot select
 * anything outside this set.
 */
/**
 * The action ids the app-key "approved together" rule compares a selection against. The extra permissions of the warning
 * screen (TC-2927) are decided one by one, and rejecting one must not count as dropping the rest of the request, so a
 * browser request leaves them out. A prepared-handoff (command line) request keeps the whole set.
 */
function groupRuleActionIds(entries: RecapEntry[], ticket: unknown): Set<string> {
  const ids = allowedActionIdSet(entries);
  if (!ticket) for (const action of elevatedActionsOf(entries, computeActionKey)) ids.delete(action.actionId);
  return ids;
}

function allowedActionIdSet(entries: RecapEntry[]): Set<string> {
  const set = new Set<string>();
  for (const entry of entries) {
    for (const action of entry.actions) {
      set.add(computeActionKey(entry, action));
    }
  }
  return set;
}

function isOpenKeySigningRequestBody(body: unknown): body is OpenKeySigningRequestBody {
  if (!body || typeof body !== 'object') return false;

  const candidate = body as Record<string, unknown>;
  return (
    typeof candidate.address === 'string' &&
    Number.isSafeInteger(candidate.chainId) &&
    typeof candidate.message === 'string' &&
    (candidate.type === 'siwe' || candidate.type === 'message') &&
    (candidate.keyId === undefined || typeof candidate.keyId === 'string')
  );
}

function openKeyApprovalRequired(reason: string, code: string) {
  return {
    approved: false,
    needsApproval: true,
    reason,
    code,
  };
}

async function signWithManagedPrivateKey(privateKey: Hex, message: string) {
  const { createWalletFromPrivateKey } = await import('@openkey/tee');
  const account = createWalletFromPrivateKey(privateKey);
  return account.signMessage({ message });
}

function coordinationosBootstrapTrigger(address: string): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: SIWE_DOMAIN,
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: makeSpaceId(address, 1, 'account'),
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    abilities: {
      capabilities: {
        capabilities: [CAPABILITIES.READ],
      },
    },
  }).siwe;
}

/**
 * POST /api/delegate/sign
 *
 * SDK OpenKey callback signing contract:
 * request `{ address, chainId, message, type, keyId? }`;
 * response `{ approved: true, signature }` or `{ approved: false, ... }`.
 *
 * This is the zero-gesture Auto-Sign path. The normal delegate routes below
 * remain explicit-approval flows and deliberately do not apply this gate.
 */
delegateRouter.post('/sign', async (c) => {
  const principal = c.get('delegateSignerPrincipal');
  const authFailure = c.get('delegateSignerAuthFailure');
  const oauthContext = c.get('delegateSignerOauthContext');
  const requestId = randomUUID();

  const auditDenial = async (
    code: CoordinationosDenialCode,
    evidence: CoordinationosPolicyEvidence,
  ) => {
    try {
      const decision = await recordCoordinationosDenial(prisma, code, evidence, requestId);
      return c.json(
        coordinationosDenialResponse(code, decision.decisionId),
        coordinationosStatus(code) as any,
      );
    } catch {
      return c.json(
        coordinationosDenialResponse('audit_write_failed', 'unavailable'),
        500,
      );
    }
  };

  if (!principal) {
    const code = authFailure?.code ?? 'missing_authorization';
    return auditDenial(code, sparseCoordinationosEvidence({
      oauthAccessTokenId: authFailure?.oauthAccessTokenId,
      tokenDigest: authFailure?.tokenDigest,
      clientId: authFailure?.clientId,
      userId: authFailure?.userId,
    }));
  }

  if (principal.kind === 'oauth-manage-key') {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({
        approved: false,
        code: 'message_rejected',
        reason: 'The signing request must be a JSON object.',
      }, 400);
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json({
        approved: false,
        code: 'message_rejected',
        reason: 'The signing request must be a JSON object.',
      }, 400);
    }
    const manageKeyDeviceUnsupported = deviceTransactionUnsupportedError(body);
    if (manageKeyDeviceUnsupported) {
      return c.json({ approved: false, code: manageKeyDeviceUnsupported.code, reason: manageKeyDeviceUnsupported.error }, 400);
    }

    // keyId and address, when supplied by older callback adapters, are
    // intentionally ignored. The OAuth token's user binding selects exactly
    // one canonical key at the database boundary.
    const candidate = body as Record<string, unknown>;
    try {
      const result = await withTinyCloudManageKeySigningPolicy(prisma, {
        userId: principal.userId, clientId: principal.clientId, request: body,
      }, async (tx) => {
        const key = await tx.ethereumKey.findFirst({
          where: primaryKeyWhere(principal.userId),
          select: { id: true, address: true, sealedBlob: true, sealingContext: true, userId: true },
        });
        if (!key || !key.sealedBlob || !key.userId) throw new Error('canonical_key_unavailable');
        const identity = {
          version: 'v1' as const, keyId: key.id, address: ensureEip55(key.address), chainId: 1 as const,
          did: `did:pkh:eip155:1:${ensureEip55(key.address)}`,
          spaceId: `tinycloud:pkh:eip155:1:${ensureEip55(key.address)}:applications`,
        };
        const policy = validateTinyCloudManageKeyRequest({ type: candidate.type, chainId: candidate.chainId, message: candidate.message, identity });
        if (!policy.allowed) throw new Error(`message_rejected:${policy.reason}`);
        const appKeyRefusal = appKeyRefusalForSiwe(candidate.message as string);
        if (appKeyRefusal) throw new Error(`message_rejected:${appKeyRefusalMessage(appKeyRefusal, 'non_browser')}`);
        const lifetimeReach = exceedsSecretLifetime(candidate.message as string, Date.now());
        if (lifetimeReach) throw new Error(`message_rejected:${secretLifetimeMessage(lifetimeReach)}`);
        // The policy above lets an `applications` host message through. Hosting a space for a client that is not
        // TinyCloud's own is signed only once the owner's primary space is hosted (a complete stored bootstrap row).
        if (await refusesThirdPartySpaceHost({
          prisma: tx, message: candidate.message as string, key, authorities: [oauthClientProvisionAuthority(principal.clientId)],
        })) throw new Error(HOST_SIGNING_FIRST_PARTY_ONLY);
        const signature = await signManagedKey(key, key.sealedBlob, candidate.message as string);
        return { signature, identity };
      });
      if (!result.allowed) {
        const code = result.reason === 'missing_consent' ? 'missing_scope' : result.reason;
        const reason = result.reason === 'user_exclusive'
          ? 'The user has disabled application signing in exclusive mode.'
          : result.reason === 'grant_disabled'
            ? 'TinyCloud signing is not enabled for this application.'
            : result.reason === 'missing_consent'
              ? 'The application does not have active TinyCloud manage-key consent.'
              : 'TinyCloud signing is disabled for this OpenKey account.';
        return c.json({ approved: false, code, reason }, 403);
      }
      return c.json({ approved: true, signature: result.value.signature, canonicalIdentity: result.value.identity });
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      if (message === 'canonical_key_unavailable') return c.json({ approved: false, code: 'canonical_key_unavailable', reason: 'The canonical TinyCloud key is unavailable.' }, 403);
      if (message === HOST_SIGNING_FIRST_PARTY_ONLY) return c.json({ approved: false, code: HOST_SIGNING_FIRST_PARTY_ONLY, reason: HOST_SIGNING_FIRST_PARTY_ONLY_MESSAGE }, 403);
      if (message.startsWith('message_rejected:')) return c.json({ approved: false, code: 'message_rejected', reason: message.slice('message_rejected:'.length) }, 400);
      return c.json({
        approved: false,
        code: 'signer_failed',
        reason: 'The canonical TinyCloud signer is unavailable.',
      }, 500);
    }
  }

  if (principal.kind === 'coordinationos-oauth') {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return auditDenial('malformed_json', sparseCoordinationosEvidence({
        oauthAccessTokenId: principal.oauthAccessTokenId,
        tokenDigest: principal.tokenDigest,
        clientId: principal.clientId,
        userId: principal.userId,
      }));
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return auditDenial('malformed_json', sparseCoordinationosEvidence({
        oauthAccessTokenId: principal.oauthAccessTokenId,
        tokenDigest: principal.tokenDigest,
        clientId: principal.clientId,
        userId: principal.userId,
      }));
    }
    const candidate = body as Record<string, unknown>;
    const required = ['address', 'chainId', 'message', 'type', 'purpose', 'keyId'] as const;
    if (required.some((field) => !Object.prototype.hasOwnProperty.call(candidate, field))) {
      return auditDenial('missing_field', sparseCoordinationosEvidence({
        oauthAccessTokenId: principal.oauthAccessTokenId,
        tokenDigest: principal.tokenDigest,
        clientId: principal.clientId,
        userId: principal.userId,
        keyId: typeof candidate.keyId === 'string' ? candidate.keyId : null,
        origin: canonicalizeCoordinationosOrigin(c.req.header('origin')),
        chainId: typeof candidate.chainId === 'number' ? candidate.chainId : null,
        purpose: typeof candidate.purpose === 'string' ? candidate.purpose : null,
        type: typeof candidate.type === 'string' ? candidate.type : null,
        siweDigest: typeof candidate.message === 'string' ? sha256Hex(candidate.message) : null,
      }));
    }

    const key = typeof candidate.keyId === 'string'
      ? await prisma.ethereumKey.findUnique({
          where: { id: candidate.keyId },
          select: {
            id: true,
            userId: true,
            address: true,
            keyType: true,
            archivedAt: true,
            sealedBlob: true,
            sealingContext: true,
          },
        })
      : null;
    const policy = evaluateCoordinationosSessionRequest({
      principal,
      client: oauthContext?.client ?? null,
      user: oauthContext?.user ?? null,
      key,
      request: {
        address: candidate.address,
        chainId: candidate.chainId,
        message: candidate.message,
        type: candidate.type,
        purpose: candidate.purpose,
        keyId: candidate.keyId,
        origin: c.req.header('origin') ?? null,
      },
    });
    if (!policy.allowed) return auditDenial(policy.code, policy.evidence);
    // A message that names an app key or key.delete, or asks for more than 7 days on secret keys, is outside
    // the approved storage records: it is denied and recorded like every other denial.
    if (typeof candidate.message === 'string' &&
      (appKeyRefusalForSiwe(candidate.message) || exceedsSecretLifetime(candidate.message, Date.now()))) {
      return auditDenial('wrong_capability', policy.evidence);
    }
    if (!key || !key.sealedBlob || !policy.evidence.nonceDigest) {
      return auditDenial('key_unavailable', policy.evidence);
    }
    // The session policy signs only a kv ReCap on `applications`, so a space host message never gets here. This is the
    // same rule as every other branch, from the server-known facts about the client, in case that policy widens.
    if (await refusesThirdPartySpaceHost({
      prisma, message: candidate.message as string, key,
      authorities: [oauthClientProvisionAuthority(principal.clientId), originProvisionAuthority(oauthContext?.client?.tinycloudSessionOrigin)],
    })) {
      return auditDenial('wrong_capability', policy.evidence);
    }

    let grant;
    try {
      grant = await consumeCoordinationosGrant(prisma, {
        evidence: policy.evidence,
        oauthAccessTokenId: principal.oauthAccessTokenId,
        nonceDigest: policy.evidence.nonceDigest,
        clientId: principal.clientId,
        userId: principal.userId,
        keyId: key.id,
        requestId,
      });
    } catch {
      return c.json(
        coordinationosDenialResponse('audit_write_failed', 'unavailable'),
        500,
      );
    }
    if (!grant.allowed) {
      return c.json(
        coordinationosDenialResponse(grant.code, grant.decision.decisionId),
        coordinationosStatus(grant.code) as any,
      );
    }

    try {
      const privateKey = await unsealManagedKey(key, key.sealedBlob);
      const { ensureTinyCloudBootstrapForApprovedSign } = await import(
        '../services/tinycloud-bootstrap'
      );
      const bootstrap = await ensureTinyCloudBootstrapForApprovedSign({
        // The OAuth grant is already a policy-approved signing decision. The
        // bootstrap service's user-preference lookup is for the unchanged
        // Better Auth session branch, so satisfy that narrow seam without
        // mutating the user's stored Auto-Sign preference.
        prisma: {
          user: {
            findUnique: async () => ({ autoSignEnabled: true }),
          },
          tinyCloudBootstrapState: prisma.tinyCloudBootstrapState,
        } as any,
        userId: principal.userId,
        key: {
          id: key.id,
          address: key.address,
          keyType: key.keyType,
        },
        privateKey,
        message: coordinationosBootstrapTrigger(key.address),
        format: 'personal_sign',
        authority: oauthClientProvisionAuthority(principal.clientId),
        // A client that is not first-party signs for an account that is already set up and sets none up.
        acceptCompleteRow: true,
      });
      // A skipped bootstrap (the account is not set up and the client is not first-party) refuses the signature.
      if (bootstrap.status !== 'complete') {
        throw new Error('TinyCloud bootstrap did not complete');
      }
      const signature = await signWithManagedPrivateKey(
        privateKey,
        candidate.message as string,
      );
      return c.json({
        approved: true,
        signature,
        decisionId: grant.decision.decisionId,
        policyVersion: grant.decision.policyVersion,
      });
    } catch {
      try {
        const decision = await recordCoordinationosSignerError(prisma, policy.evidence, requestId);
        return c.json(
          coordinationosDenialResponse('signer_failed', decision.decisionId),
          500,
        );
      } catch {
        return c.json(
          coordinationosDenialResponse('audit_write_failed', 'unavailable'),
          500,
        );
      }
    }
  }

  const user = c.get('user');
  const body = await c.req.json();
  const deviceUnsupported = deviceTransactionUnsupportedError(body);
  if (deviceUnsupported) {
    return c.json({ approved: false, code: deviceUnsupported.code, reason: deviceUnsupported.error }, 400);
  }

  if (!isOpenKeySigningRequestBody(body)) {
    return c.json({
      approved: false,
      reason: 'address, chainId, message, and type are required',
    }, 400);
  }
  const invalidSignSiwe = invalidSiweMessage(body.message);
  if (invalidSignSiwe) return c.json({ approved: false, code: invalidSignSiwe.code, reason: invalidSignSiwe.error }, 400);

  const signAppKeyRefusal = appKeyRefusalForSiwe(body.message);
  if (signAppKeyRefusal) {
    return c.json({
      approved: false,
      code: appKeyRefusalCode(signAppKeyRefusal),
      reason: appKeyRefusalMessage(signAppKeyRefusal, 'non_browser'),
    }, appKeyRefusalStatus(signAppKeyRefusal));
  }
  // Signed bytes cannot be shortened, so more than 7 days on secret keys is refused.
  const signLifetimeReach = exceedsSecretLifetime(body.message, Date.now());
  if (signLifetimeReach) {
    return c.json({ approved: false, code: SECRET_LIFETIME_CODE, reason: secretLifetimeMessage(signLifetimeReach) }, 400);
  }

  let address: string;
  try {
    address = ensureEip55(body.address);
  } catch {
    return c.json({
      approved: false,
      reason: 'address must be a valid EVM address',
    }, 400);
  }

  if (body.chainId <= 0) {
    return c.json({
      approved: false,
      reason: 'chainId must be a positive EIP-155 chain ID',
    }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: {
      userId: user.id,
      archivedAt: null,
      ...(body.keyId
        ? { id: body.keyId }
        : { address, keyType: 'MANAGED' as const }),
    },
  });

  if (!key) {
    return c.json({ approved: false, reason: 'Managed key not found' }, 404);
  }

  if (ensureEip55(key.address) !== address) {
    return c.json({
      approved: false,
      reason: 'Requested address does not match the managed key',
    }, 403);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({
      approved: false,
      reason: 'Only managed keys can be used with this endpoint',
    }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ approved: false, reason: 'Key has no sealed data' }, 400);
  }

  const autoSignPreference = await prisma.user.findUnique({
    where: { id: user.id },
    select: { autoSignEnabled: true },
  });

  if (!autoSignPreference) {
    return c.json({ approved: false, reason: 'User not found' }, 404);
  }

  let entries: RecapEntry[];
  try {
    entries = parsePreparedRecap(body.message);
  } catch {
    return c.json(openKeyApprovalRequired(
      'OpenKey Auto-Sign only supports bootstrap SIWE/ReCap signing requests',
      'outside_bootstrap_allowlist',
    ));
  }

  // TC-3442: "Always" asks for the passkey on every approval, so it pauses Auto-Sign, which has no approval to ask on.
  // The request then goes to the approval screen like any other.
  const autoSignOn = autoSignPreference.autoSignEnabled
    && (await passkeyApprovalModes(prisma, user.id))?.effectiveMode !== 'ALWAYS';
  const autoSignDecision = evaluateAutoSignPolicy(
    autoSignOn,
    evaluateBootstrapSigningScope({
      entries,
      address,
      chainId: body.chainId,
    }),
  );

  if (!autoSignDecision.allowed) {
    return c.json(openKeyApprovalRequired(autoSignDecision.reason, autoSignDecision.code));
  }

  // This is the cookie-session branch: the signer middleware admits it only from OpenKey's own browser origin
  // (`rejectNonOpenKeySignRequest`), which is not first-party for provisioning, and the Origin header is the caller's
  // word, not evidence. So no one is first-party here, by construction: a space host message is signed only by the
  // third-party rule of POST /api/keys/:id/sign (the key owner's own spaces once the owner's primary space is
  // hosted). Nothing in the web app or the SDK sends one here.
  if (await refusesThirdPartySpaceHost({ prisma, message: body.message, key, authorities: [UNATTRIBUTED_PROVISION_AUTHORITY] })) {
    return c.json({ approved: false, code: HOST_SIGNING_FIRST_PARTY_ONLY, reason: HOST_SIGNING_FIRST_PARTY_ONLY_MESSAGE }, 403);
  }

  const signature = await signManagedKey(key, key.sealedBlob, body.message);
  // The route is called from the app's own page, so Origin is the app origin.
  recordAppSignIn(prisma, user.id, c.req.header('origin'));
  return c.json({
    approved: true,
    signature,
  });
});

/**
 * POST /api/delegate/host
 *
 * Signs a TinyCloud space/host SIWE for a managed key. This is the root-key
 * half of bootstrap space hosting; the caller submits the signed SIWE to the
 * node's /delegate endpoint. Refused for every caller: nothing first-party can be attributed here.
 */
delegateRouter.post('/host', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    peerId: string;
    space?: string;
    prefix?: string;
  }>();
  const deviceUnsupported = deviceTransactionUnsupportedError(body);
  if (deviceUnsupported) return c.json(deviceUnsupported, 400);
  // This signature is the ability to create a space on the node, for any peer and prefix the caller names. The route
  // takes only the OpenKey account origin, which says nothing about which app is asking, so no first-party authority
  // can be bound to it: it signs nothing until a caller that can be attributed is added.
  if (!mayProvision(UNATTRIBUTED_PROVISION_AUTHORITY)) {
    return c.json({ error: 'Only TinyCloud\'s own apps can have OpenKey sign a space host request.', code: 'host_signing_first_party_only' }, 403);
  }

  if (!body.keyId || !body.peerId) {
    return c.json({ error: 'keyId and peerId are required' }, 400);
  }

  const spacePrefix = body.space || body.prefix;
  if (!spacePrefix) {
    return c.json({ error: 'space is required' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id, archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({ error: 'Only managed keys can be used with this endpoint.' }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ error: 'Key has no sealed data' }, 400);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const normalizedSpace = spacePrefix.startsWith('tinycloud:')
    ? spacePrefix.slice(spacePrefix.lastIndexOf(':') + 1)
    : spacePrefix;
  const spaceId = makeSpaceId(address, chainId, normalizedSpace);
  const issuedAt = new Date().toISOString();
  const siwe = generateHostSIWEMessage({
    address,
    chainId,
    domain: SIWE_DOMAIN,
    issuedAt,
    spaceId,
    peerId: body.peerId,
  });

  const signature = await signManagedKey(key, key.sealedBlob, siwe);
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  return c.json({
    siwe,
    signature,
    spaceId,
    ownerDid,
    address,
    chainId,
    peerId: body.peerId,
  });
});

/**
 * POST /api/delegate
 *
 * Creates a TinyCloud delegation for the CLI using a MANAGED key.
 * The server unseals the private key via TEE and signs the SIWE message.
 */
delegateRouter.post('/', async (c) => {
  const user = c.get('user');
  const body = await readDelegateBody<{
    keyId: string;
    jwk: DelegationJwk;
    host: string;
    prefix?: string;
    actionKeys?: unknown;
    permissionKeys?: unknown;
    permissions?: unknown;
    deviceTransactionId?: unknown;
    approvalRequestId?: string;
    /** Optional; may only repeat the renewal choice the preview bound (TC-2933). */
    renewal?: unknown;
    expiry?: unknown;
    expiryChosen?: unknown;
    linkExpiry?: unknown;
    expiryChangeable?: unknown;
    reason?: unknown;
    /**
     * Blocker 1: versioned managed-approval path. When supplied together
     * with `authorizationContextToken` and `selectedActionIds`, the
     * server signs the SIWE bytes that were bound at /prepare instead of
     * regenerating a fresh preview. The regenerated-preview path is
     * insecure because the widget shows the /prepare preview but the
     * caller-echoed re-prepare produces different issuedAt/expirationTime
     * bytes, so the user would sign different bytes from the ones the
     * approval UI displayed.
     *
     * Token-less callers keep the legacy behavior (regenerate and sign).
     */
    prepared?: any;
    authorizationContextToken?: string;
    selectedActionIds?: unknown;
    protocolVersion?: number;
    /** TC-3442: `{ challengeToken, response }` for the challenge /prepare offered, when Approve needs the passkey. */
    passkeyAssertion?: unknown;
  }>(c);
  const privateMembers = hasPrivateJwkMember(body.jwk);
  logSessionJwk('/api/delegate', privateMembers);
  if (privateMembers && !body.deviceTransactionId) countPrivateSessionJwk('/api/delegate');
  // Only the session key's public members are used, stored, or returned; a
  // malformed key counts as missing. A request naming a device transaction
  // keeps that flow's exact check of the key as sent, and one naming an
  // approval request of a well-formed key as sent; an empty or false id names
  // neither and is stripped like any other.
  const sessionJwk = publicJwk(body.jwk);
  if (!body.deviceTransactionId && (!sessionJwk || !body.approvalRequestId)) {
    body.jwk = sessionJwk as DelegationJwk;
  }

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }
  if (typeof body.prepared?.siwe === 'string') {
    const invalidEchoedSiwe = invalidSiweMessage(body.prepared.siwe, 'characters');
    if (invalidEchoedSiwe) return c.json(invalidEchoedSiwe, 400);
  }
  if (body.approvalRequestId !== undefined && (body.protocolVersion !== 1 || !body.authorizationContextToken)) {
    return c.json({ error: 'Approval requests require the consent preview context' }, 400);
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id, archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found' }, 404);
  }

  if (key.keyType !== 'MANAGED') {
    return c.json({ error: 'Only managed keys can be used with this endpoint. Use /api/delegate/prepare + /api/delegate/complete for external keys.' }, 400);
  }

  if (!key.sealedBlob) {
    return c.json({ error: 'Key has no sealed data' }, 400);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;
  const reason = normalizeDelegateReason(body.reason);
  let permissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      permissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json(delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions'), 400);
    }
  }
  let expiryMs: number;
  try {
    // A grant on secret keys lasts 7 days at most.
    expiryMs = clampSecretExpiryMs(resolveRequestExpiryMs(body), permissions);
  } catch (err) {
    return c.json(delegateErrorResponse(err, 'Invalid expiry', 'invalid_expiry'), 400);
  }

  // Blocker 1: versioned managed-approval path. When the widget forwards
  // the /prepare token AND the exact preview bytes, we sign the STORED
  // originalSiwe bytes byte-for-byte. Any drift between the preview and
  // the caller-echoed prepared block is a hard fail — the whole reason
  // this branch exists is to guarantee "the user signed the exact bytes
  // the approval UI showed them". We never trust caller-echoed bytes as
  // the payload; they are only used as the digest cross-check.
  const isVersionedCaller =
    typeof body.protocolVersion === 'number' && body.protocolVersion >= 1;
  const hasToken =
    typeof body.authorizationContextToken === 'string' &&
    body.authorizationContextToken.length > 0;
  if (isVersionedCaller && !hasToken) {
    return c.json(
      { error: 'protocolVersion >= 1 requires an authorizationContextToken', code: 'missing_authorization_context_token' },
      400,
    );
  }

  if (hasToken) {
    const token = body.authorizationContextToken as string;
    if (!body.prepared || typeof body.prepared !== 'object') {
      return c.json(
        { error: 'prepared block is required when authorizationContextToken is present', code: 'missing_prepared' },
        400,
      );
    }
    if (
      !Array.isArray(body.selectedActionIds) ||
      body.selectedActionIds.some((id) => typeof id !== 'string')
    ) {
      return c.json(
        { error: 'selectedActionIds must be a string[] when authorizationContextToken is provided', code: 'invalid_selected_action_ids' },
        400,
      );
    }

    // Peek the token so we can pull the server-bound originalSiwe. The
    // bindings are validated by `checkAuthorizationContext` below; the
    // context is consumed only after that check, the signed-expiry check,
    // and the device-window check have all passed. Peek itself is
    // non-consuming, so a caller cannot use it to burn the token.
    const preview = peekAuthorizationContext(token);
    if (!preview.ok) {
      return c.json({ error: preview.message, code: preview.error }, 400);
    }
    const bound = preview.value;
    if (bound.approvalRequestId !== body.approvalRequestId) {
      return c.json({ error: 'Approval request does not match the consent preview' }, 400);
    }
    confirmBoundRenewal(body.renewal, bound.renewal);

    // The stored context MUST have bound originalSiwe. Older /prepare
    // invocations that predate Blocker 1 did not set this field — those
    // tokens are unusable for the managed signing path and must retry.
    if (!bound.originalSiwe) {
      return c.json(
        {
          error: 'Authorization context has no bound originalSiwe — /prepare must be called again',
          code: 'authorization_context_missing_original_siwe',
        },
        400,
      );
    }

    // Structural cross-checks against the stored context. These duplicate
    // checks `checkAuthorizationContext` makes below, but running them here
    // surfaces clearer error codes and fails before we do any real work.
    if (bound.keyAddress !== address.toLowerCase()) {
      return c.json(
        {
          error: 'Bound keyAddress does not match the supplied keyId',
          code: 'key-mismatch',
        },
        400,
      );
    }
    if (bound.host !== host) {
      return c.json(
        { error: 'Host does not match the prepared context.', code: 'host-mismatch' },
        400,
      );
    }

    // The whole point of Blocker 1: sign the STORED bytes. Verify that
    // the caller-echoed prepared.siwe matches byte-for-byte. Signing the
    // stored bytes protects us from a compromised widget re-preparing
    // the SIWE; the caller-echo check surfaces the mismatch to the CLI
    // so a compromised widget cannot silently return a session bound to
    // different bytes than the ones the user reviewed.
    const echoedSiwe = typeof body.prepared.siwe === 'string' ? body.prepared.siwe : '';
    if (echoedSiwe !== bound.originalSiwe) {
      return c.json(
        {
          error: 'prepared.siwe does not match the SIWE bound at /prepare — refusing to sign',
          code: 'prepared_siwe_mismatch',
        },
        400,
      );
    }

    // Parse the bound SIWE, enforce baseline subset and required actions
    // against it (defense in depth — the /prepare handler already digested
    // the baseline abilities, but running these here catches store
    // corruption or any future change that widens the /prepare surface).
    let preparedEntries: RecapEntry[];
    try {
      preparedEntries = parsePreparedRecap(bound.originalSiwe);
    } catch (e) {
      return c.json(
        { error: e instanceof Error ? e.message : 'Bound SIWE could not be re-parsed', code: 'bound_siwe_parse_failed' },
        500,
      );
    }
    let baseline: SessionAbilities;
    try {
      baseline = permissions
        ? sessionAbilitiesFromPermissions(permissions, { address, chainId }, { deviceTransaction: body.deviceTransactionId !== undefined })
        : ownFolderSessionAbilities(extractImmutableSiweFields(bound.originalSiwe, { chainId, spaceId: bound.spaceId }).domain, { address, chainId });
      assertBaselineSubset(preparedEntries, baseline);
      assertRequiredActions(preparedEntries, baseline);
    } catch (e) {
      return c.json(delegateErrorResponse(e, 'Invalid delegation', 'invalid_permissions'), 400);
    }

    // Sol MAJOR-5: derive the EXACT set of action IDs encoded in the
    // BOUND (i.e. server-authoritative) SIWE. The caller's
    // selectedActionIds must EXACTLY match this set — a subset would
    // mean the widget claimed narrower authority than it will sign; a
    // superset would mean the widget claimed capabilities not in the
    // signed bytes.
    const siweEncodedActionIds = new Set<string>();
    for (const entry of preparedEntries) {
      for (const action of entry.actions) {
        siweEncodedActionIds.add(computeActionKey(entry, action));
      }
    }
    const clientSelected = new Set(body.selectedActionIds as string[]);
    const missingFromSelection: string[] = [];
    for (const id of siweEncodedActionIds) {
      if (!clientSelected.has(id)) missingFromSelection.push(id);
    }
    if (missingFromSelection.length > 0) {
      return c.json(
        {
          error: `selectedActionIds is missing entries that appear in the signed SIWE: ${missingFromSelection.slice(0, 5).join(', ')}${missingFromSelection.length > 5 ? ` (and ${missingFromSelection.length - 5} more)` : ''}`,
          code: 'selected_actions_missing_siwe_entries',
        },
        400,
      );
    }
    const extrasInSelection: string[] = [];
    for (const id of clientSelected) {
      if (!siweEncodedActionIds.has(id)) extrasInSelection.push(id);
    }
    if (extrasInSelection.length > 0) {
      return c.json(
        {
          error: `selectedActionIds contains entries not present in the signed SIWE: ${extrasInSelection.slice(0, 5).join(', ')}${extrasInSelection.length > 5 ? ` (and ${extrasInSelection.length - 5} more)` : ''}`,
          code: 'selected_actions_exceed_siwe_entries',
        },
        400,
      );
    }

    // Recompute the immutable-fields digest from the BOUND SIWE (never
    // from the caller-echoed prepared, even though we already verified
    // they are equal above). The digest bound at /prepare was computed
    // over the same bytes, so this MUST match.
    const immutable = extractImmutableSiweFields(bound.originalSiwe, {
      chainId,
      spaceId: bound.spaceId,
    });

    // TC-587: the session handed to WASM after signing is built only from
    // the bound context (see `completeSessionSetup` below), never from the
    // caller-echoed prepared block. An echoed spaceId or verificationMethod
    // that disagrees with the bound values is refused here, before the
    // context is consumed, instead of reaching WASM after signing.
    const boundVerificationMethod = immutable.uri;
    if (
      (body.prepared.spaceId !== undefined && body.prepared.spaceId !== bound.spaceId)
      || (body.prepared.verificationMethod !== undefined && body.prepared.verificationMethod !== boundVerificationMethod)
    ) {
      return c.json(
        {
          error: 'prepared.spaceId or prepared.verificationMethod does not match the context bound at /prepare — refusing to sign',
          code: 'prepared_metadata_mismatch',
        },
        400,
      );
    }

    // Validate every binding without consuming (TC-587): the expiry and
    // device-window refusals below leave the pending approval usable.
    const check = checkAuthorizationContext({
      token,
      userId: user.id,
      keyId: key.id,
      keyAddress: address,
      jwk: body.jwk,
      host,
      spaceId: bound.spaceId,
      selectedActionIds: clientSelected,
      candidateImmutableFieldsDigest: digestImmutableFields(immutable),
      candidateAbilitiesDigest: digestDelegationBaseline(baseline),
      requiredActionIds: requiredActionIdSet(preparedEntries),
    });
    if (!check.ok) {
      return c.json({ error: check.message, code: check.error }, 400);
    }

    const expirationTime = siweExpirationTime(bound.originalSiwe);
    if (!expirationTime) {
      return c.json({ error: 'prepared session must include a valid expirationTime or SIWE Expiration Time' }, 400);
    }
    const deviceWindow = await deviceDelegationWindowError(body, { host, signedSiwe: bound.originalSiwe });
    if (deviceWindow) return c.json(deviceWindow.body, deviceWindow.status);
    assertDevicePreviewTransaction(bound.deviceTransactionId, body.deviceTransactionId);
    if (bound.deviceTransactionId && bound.renewal?.choice === 'leased' && !renewalLeasesEnabled()) {
      throw new ApprovalResultError('renewal_disabled', DEVICE_RENEWAL_UNAVAILABLE, 400);
    }
    await checkApprovalDelegation(body, { signedSiwe: bound.originalSiwe });
    const tokenAppKeyRefusal = appKeyRefusalForSiwe(bound.originalSiwe, preparedEntries);
    if (tokenAppKeyRefusal) return c.json(appKeyRefusalBody(tokenAppKeyRefusal, 'non_browser'), appKeyRefusalStatus(tokenAppKeyRefusal));
    const tokenLifetimeReach = exceedsSecretLifetime(bound.originalSiwe, Date.now());
    if (tokenLifetimeReach) return c.json(secretLifetimeBody(tokenLifetimeReach), 400);
    // The stored SIWE was built from the permissions and may host a space: the rule of POST /api/keys/:id/sign applies,
    // from the authority the context was bound with (a checked origin, a still-valid approval or device request, or a
    // loopback or paste link), before the context is spent. Any other link is another site.
    if (await refusesSpaceHost({
      message: bound.originalSiwe, key,
      authority: () => boundProvisionAuthority({ bound, sessionUserId: user.id, body, host }),
    })) {
      return c.json(HOST_SIGNING_REFUSAL_BODY, 403);
    }
    // TC-3442: the account's passkey setting, before the context is spent or the key unsealed.
    const passkeyRefusal = await checkApprovalPasskey(
      prisma,
      { userId: user.id, sessionId: c.get('session')?.id ?? null },
      delegatePasskeyBinding(token, address, bound.originalSiwe),
      messageApprovalSensitivity(bound.originalSiwe, address),
      body.passkeyAssertion,
    );
    if (passkeyRefusal) return c.json(passkeyRefusal, 403);

    // About to sign: consume the context atomically, only if it is still
    // the exact one checked above, so a concurrent approval or a replay
    // cannot sign it a second time.
    const consumed = consumeCheckedAuthorizationContext(check.claim);
    if (!consumed.ok) {
      return c.json({ error: consumed.message, code: consumed.error }, 400);
    }

    await admitApprovalDelegation(body);
    // An attempt that fails after admission gives the admission back (the body is not re-indented to keep the diff small).
    try {

    // Sign the STORED originalSiwe verbatim. This is the entire point of
    // Blocker 1: never regenerate the SIWE at approval time.
    await assertReviewerSignedDelegation(prisma, user.id, bound.originalSiwe);
    const signature = await signManagedKey(key, key.sealedBlob, bound.originalSiwe);

    // Rebuild the session from the bound context only: the bound SIWE, its
    // space, its session key (the SIWE URI is the session key's
    // verificationMethod), and the bound JWK (digest-equal to body.jwk per
    // the check above). These are the inputs a successful /prepare already
    // produced, so a failure past this point is operational (TEE signing or
    // WASM), not caused by caller input.
    const session = completeSessionSetup({
      siwe: bound.originalSiwe,
      jwk: bound.jwk,
      spaceId: bound.spaceId,
      verificationMethod: boundVerificationMethod,
      signature,
    });

    const ownerSealedBlob = key.sealedBlob;
    let deviceRenewal;
    if (bound.deviceTransactionId && bound.renewal?.choice === 'leased') {
      try {
        deviceRenewal = await setUpSignInLease(prisma, {
          userId: user.id,
          sessionId: null,
          host,
          jwk: bound.jwk,
          spaceId: bound.spaceId,
          signedMessage: bound.originalSiwe,
          signature,
          leaseLifetimeSeconds: bound.renewal.leaseLifetimeSeconds,
          sensitiveConfirmed: bound.renewal.sensitiveConfirmed === true,
          signOwner: (message) => signManagedKey(key, ownerSealedBlob, message),
        });
      } catch (error) {
        const failure = signInRenewalFailure(error);
        const message = failure.body.code === 'renewal_failed'
          ? "OpenKey couldn't set up renewal. This device is waiting for your approval. You can approve it without renewal."
          : failure.body.code === 'renewal_disabled' ? DEVICE_RENEWAL_UNAVAILABLE : failure.body.error;
        return c.json({ error: message, code: failure.body.code }, failure.status);
      }
    } else if (bound.deviceTransactionId && bound.renewal?.choice === 'finite') {
      deviceRenewal = { renewal: null, renewalReason: 'renewal_declined' };
    }

    let hostActivated = false;
    let activationMayStillApply = false;
    const requestedSpaces = delegationSpaces(preparedEntries, baseline);
    let spaceReadiness = activationReadiness(requestedSpaces, preparedEntries);
    try {
      const activationResult = await activateSessionWithinTimeout(host, session.delegationHeader);
      hostActivated = activationResult.success;
      if (hostActivated) {
        spaceReadiness = await finishManagedSpaceOnboarding({
          userId: user.id,
          key,
          host,
          address,
          chainId,
          requestedSpaces,
          entries: preparedEntries,
          activation: activationResult,
          authority: await boundProvisionAuthority({ bound, sessionUserId: user.id, body, host }),
        });
      }
      if (!hostActivated) {
        log('warn', 'delegate_session_activation_warning');
        spaceReadiness = activationReadiness(requestedSpaces, preparedEntries, activationResult);
      }
    } catch (e) {
      activationMayStillApply = true;
      logError('warn', 'delegate_session_activation_failed', e);
    }

    const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
    const effectiveGrants = preparedEntries.map((entry) => ({
      service: entry.service,
      space: entry.space,
      path: entry.path,
      actions: [...entry.actions],
    }));

    recordAppSignIn(prisma, user.id, bound.appOrigin);
    const delegation = {
      delegationHeader: session.delegationHeader,
      delegationCid: session.delegationCid,
      spaceId: bound.spaceId,
      ownerDid,
      verificationMethod: session.verificationMethod,
      jwk: body.jwk,
      address,
      chainId,
      // Whether the signing key is the user's primary key, from the DB
      // record. Unsigned metadata for the CLI; the SIWE stays the authority.
      primary: isPrimaryKey(key),
      hostActivated,
      ...spaceReadiness,
      // `edited` is a hint for the UI response payload; the authority
      // gate is the token itself. The stored context was issued from a
      // /prepare that may or may not have narrowed; the actual signed
      // permissions are derivable from the SIWE bytes and are what the
      // CLI should trust.
      edited: false,
      reason,
      expirationTime,
      expiresAt: expirationTime,
      expiry: expirationTime,
      siwe: bound.originalSiwe,
      signature,
      signedMessage: bound.originalSiwe,
      permissions: effectiveGrants,
      ...deviceRenewal,
    };
    try {
      return c.json(await saveApprovalDelegation(body, user.id, delegation, { renewal: bound.renewal, host, sessionId: c.get('session')?.id ?? null, signOwner: (message) => signManagedKey(key, ownerSealedBlob, message) }));
    } catch (error) {
      if (body.approvalRequestId !== undefined && (hostActivated || activationMayStillApply)) {
        // A timeout also sends a best-effort revoke, which can land before a late activation (TC-2795).
        await revokeActivatedManagedDelegation(host, key, key.sealedBlob, ownerDid, session.delegationCid);
      }
      throw error;
    }
    } catch (error) {
      await releaseApprovalDelegation(body);
      throw error;
    }
  }

  // Legacy token-less path — unchanged behavior. The CLI and any older
  // callers that predate the versioned protocol land here and continue to
  // work as before.
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      actionKeys: normalizeStringArray(body.actionKeys, 'actionKeys'),
      permissionKeys: normalizeStringArray(body.permissionKeys, 'permissionKeys'),
      permissions,
      deviceTransaction: body.deviceTransactionId !== undefined,
      expiryMs,
    });
  } catch (e) {
    return c.json(delegateErrorResponse(e, 'Failed to prepare delegation', 'delegation_prepare_failed'), 400);
  }
  const invalidPreparedSiwe = invalidSiweMessage(preparedResult.prepared.siwe, 'characters');
  if (invalidPreparedSiwe) return c.json(invalidPreparedSiwe, 400);

  const expirationTime = siweExpirationTime(preparedResult.prepared.siwe);
  if (!expirationTime) {
    return c.json({ error: 'prepared session must include a valid expirationTime or SIWE Expiration Time' }, 400);
  }
  const deviceWindow = await deviceDelegationWindowError(body, { host, signedSiwe: preparedResult.prepared.siwe }, true);
  if (deviceWindow) return c.json(deviceWindow.body, deviceWindow.status);

  const legacyAppKeyRefusal = appKeyRefusalForSiwe(preparedResult.prepared.siwe);
  if (legacyAppKeyRefusal) return c.json(appKeyRefusalBody(legacyAppKeyRefusal, 'non_browser'), appKeyRefusalStatus(legacyAppKeyRefusal));
  // The SIWE was built from the permissions and may host a space. No origin is bound to this token-less request, so it
  // is another site: the rule of POST /api/keys/:id/sign signs only the owner's non-default spaces, once the owner's
  // primary space is hosted. A `default` target is refused: this request binds no context to check a row against.
  if (await refusesSpaceHost({ message: preparedResult.prepared.siwe, key, authority: () => UNATTRIBUTED_PROVISION_AUTHORITY, noBoundContext: true })) {
    return c.json(HOST_SIGNING_REFUSAL_BODY, 403);
  }
  // TC-3442: these bytes are made here, so no passkey challenge could have been bound to them. An approval the
  // account's setting says needs the passkey is refused on this path; the versioned path above can carry it.
  const legacyPasskeyRefusal = await checkApprovalPasskey(
    prisma,
    { userId: user.id, sessionId: c.get('session')?.id ?? null },
    { purpose: 'delegate_unbound', requestDigest: approvalRequestDigest(preparedResult.prepared.siwe) },
    messageApprovalSensitivity(preparedResult.prepared.siwe, address),
    undefined,
  );
  if (legacyPasskeyRefusal) return c.json(legacyPasskeyRefusal, 403);

  await assertReviewerSignedDelegation(prisma, user.id, preparedResult.prepared.siwe);
  const signature = await signManagedKey(key, key.sealedBlob, preparedResult.prepared.siwe);

  const session = completeSessionSetup({
    ...preparedResult.prepared,
    signature,
  });

  let hostActivated = false;
  const signedEntries = parsePreparedRecap(preparedResult.prepared.siwe);
  let spaceReadiness = activationReadiness(preparedResult.requestedSpaces, signedEntries);
  try {
    const activationResult = await activateSessionWithinTimeout(host, session.delegationHeader);
    hostActivated = activationResult.success;
    if (hostActivated) {
      spaceReadiness = await finishManagedSpaceOnboarding({
        userId: user.id,
        key,
        host,
        address,
        chainId,
        requestedSpaces: preparedResult.requestedSpaces,
        entries: signedEntries,
        activation: activationResult,
        // No origin is bound to this token-less request, so it never provisions.
        authority: UNATTRIBUTED_PROVISION_AUTHORITY,
      });
    }
    if (!hostActivated) {
      log('warn', 'delegate_session_activation_warning');
      spaceReadiness = activationReadiness(preparedResult.requestedSpaces, signedEntries, activationResult);
    }
  } catch (e) {
    logError('warn', 'delegate_session_activation_failed', e);
  }
  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  let effectiveEntries: RecapEntry[] = [];
  try {
    effectiveEntries = parsePreparedRecap(preparedResult.prepared.siwe);
  } catch {
    effectiveEntries = [];
  }
  const effectiveGrants = effectiveEntries.map((entry) => ({
    service: entry.service,
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));

  // The legacy path carries no app origin, so this records `unknown`.
  recordAppSignIn(prisma, user.id, undefined);
  return c.json({
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId: preparedResult.spaceId,
    ownerDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    primary: isPrimaryKey(key),
    hostActivated,
    ...spaceReadiness,
    edited: preparedResult.edited,
    reason,
    expirationTime,
    expiresAt: expirationTime,
    expiry: expirationTime,
    // Include the SIWE message so callers (CLI, web SDK) can persist it
    // alongside the delegation. The SDK extracts `expirationTime` from
    // this string at session-restore time; without it, restored sessions
    // are treated as expired-at-epoch-zero.
    siwe: preparedResult.prepared.siwe,
    signature,
    // Versioned protocol: `signedMessage` is the exact bytes signed,
    // `permissions` is the effective grant set. Callers should prefer
    // these fields over reconstructing from the SIWE string.
    signedMessage: preparedResult.prepared.siwe,
    permissions: effectiveGrants,
  });
});

/**
 * POST /api/delegate/prepare
 *
 * Prepares a SIWE delegation message for an external key to sign.
 * Returns the SIWE message and prepared session data. The client
 * signs the SIWE message with their browser wallet, then calls
 * POST /api/delegate/complete with the signature.
 */
delegateRouter.post('/prepare', async (c) => {
  const user = c.get('user');
  const body = await readDelegateBody<{
    keyId: string;
    jwk: DelegationJwk;
    host: string;
    prefix?: string;
    actionKeys?: unknown;
    permissionKeys?: unknown;
    permissions?: unknown;
    expiry?: unknown;
    /** TC-2272: true when `expiry` is the time the user picked on the approval screen, not a link parameter. */
    expiryChosen?: unknown;
    /** The link's own `expiry` (before any pick) and its `expiryChangeable=true` opt-in. */
    linkExpiry?: unknown;
    expiryChangeable?: unknown;
    reason?: unknown;
    /** Caller-reported attribution for ordinary links only; never verified app identity. */
    requesterOrigin?: unknown;
    deviceTransactionId?: unknown;
    approvalRequestId?: string;
    renewal?: unknown;
    /** What a plain legacy link says about how it returns the delegation (`paste` or `callback`) and its callback URL. */
    linkDelivery?: unknown;
    linkCallback?: unknown;
  }>(c);
  const privateMembers = hasPrivateJwkMember(body.jwk);
  logSessionJwk('/api/delegate/prepare', privateMembers);
  if (privateMembers && !body.deviceTransactionId) countPrivateSessionJwk('/api/delegate/prepare');
  // Only the session key's public members are used, stored, or returned; a
  // malformed key counts as missing. A request naming a device transaction
  // keeps that flow's exact check of the key as sent, and one naming an
  // approval request of a well-formed key as sent; an empty or false id names
  // neither and is stripped like any other.
  const sessionJwk = publicJwk(body.jwk);
  if (!body.deviceTransactionId && (!sessionJwk || !body.approvalRequestId)) {
    body.jwk = sessionJwk as DelegationJwk;
  }

  if (!body.keyId || !body.jwk || !body.host) {
    return c.json({ error: 'keyId, jwk, and host are required' }, 400);
  }

  let requesterDomain: string | undefined;
  if (body.requesterOrigin !== undefined) {
    if (body.deviceTransactionId !== undefined || body.approvalRequestId !== undefined) {
      return c.json({ error: 'requesterOrigin cannot override a device or signed approval request', code: 'requester_origin_unsupported' }, 400);
    }
    const origin = canonicalizeCoordinationosOrigin(body.requesterOrigin);
    const url = origin ? new URL(origin) : null;
    if (!url || origin !== body.requesterOrigin ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOCAL_HOSTNAMES.has(url.hostname)))) {
      return c.json({ error: 'requesterOrigin must be a canonical HTTPS origin or HTTP loopback origin', code: 'invalid_requester_origin' }, 400);
    }
    requesterDomain = url.host;
  }

  const key = await prisma.ethereumKey.findFirst({
    where: { id: body.keyId, userId: user.id, archivedAt: null },
  });

  if (!key) {
    return c.json({ error: 'Key not found', code: 'key_not_found' }, 404);
  }

  const address = ensureEip55(key.address);
  const chainId = 1;
  const prefix = body.prefix || 'default';
  const host = body.host;
  const reason = normalizeDelegateReason(body.reason);
  let permissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      permissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json(delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions'), 400);
    }
  }
  let expiryMs: number;
  try {
    // A grant on secret keys lasts 7 days at most.
    expiryMs = clampSecretExpiryMs(resolveRequestExpiryMs(body), permissions);
  } catch (err) {
    return c.json(delegateErrorResponse(err, 'Invalid expiry', 'invalid_expiry'), 400);
  }
  const device = await checkDeviceDelegationWindow(body, {
    expirationTime: new Date(Date.now() + expiryMs).toISOString(),
    host,
  });
  if (device.error) return c.json(device.error.body, device.error.status);
  if (device.record && body.approvalRequestId !== undefined) {
    throw new ApprovalResultError('request_binding', 'Choose one approval request for this preview.', 400);
  }
  await checkApprovalDelegation(body, { expiryMs });
  let renewal: BoundRenewalChoice | undefined;
  if (device.record) {
    try {
      renewal = parseRenewalChoice(body.renewal, device.record.renewal, renewalLeasesEnabled(), 'sign-in') ?? undefined;
    } catch (error) {
      if (!(error instanceof RenewalLeaseError)) throw error;
      throw new ApprovalResultError(error.code, error.code === 'renewal_disabled' ? DEVICE_RENEWAL_UNAVAILABLE : error.message, error.status);
    }
    if (renewal?.choice === 'leased' && key.keyType !== 'MANAGED') {
      throw new ApprovalResultError('request_binding', "Your wallet signs in for a set time, so this device's access ends at the time shown.", 400);
    }
  } else {
    renewal = await bindApprovalRenewal(body);
  }
  let preparedResult: ReturnType<typeof prepareDelegationSession>;
  try {
    preparedResult = prepareDelegationSession({
      address,
      chainId,
      prefix,
      jwk: body.jwk,
      actionKeys: normalizeStringArray(body.actionKeys, 'actionKeys'),
      permissionKeys: normalizeStringArray(body.permissionKeys, 'permissionKeys'),
      permissions,
      deviceTransaction: body.deviceTransactionId !== undefined,
      expiryMs,
      domain: requesterDomain,
    });
  } catch (e) {
    return c.json(delegateErrorResponse(e, 'Failed to prepare delegation', 'delegation_prepare_failed'), 400);
  }
  // Device approvals: the bytes handed to the wallet are a subset of what the device requested.
  const deviceSubset = await deviceDelegationWindowError(body, { host, signedSiwe: preparedResult.prepared.siwe });
  if (deviceSubset) return c.json(deviceSubset.body, deviceSubset.status);
  // TC-3821: a leased choice on a grant reaching secrets needs the owner's confirm and a window of at most 7 days.
  checkApprovalLeaseGrant(preparedResult.prepared.siwe, renewal);

  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;

  // Ensure JWK is preserved as a plain object through JSON round-trip.
  // The WASM prepareSession may return JWK as a special object that
  // doesn't serialize correctly, so we merge the original JWK back in.
  const preparedData = {
    ...preparedResult.prepared,
    jwk: body.jwk,
  };

  const prepareAppKeyRefusal = appKeyRefusalForSiwe(preparedResult.prepared.siwe);
  if (prepareAppKeyRefusal) return c.json(appKeyRefusalBody(prepareAppKeyRefusal, 'non_browser'), appKeyRefusalStatus(prepareAppKeyRefusal));

  // A plain legacy link says how it returns its delegation. The server classifies that here, from what the page sent at
  // prepare time, and seals the result: the approval never supplies it (see `delegate-link-delivery.ts`).
  const linkDelivery = body.deviceTransactionId === undefined && body.approvalRequestId === undefined && body.requesterOrigin === undefined
    ? classifyDelegateLinkDelivery(body.linkDelivery, body.linkCallback)
    : undefined;

  // The server built this SIWE from the permissions, and `tinycloud.space/host` is among the abilities they may name. A
  // message that hosts a space is the ability to create it: the rule of POST /api/keys/:id/sign applies. The asker is
  // known only from what this prepare has just validated: an approval request, a device request or a loopback or
  // paste link (`approvalProvisionAuthority`); any other link is another site. Refused before a context is issued.
  if (await refusesSpaceHost({
    message: preparedResult.prepared.siwe, key,
    authority: () => approvalProvisionAuthority({ approvalRequest: body.approvalRequestId !== undefined, device: device.record !== null, linkDelivery: linkDelivery !== undefined }),
  })) {
    return c.json(HOST_SIGNING_REFUSAL_BODY, 403);
  }

  // Issue an opaque single-use authorization context so /complete cannot
  // be replayed with a broader SIWE, a different key, or a different host.
  // The context digests are the sole authority for /complete — the `edited`
  // flag in the /complete body is not consulted for authority.
  let authorizationContext: AuthorizationContextToken | null = null;
  try {
    const baselineEntries = parsePreparedRecap(preparedResult.prepared.siwe);
    const allowedActionIds = allowedActionIdSet(baselineEntries);
    const initialSelectionActionIds = new Set(preparedResult.selectedActionKeys);
    const immutableFields = extractImmutableSiweFields(
      preparedResult.prepared.siwe,
      { chainId, spaceId: preparedResult.spaceId },
    );
    // Bound here and enforced at /complete and the managed approval: the
    // `permissions` a caller forwards at completion must grant what this
    // request did.
    const baselineAbilitiesDigest = digestDelegationBaseline(preparedResult.baselineAbilities);
    authorizationContext = issueAuthorizationContext({
      userId: user.id,
      keyId: key.id,
      keyAddress: address,
      jwk: body.jwk,
      host,
      spaceId: preparedResult.spaceId,
      baselineAbilitiesDigest,
      immutableFieldsDigest: digestImmutableFields(immutableFields),
      allowedActionIds,
      initialSelectionActionIds,
      expirationTime: immutableFields.expirationTime,
      // Blocker 1: bind the exact SIWE bytes at prepare time so the
      // managed approval path can sign the server-stored preview verbatim
      // instead of regenerating the message (which would produce fresh
      // issuedAt/expirationTime bytes on every attempt).
      originalSiwe: preparedResult.prepared.siwe,
      approvalRequestId: body.approvalRequestId,
      deviceTransactionId: device.record?.id,
      linkDelivery,
      renewal,
    });
  } catch (issueErr) {
    logError('warn', 'delegate_authorization_context_issue_failed', issueErr);
    // If we cannot issue a context there is no safe /complete path — force
    // callers to retry.
    return c.json(
      {
        error: 'Failed to issue authorization context',
        code: 'authorization_context_failed',
      },
      500,
    );
  }

  // Approving sets the account up only for an approval request, a device request or a loopback or paste link, and only
  // while that case is on. Every other link says it does not, rather than promise a setup.
  const setsUpAccount = approvalSetsUpAccount({
    approvalRequest: body.approvalRequestId !== undefined,
    device: device.record !== null,
    linkDelivery: linkDelivery !== undefined,
  });
  let spaceSetup: { space: string; plan: SpaceSetupPlan | 'no-setup' } | null = null;
  try {
    // A reviewer's spaces are hosted when the account is provisioned, so the notice would only mislead.
    const setup = await reviewerForUser(prisma, user.id) ? null : await managedSpaceSetupPlan({
      userId: user.id,
      keyType: key.keyType,
      host,
      address,
      chainId,
      spaceId: preparedResult.spaceId,
    });
    // The notice must not promise a setup the approval will skip (`approvalSetsUpAccount`).
    const disclosed = setup && { space: setup.space, plan: setup.plan === 'setup' && !setsUpAccount ? 'no-setup' as const : setup.plan };
    if (setup?.plan !== 'setup') {
      spaceSetup = disclosed;
    } else if (process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN !== 'off') {
      const { isTinyCloudBootstrapComplete } = await import('../services/tinycloud-bootstrap');
      if (!(await isTinyCloudBootstrapComplete(prisma, { keyId: key.id, chainId, host: setup.bootstrapHost }))) {
        spaceSetup = disclosed;
      }
    }
  } catch (error) {
    logError('warn', 'delegate_space_setup_notice_failed', error);
  }

  // TC-3442: a managed key approves through POST /api/delegate; say whether Approve needs the passkey, with the
  // challenge for exactly the bytes bound here.
  const passkey = key.keyType === 'MANAGED'
    ? await approvalPasskeyOffer(
      prisma,
      { userId: user.id, sessionId: c.get('session')?.id ?? null },
      delegatePasskeyBinding(authorizationContext.token, address, preparedResult.prepared.siwe),
      messageApprovalSensitivity(preparedResult.prepared.siwe, address),
    )
    : { required: false as const };

  return c.json({
    prepared: preparedData,
    spaceId: preparedResult.spaceId,
    requestedSpaces: preparedResult.requestedSpaces.map(space => ({ ...space, spaceReady: null })),
    spaceSetup,
    ownerDid,
    address,
    chainId,
    host,
    jwk: body.jwk,
    permissions: preparedResult.permissions,
    selectedActionKeys: preparedResult.selectedActionKeys,
    edited: preparedResult.edited,
    ownFolderOnly: preparedResult.ownFolderOnly,
    ownFolderShared: preparedResult.ownFolderShared,
    reason,
    // Versioned protocol: /complete MUST echo this token.
    authorizationContext: {
      token: authorizationContext.token,
      expiresAt: authorizationContext.expiresAt,
      baselineAbilitiesDigest: authorizationContext.baselineAbilitiesDigest,
    },
    passkey,
  });
});

/**
 * POST /api/delegate/complete
 *
 * Completes a delegation using a wallet-signed SIWE message.
 * Takes the prepared session data from /prepare plus the signature,
 * calls completeSessionSetup, activates the session, and returns
 * the delegation data.
 */
delegateRouter.post('/complete', async (c) => {
  const user = c.get('user');
  const body = await readDelegateBody<{
    prepared: any;
    signature: string;
    host: string;
    jwk: DelegationJwk;
    edited?: boolean;
    reason?: unknown;
    deviceTransactionId?: unknown;
    approvalRequestId?: string;
    /** Optional; may only repeat the renewal choice the preview bound (TC-2933). */
    renewal?: unknown;
    /**
     * The permissions that were the baseline for /prepare: the subset check
     * that guards against a compromised frontend crafting a broader SIWE runs
     * against them. Optional; when absent the baseline is the own folder of
     * the signed SIWE's domain, as /prepare chose.
     * Raw encryption entries must name a network owned by the SIWE signer.
     */
    permissions?: unknown;
    /**
     * Versioned protocol version marker. When >= 1, the request MUST
     * include an authorizationContextToken and selectedActionIds; the
     * server refuses to accept a versioned caller without a bound context.
     */
    protocolVersion?: number;
    /**
     * Versioned protocol: opaque token issued by /prepare. Required for
     * new callers (protocolVersion >= 1 or explicit request). When present,
     * the server re-validates every bound invariant (key, JWK, host,
     * immutable SIWE fields, allowed action set, required action set)
     * regardless of the `edited` flag. The `edited` flag is retained for
     * backward compatibility ONLY as a hint for the UI response payload;
     * it has NO effect on authority.
     */
    authorizationContextToken?: string;
    /**
     * Which action IDs the user finally selected. Required alongside
     * `authorizationContextToken`; each ID must be in the /prepare
     * allowed set and every required action must remain.
     *
     * Sol MAJOR-5: when the context token is present, this MUST exactly
     * match the actions encoded in the signed SIWE. Any drift (subset,
     * superset, or unrelated) is rejected.
     */
    selectedActionIds?: unknown;
  }>(c);
  const privateMembers = hasPrivateJwkMember(body.jwk);
  logSessionJwk('/api/delegate/complete', privateMembers);
  if (privateMembers && !body.deviceTransactionId) countPrivateSessionJwk('/api/delegate/complete');
  // Only the session key's public members are used, stored, or returned; a
  // malformed key counts as missing. A request naming a device transaction
  // keeps that flow's exact check of the key as sent, and one naming an
  // approval request of a well-formed key as sent; an empty or false id names
  // neither and is stripped like any other.
  const sessionJwk = publicJwk(body.jwk);
  if (!body.deviceTransactionId && (!sessionJwk || !body.approvalRequestId)) {
    body.jwk = sessionJwk as DelegationJwk;
  }

  if (!body.prepared || !body.signature || !body.host || !body.jwk) {
    return c.json({ error: 'prepared, signature, host, and jwk are required' }, 400);
  }
  // After the required-field gate, keep the wallet signature as the exact
  // string verified below, passed to session setup, and returned to clients.
  if (typeof body.signature !== 'string') {
    return c.json({ error: 'signature must be a string' }, 400);
  }
  const signature = body.signature;

  // Versioned protocol enforcement (Sol MAJOR-5): new callers MUST bind
  // through an authorization context token. Legacy callers (no
  // protocolVersion, no token) still get strict subset validation over
  // the SIWE bytes below, but the strong invariant re-derivation only
  // applies when a token is present.
  const isVersionedCaller =
    typeof body.protocolVersion === 'number' && body.protocolVersion >= 1;
  if (isVersionedCaller && !body.authorizationContextToken) {
    return c.json(
      { error: 'protocolVersion >= 1 requires an authorizationContextToken', code: 'missing_authorization_context_token' },
      400,
    );
  }

  let baselinePermissions: PermissionEntry[] | undefined;
  if (body.permissions !== undefined) {
    try {
      baselinePermissions = validatePermissions(body.permissions);
    } catch (err) {
      return c.json(delegateErrorResponse(err, 'Invalid permissions', 'invalid_permissions'), 400);
    }
  }

  if (typeof body.prepared.siwe !== 'string') {
    return c.json({ error: 'prepared.siwe must be a string' }, 400);
  }
  const invalidCompleteSiwe = invalidSiweMessage(body.prepared.siwe, 'characters');
  if (invalidCompleteSiwe) return c.json(invalidCompleteSiwe, 400);
  // TC-547: the signer is the address in the signed SIWE. The prepared
  // object `/prepare` returns (and the web echoes back) carries no
  // `address`, so reading it from there bound versioned approvals to an
  // empty key address. A caller-supplied `address` must agree with the SIWE.
  const preparedSpaceId = String(body.prepared.spaceId || '');
  const signedFields = extractImmutableSiweFields(body.prepared.siwe, {
    chainId: Number(body.prepared.chainId) || 1,
    spaceId: preparedSpaceId,
  });

  const completeAppKeyRefusal = appKeyRefusalForSiwe(body.prepared.siwe);
  if (completeAppKeyRefusal) return c.json(appKeyRefusalBody(completeAppKeyRefusal, 'non_browser'), appKeyRefusalStatus(completeAppKeyRefusal));

  // Authority-side validation always runs; the `edited` request field is
  // never trusted as an authority gate. Older callers omit both the
  // context token and the selectedActionIds field; those paths still get
  // strict subset+required validation over the SIWE bytes here.
  let baseline: SessionAbilities;
  try {
    const entries = parsePreparedRecap(body.prepared.siwe);
    const signer = { address: signedFields.address, chainId: signedFields.chainId };
    // With no permissions, the baseline is the own folder of the account the
    // request was prepared for, not of the signer. A SIWE re-signed by another
    // address passes this subset check, and the checks after it decide:
    // prepared.address (key-mismatch), the signature, then the context bindings.
    const preview = typeof body.authorizationContextToken === 'string'
      ? peekAuthorizationContext(body.authorizationContextToken) : undefined;
    const [, , , preparedChainId, preparedOwner] = (preview?.ok ? preview.value.spaceId : preparedSpaceId).split(':');
    baseline = baselinePermissions
      ? sessionAbilitiesFromPermissions(baselinePermissions, signer, { deviceTransaction: body.deviceTransactionId !== undefined })
      : ownFolderSessionAbilities(signedFields.domain, preparedOwner
        ? { address: preparedOwner, chainId: Number(preparedChainId) }
        : signer);
    assertBaselineSubset(entries, baseline);
    assertRequiredActions(entries, baseline);
  } catch (e) {
    return c.json(delegateErrorResponse(e, 'Invalid delegation', 'invalid_permissions'), 400);
  }

  const preparedAddress = signedFields.address;
  if (
    body.prepared.address !== undefined
    && String(body.prepared.address).toLowerCase() !== preparedAddress.toLowerCase()
  ) {
    return c.json(
      { error: 'prepared.address does not match the address in the signed SIWE.', code: 'key-mismatch' },
      400,
    );
  }
  // The wallet must have signed exactly these SIWE bytes as that address.
  // Every refusal in this route (signature, signed expiry, context
  // bindings, device window) happens before the single-use context is
  // consumed and before any host activation, so a refused request has no
  // effect and leaves the pending approval usable (TC-587).
  let recoveredAddress = '';
  try {
    recoveredAddress = verifyMessage(String(body.prepared.siwe ?? ''), signature);
  } catch {
    // An unparseable signature is refused below like a mismatched one.
  }
  if (!preparedAddress || recoveredAddress.toLowerCase() !== preparedAddress.toLowerCase()) {
    return c.json(
      { error: 'The signature was not made by the address in the signed SIWE.', code: 'signature-mismatch' },
      400,
    );
  }

  // Whether the signer is the user's primary key, read from this user's
  // record for the signing address. External wallets, and addresses this
  // user does not hold, are never primary.
  const signerKey = await prisma.ethereumKey.findFirst({
    where: { userId: user.id, address: { equals: preparedAddress, mode: 'insensitive' }, archivedAt: null },
    select: { keyType: true, isCanonicalTinyCloud: true, archivedAt: true },
  });
  const primary = signerKey ? isPrimaryKey(signerKey) : false;

  // Report the lifetime the wallet signed, never caller-supplied metadata.
  const expirationTime = siweExpirationTime(body.prepared.siwe);
  if (!expirationTime) {
    return c.json({ error: 'The signed SIWE must include a valid Expiration Time', code: 'missing_expiration_time' }, 400);
  }
  // Signed bytes cannot be shortened, so more than 7 days on secret keys is refused.
  const completeLifetimeReach = exceedsSecretLifetime(body.prepared.siwe, Date.now());
  if (completeLifetimeReach) return c.json(secretLifetimeBody(completeLifetimeReach), 400);

  let contextClaim: AuthorizationContextClaim | undefined;
  let signInAppOrigin: string | undefined;
  let boundRenewal: BoundRenewalChoice | undefined;
  let boundDeviceTransactionId: string | undefined;
  // Versioned callers: the `completeSessionSetup` input, built only from the
  // signed SIWE and the bound context (see below).
  let versionedSessionInput: Record<string, unknown> | undefined;

  if (body.authorizationContextToken) {
    if (typeof body.authorizationContextToken !== 'string') {
      return c.json({ error: 'authorizationContextToken must be a string' }, 400);
    }
    const peekedContext = peekAuthorizationContext(body.authorizationContextToken);
    if (peekedContext.ok) {
      signInAppOrigin = peekedContext.value.appOrigin;
      boundRenewal = peekedContext.value.renewal;
      boundDeviceTransactionId = peekedContext.value.deviceTransactionId;
    }
    if (peekedContext.ok && peekedContext.value.approvalRequestId !== body.approvalRequestId) {
      return c.json({ error: 'Approval request does not match the consent preview' }, 400);
    }
    if (peekedContext.ok) confirmBoundRenewal(body.renewal, boundRenewal);
    if (!Array.isArray(body.selectedActionIds) || body.selectedActionIds.some((id) => typeof id !== 'string')) {
      return c.json({ error: 'selectedActionIds must be a string[] when authorizationContextToken is provided' }, 400);
    }
    const preparedEntries = parsePreparedRecap(body.prepared.siwe || '');
    const immutable = signedFields;

    // Sol MAJOR-5: derive the exact set of action IDs encoded in the SIGNED
    // SIWE and require selectedActionIds to EXACTLY match. The old code
    // only required selectedActionIds to be a subset of the /prepare
    // allowed set — which meant a widget could sign a broad SIWE while
    // returning a narrow selection, or vice versa, and the mismatch would
    // silently pass. The signed-SIWE-encoded set is authoritative.
    const siweEncodedActionIds = new Set<string>();
    for (const entry of preparedEntries) {
      for (const action of entry.actions) {
        siweEncodedActionIds.add(computeActionKey(entry, action));
      }
    }
    const clientSelected = new Set(body.selectedActionIds as string[]);
    // Every action encoded in the signed SIWE must appear in
    // selectedActionIds. Missing entries = the client claims narrower
    // permissions than the SIWE grants.
    const missingFromSelection: string[] = [];
    for (const id of siweEncodedActionIds) {
      if (!clientSelected.has(id)) missingFromSelection.push(id);
    }
    if (missingFromSelection.length > 0) {
      return c.json(
        {
          error: `selectedActionIds is missing entries that appear in the signed SIWE: ${missingFromSelection.slice(0, 5).join(', ')}${missingFromSelection.length > 5 ? ` (and ${missingFromSelection.length - 5} more)` : ''}`,
          code: 'selected_actions_missing_siwe_entries',
        },
        400,
      );
    }
    // Every selectedActionId must appear in the signed SIWE. Extras = the
    // client claims capabilities not actually signed.
    const extrasInSelection: string[] = [];
    for (const id of clientSelected) {
      if (!siweEncodedActionIds.has(id)) extrasInSelection.push(id);
    }
    if (extrasInSelection.length > 0) {
      return c.json(
        {
          error: `selectedActionIds contains entries not present in the signed SIWE: ${extrasInSelection.slice(0, 5).join(', ')}${extrasInSelection.length > 5 ? ` (and ${extrasInSelection.length - 5} more)` : ''}`,
          code: 'selected_actions_exceed_siwe_entries',
        },
        400,
      );
    }

    // Validate every binding without consuming; the context is consumed
    // below, only once the whole request has passed.
    const check = checkAuthorizationContext({
      token: body.authorizationContextToken,
      userId: user.id,
      // Key identity is enforced via keyAddress (which the /complete SIWE
      // always carries); the /prepare context also bound the keyId but we
      // do not require it here.
      keyAddress: preparedAddress,
      jwk: body.jwk,
      host: body.host,
      spaceId: preparedSpaceId,
      selectedActionIds: clientSelected,
      candidateImmutableFieldsDigest: digestImmutableFields(immutable),
      candidateAbilitiesDigest: digestDelegationBaseline(baseline),
      requiredActionIds: requiredActionIdSet(preparedEntries),
    });
    if (!check.ok) {
      return c.json({ error: check.message, code: check.error }, 400);
    }
    // TC-587: an echoed spaceId or verificationMethod that disagrees with
    // the bound space or the signed SIWE's URI (the session key's
    // verificationMethod) is refused here, before the context is consumed.
    if (
      (body.prepared.spaceId !== undefined && body.prepared.spaceId !== check.spaceId)
      || (body.prepared.verificationMethod !== undefined && body.prepared.verificationMethod !== signedFields.uri)
    ) {
      return c.json(
        {
          error: 'prepared.spaceId or prepared.verificationMethod does not match the signed SIWE and the context bound at /prepare',
          code: 'prepared_metadata_mismatch',
        },
        400,
      );
    }
    contextClaim = check.claim;
    // No echoed prepared field reaches WASM: the signed SIWE bytes, the
    // bound space and JWK (digest-equal to body.jwk per the check), and the
    // signed SIWE's URI as verificationMethod.
    versionedSessionInput = {
      siwe: body.prepared.siwe,
      jwk: check.jwk,
      spaceId: check.spaceId,
      verificationMethod: signedFields.uri,
      // The exact string the signature check above verified.
      signature,
    };
  }

  // Device approvals: judge the session key and lifetime by the canonical
  // bytes the wallet signed, not the caller-supplied jwk or a line search.
  const deviceWindow = await deviceDelegationWindowError(body, {
    host: body.host,
    signedSiwe: String(body.prepared?.siwe ?? ''),
  }, !body.authorizationContextToken);
  if (deviceWindow) return c.json(deviceWindow.body, deviceWindow.status);
  if (body.authorizationContextToken) {
    assertDevicePreviewTransaction(boundDeviceTransactionId, body.deviceTransactionId);
    if (boundDeviceTransactionId && boundRenewal?.choice === 'leased') {
      throw new ApprovalResultError('request_binding', "Your wallet signs in for a set time, so this device's access ends at the time shown.", 400);
    }
  }
  if (body.approvalRequestId !== undefined && !body.authorizationContextToken) {
    return c.json({ error: 'Approval requests require the consent preview context' }, 400);
  }
  await checkApprovalDelegation(body, { signedSiwe: body.prepared.siwe });

  // Token-less legacy callers still pass the echoed prepared block (with
  // the caller's JWK, a proper object with kty for WASM deserialization).
  const session = completeSessionSetup(
    versionedSessionInput ?? {
      ...body.prepared,
      jwk: body.jwk,
      signature,
    },
  );

  // Completion is about to succeed: consume the context atomically, only if
  // it is still the exact one checked above. A concurrent completion that
  // consumed it first, or a replay, is refused here.
  if (contextClaim) {
    const consumed = consumeCheckedAuthorizationContext(contextClaim);
    if (!consumed.ok) {
      return c.json({ error: consumed.message, code: consumed.error }, 400);
    }
  }

  await admitApprovalDelegation(body);
  // An attempt that fails after admission gives the admission back (not re-indented, to keep the diff small).
  try {

  const address = preparedAddress;
  const chainId = signedFields.chainId;
  const spaceId = preparedSpaceId;
  let hostActivated = false;
  const signedEntries = parsePreparedRecap(body.prepared.siwe);
  const requestedSpaces = delegationSpaces(signedEntries, baseline);
  let spaceReadiness = activationReadiness(requestedSpaces, signedEntries);
  try {
    const activationResult = await activateSessionWithinTimeout(body.host, session.delegationHeader);
    hostActivated = activationResult.success;
    spaceReadiness = activationReadiness(requestedSpaces, signedEntries, activationResult);
    if (!hostActivated) {
      log('warn', 'delegate_session_activation_warning');
    }
  } catch (e) {
    logError('warn', 'delegate_session_activation_failed', e);
  }

  const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
  const reason = normalizeDelegateReason(body.reason);

  // Effective grants after any narrowing — the SDK consumer uses these
  // to reconcile local state so returned permissions can never appear
  // broader than what was signed.
  let effectiveEntries: RecapEntry[] = [];
  try {
    effectiveEntries = parsePreparedRecap(body.prepared.siwe || '');
  } catch {
    effectiveEntries = [];
  }
  const effectiveGrants = effectiveEntries.map((entry) => ({
    service: entry.service,
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));

  recordAppSignIn(prisma, user.id, signInAppOrigin);
  const delegation = {
    delegationHeader: session.delegationHeader,
    delegationCid: session.delegationCid,
    spaceId,
    ownerDid,
    verificationMethod: session.verificationMethod,
    jwk: body.jwk,
    address,
    chainId,
    primary,
    hostActivated,
    ...spaceReadiness,
    edited: Boolean(body.edited),
    reason,
    expirationTime,
    expiresAt: expirationTime,
    expiry: expirationTime,
    // Echo the SIWE the caller asked us to sign — the SDK extracts
    // `expirationTime` from this when restoring the session, and
    // without it a restored session is treated as expired-at-epoch-zero.
    siwe: body.prepared.siwe,
    // The exact wallet signature verified above and included in the session.
    signature,
    // Versioned protocol additions:
    //   `signedMessage` is the exact bytes the signature verifies against
    //   (identical to `siwe`, but named per the SDK protocol so clients
    //   have a stable field).
    //   `permissions` is the effective grant set after any narrowing.
    signedMessage: body.prepared.siwe,
    permissions: effectiveGrants,
    ...(body.deviceTransactionId && boundRenewal?.choice === 'finite'
      ? { renewal: null, renewalReason: 'renewal_wallet_unsupported' }
      : {}),
  };
  // External-wallet approvals: OpenKey holds neither the wallet key nor the session key, so this path doesn't revoke. The grant's lifetime is whatever the owner chose, with no 24 h bound or 30-day cap (TC-2795).
  return c.json(await saveApprovalDelegation(body, user.id, delegation, { renewal: boundRenewal, host: body.host, sessionId: c.get('session')?.id ?? null }));
  } catch (error) {
    await releaseApprovalDelegation(body);
    throw error;
  }
});

/**
 * POST /api/delegate/authorize-sign-prepare
 *
 * Issues a server-bound authorization context for the OpenKey editable
 * signing flow. The widget MUST call this before `/authorize-sign` — the
 * caller-echoed SIWE, JWK, and selection are NEVER trusted as authority.
 *
 * The context binds:
 *   - authenticated user
 *   - keyId and its EIP-55 address (looked up server-side)
 *   - JWK (structural digest)
 *   - the immutable SIWE header fields (domain, address, uri, version,
 *     chainId, nonce, issuedAt, expirationTime, notBefore, requestId,
 *     statement, non-ReCap resources)
 *   - the allowed set of action IDs
 *   - the initial selection (subset of allowed)
 *   - the space ID
 *   - the original SIWE bytes (so /authorize-sign narrows from a
 *     server-bound baseline)
 *   - a 5-minute single-use token
 *
 * The response returns the opaque token plus the allowed/initial action
 * IDs so the widget can render a review page.
 */
delegateRouter.post('/authorize-sign-prepare', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    keyId: string;
    /** Caller-supplied SIWE that will be narrowed by /authorize-sign. */
    siwe: string;
    /** Session JWK; digested and stored so /authorize-sign cannot swap it. */
    jwk: DelegationJwk;
    /**
     * Optional. The host the resulting session will activate against. Bound
     * into the context so /authorize-sign cannot swap hosts. Defaults to
     * empty when the widget will not activate a delegation directly.
     */
    host?: string;
    /**
     * Optional presentation envelope forwarded by the widget. Display-only
     * — bound into the authorization context so the review UI can render
     * honest provenance labels. Size-bounded (≤16KB) and validated below.
     * The envelope MUST NOT expand authority; the ReCap payload remains
     * the sole gate for what the user can approve.
     */
    presentation?: {
      protocolVersion?: number;
      displayName?: string;
      reason?: string;
      manifestId?: string;
      manifestDigest?: string;
      /** Reported owner identifier. Compared with the key-derived owner; never used as a value. */
      owner?: string;
      manifests?: Array<{
        name?: string;
        appId?: string;
        payload?: Record<string, unknown>;
      }>;
    };
    /**
     * Optional. The browser origin the widget verified from the
     * postMessage sender. When present AND https, the server attempts an
     * SSRF-guarded fetch of `.well-known/openkey-manifest.json` and
     * compares its canonical SHA-256 to `presentation.manifestDigest`.
     * A successful compare upgrades the metadata-trust status to
     * `origin-bound`; any failure fails closed to `unsigned`.
     */
    reportedOrigin?: string;
    /**
     * The origin the widget verified from the postMessage sender. A
     * SIWE-shaped `siwe` must name exactly this origin (domain and web URI);
     * absent or unattributed is refused. Distinct from `reportedOrigin`,
     * which only drives the optional manifest origin-bind.
     */
    requestOrigin?: string;
    /** TC-2272: the app sends `expiryChangeable: true` when it accepts a different signed expiry. */
    expiryChangeable?: unknown;
    /** The app's renewal ask for this sign-in (`{ version: 1, leaseLifetimeSeconds }`); ignored while leases are off. */
    renewal?: unknown;
    requesterOrigin?: unknown;
    ticket?: string;
    transportVersion?: number;
    callback?: unknown;
    delivery?: unknown;
  }>();
  if (body.requesterOrigin !== undefined) {
    return c.json({ error: 'requesterOrigin is only supported for ordinary delegation preparation', code: 'requester_origin_unsupported' }, 400);
  }
  const privateMembers = hasPrivateJwkMember(body.jwk);
  logSessionJwk('/api/delegate/authorize-sign-prepare', privateMembers);
  if (privateMembers) countPrivateSessionJwk('/api/delegate/authorize-sign-prepare');
  // Only the session key's public members are used or stored; a malformed
  // key counts as missing.
  body.jwk = publicJwk(body.jwk) as DelegationJwk;
  const deviceUnsupported = deviceTransactionUnsupportedError(body);
  if (deviceUnsupported) return c.json(deviceUnsupported, 400);

  if (!body.keyId || !body.siwe || !body.jwk || typeof body.jwk !== 'object') {
    return c.json(
      { error: 'keyId, siwe, and jwk are required', code: 'missing_authorize_sign_prepare_fields' },
      400,
    );
  }
  if (typeof body.siwe !== 'string') {
    return c.json({ error: 'siwe must be a string', code: 'invalid_siwe' }, 400);
  }
  const invalidRequestSiwe = invalidSiweMessage(body.siwe, 'characters');
  if (invalidRequestSiwe) return c.json(invalidRequestSiwe, 400);
  const ticket = handoffTicket(body);
  // TC-1486: refuse a SIWE that names a different site than the verified
  // requester, or that arrives unattributed. Prepared-handoff tickets are
  // exempt: their request was bound at claim time and the requester is a
  // local CLI, not a browser origin.
  let siweOriginChecked = false;
  if (!ticket && typeof body.siwe === 'string') {
    const siweCheck = checkSiweOrigin(body.siwe, body.requestOrigin);
    if (siweCheck.siwe && !siweCheck.ok) {
      return c.json({ error: siweCheck.message, code: 'siwe_origin_refused', reason: siweCheck.code }, 403);
    }
    siweOriginChecked = siweCheck.siwe && siweCheck.ok;
  }
  const handoffTicketHash = ticket
    ? await activePreparedHandoffService.assertRequest(ticket, user.id, {
      keyId: body.keyId, siwe: body.siwe, jwk: body.jwk, host: body.host ?? '',
      presentation: body.presentation, reportedOrigin: body.reportedOrigin,
    })
    : undefined;

  const key = await prisma.ethereumKey.findFirst({
    where: {
      id: body.keyId,
      userId: user.id,
      archivedAt: null,
    },
    select: {
      id: true,
      userId: true,
      address: true,
      keyType: true,
      archivedAt: true,
      sealedBlob: true,
      sealingContext: true,
    },
  });
  if (!key) {
    return c.json({ error: 'Key not found', code: 'key_not_found' }, 404);
  }

  // Only ReCap SIWE requests can be narrowed. Legacy exact-byte signing
  // uses /api/keys/:id/sign.
  let originalEntries: RecapEntry[];
  try {
    originalEntries = parsePreparedRecap(body.siwe);
  } catch (e) {
    return c.json(
      {
        error: UNREADABLE_RECAP_MESSAGE,
        code: 'invalid_siwe_recap',
      },
      400,
    );
  }
  if (originalEntries.length === 0) {
    return c.json(
      {
        error:
          'authorize-sign-prepare requires a SIWE with ReCap capabilities; use /api/keys/:id/sign for byte-exact signing',
        code: 'not_a_recap_siwe',
      },
      400,
    );
  }
  // Messages that name key.delete, an unreadable recap or an unparsable
  // `apps/` key are refused here. A well-formed `apps/` grant from a browser
  // request is admitted or refused after the manifest bind below; a ticket
  // request carries no origin and is always refused.
  const prepareSignAppKeyRefusal = appKeyRefusalForSiwe(body.siwe, originalEntries);
  let appKeyCandidate = false;
  if (prepareSignAppKeyRefusal) {
    if (prepareSignAppKeyRefusal.reason !== 'apps_key' || ticket) {
      return c.json(appKeyRefusalBody(prepareSignAppKeyRefusal, ticket ? 'non_browser' : 'browser'), appKeyRefusalStatus(prepareSignAppKeyRefusal));
    }
    appKeyCandidate = true;
  }
  // A website's own sign-in (no ticket) may ask to `decrypt`, `key.create`, `key.block` or `key.unblock` on the
  // encryption network, or on keys outside its own `apps/` prefix, with a per-permission warning the owner decides
  // on (TC-2927); the decision is checked at the preview. What is never accepted from any app, ours included, is an
  // exact share key (`share/<id>`) that OpenKey did not make for the request. A ticket request (the command line's
  // `--keys <folder>`) is not checked here.
  const prepareEncryptionRefusal = ticket ? null : exactShareKeyRefusal(body.siwe);
  if (prepareEncryptionRefusal) {
    return c.json(appKeyRefusalBody(prepareEncryptionRefusal, 'browser'), appKeyRefusalStatus(prepareEncryptionRefusal));
  }
  // `key.block` and `key.unblock` on a key or prefix outside `apps/` take the same road as `decrypt`: a website's
  // own sign-in (no ticket) shows the owner the warning screen and the decision is checked at the preview. A
  // ticket request carries no owner decision and is always refused.
  if (ticket && blockResourcesOutsideApps(body.siwe).length > 0) {
    const refusal = { reason: 'apps_key' } as const;
    return c.json(appKeyRefusalBody(refusal, 'non_browser'), appKeyRefusalStatus(refusal));
  }
  let boundDeclaredAppId: string | undefined;
  let boundDeclaredKeysAppId: string | undefined;
  let boundDeclaredKeys: ManifestKeys | undefined;

  const keyAddress = ensureEip55(key.address);
  // Sol MAJOR-2: parse chainId from the SIWE rather than hard-coding it.
  // The widget-supplied SIWE carries the chain the caller wants to bind
  // the delegation to; if we substitute a server default the immutable
  // digest check becomes tautological.
  const chainIdMatch = body.siwe.match(/^Chain ID:\s*(\d+)\s*$/m);
  const chainId = chainIdMatch?.[1] ? Number(chainIdMatch[1]) : Number.NaN;
  if (!Number.isFinite(chainId) || chainId < 1) {
    return c.json(
      { error: 'SIWE is missing a valid Chain ID', code: 'invalid_siwe_chainid' },
      400,
    );
  }

  // ReCap resources can cover several spaces; the primary is for routing only.
  if (originalEntries.length === 0) {
    return c.json(
      { error: 'ReCap has no entries', code: 'empty_recap_entries' },
      400,
    );
  }
  const spaceId = primaryRoutingSpace(delegationSpaces(originalEntries).map(space => space.spaceId), makeSpaceId(keyAddress, chainId, 'default'));

  // A request the pre-sign rule cannot read can never be signed; refuse it
  // before issuing a context and a review screen for it.
  const readable = parseStrictSiwe(body.siwe);
  if (!readable.ok) {
    return c.json(
      { error: `The requested SIWE is not well formed: ${readable.message}`, code: SIGNED_SUBSET_REFUSAL_CODE, reason: 'request_unparsable' },
      400,
    );
  }
  // A message that hosts a space is the ability to create it: the rule of POST /api/keys/:id/sign applies, from the
  // origin the SIWE was just checked against (`siweOriginChecked`). No checked origin is another site. Refused here, so
  // no context and no review screen is issued for it; /authorize-sign applies it again to the bytes it signs.
  if (await refusesSpaceHost({
    message: body.siwe, key,
    authority: () => originProvisionAuthority(siweOriginChecked && typeof body.requestOrigin === 'string' ? body.requestOrigin : undefined),
  })) {
    return c.json(HOST_SIGNING_REFUSAL_BODY, 403);
  }
  const immutable = extractImmutableSiweFields(body.siwe, {
    chainId,
    spaceId,
  });
  if (!immutable.issuedAt || !immutable.expirationTime || !immutable.nonce) {
    return c.json(
      {
        error: 'SIWE is missing required header fields (issuedAt, expirationTime, or nonce)',
        code: 'invalid_siwe_header',
      },
      400,
    );
  }
  // The grant is signed to the Expiration Time and the length rules read Expiration Time minus Issued At, so an
  // Issued At ahead of the clock would shorten the length the rules see. Issued At is refused past the clock skew.
  if (Date.parse(immutable.issuedAt) > Date.now() + MAX_ISSUED_AT_SKEW_MS) {
    return c.json(
      {
        error: 'The SIWE Issued At is in the future. Set Issued At to the current time and send the request.',
        code: 'invalid_siwe_header',
      },
      400,
    );
  }
  // The renewal lease counts its window from Not Before when the message has one, so a Not Before ahead of the
  // clock would move the lease past the end the approval screen showed. Not Before is refused past the same skew.
  if (immutable.notBefore && Date.parse(immutable.notBefore) > Date.now() + MAX_ISSUED_AT_SKEW_MS) {
    return c.json(
      {
        error: 'The SIWE Not Before is in the future. Set Not Before to the current time or remove it and send the request.',
        code: 'invalid_siwe_header',
      },
      400,
    );
  }
  // Sol MAJOR-2: verify the SIWE's own address/chainId match what the
  // caller ended up bound to. The signer key selection (via keyId) is
  // independent from the SIWE header; drift here means the widget or a
  // MITM is proposing to sign SIWE bytes for a different account.
  if (immutable.address.toLowerCase() !== keyAddress.toLowerCase()) {
    return c.json(
      {
        error: `SIWE address ${immutable.address} does not match bound signer key ${keyAddress}`,
        code: 'siwe_address_mismatch',
      },
      400,
    );
  }
  if (immutable.chainId !== chainId) {
    return c.json(
      {
        error: `SIWE chainId ${immutable.chainId} does not match parsed Chain ID ${chainId}`,
        code: 'siwe_chainid_mismatch',
      },
      400,
    );
  }

  const allowedActionIds = allowedActionIdSet(originalEntries);
  const initialSelectionActionIds = new Set(allowedActionIds);

  // Sol MAJOR-4: caveat-inclusive baseline digest. Previously we digested
  // `entriesToAbilities(entries)` which threw away caveats — making the
  // /authorize-sign candidate comparison tautological because both sides
  // were derived from the same caveat-stripped `entries`. We now digest
  // the FULL ReCap attenuation extracted from the ORIGINAL SIWE bytes,
  // including per-(resource, ability) caveat multisets. On finalize we
  // recompute the candidate digest from the regenerated `signedMessage`
  // (not the bound `originalEntries`) so a caveat-dropping regeneration
  // fails the equality check.
  const baselineAttenuation = extractRecapAttenuationFromSiwe(body.siwe);
  const baselineAbilitiesDigest = digestFullRecapAttenuation(baselineAttenuation);

  // Envelope validation + optional origin-bind. Fail-closed: any validation
  // failure downgrades to `unsigned` — envelope metadata NEVER expands
  // authority, and the caller cannot claim `verified` from the client side.
  let metadataTrust: {
    status: 'verified' | 'origin-bound' | 'unsigned';
    reason: string;
  } = { status: 'unsigned', reason: 'no manifest supplied' };
  let verifiedManifest:
    | {
        name?: string;
        appId?: string;
        manifestId?: string;
        manifestDigest?: string;
        reportedOrigin?: string;
        /**
         * Sol MAJOR-2: only present when origin-bind succeeded AND the
         * manifest carried a `secrets` block AND/or a `permissions`
         * block. The widget uses these to decide whether a KV/SQL
         * secret grant matches an app-declared scoped secret. Missing
         * or mismatched → grant stays sensitive.
         */
        declaredAppScope?: {
          prefix?: string;
          defaultSpace?: string;
          secrets?: Array<{ secretName: string; scope?: string; actions: string[] }>;
          permissions?: Array<{ service: string; space?: string; path: string; actions: string[] }>;
        };
      }
    | undefined;

  if (body.presentation !== undefined) {
    const envelope = body.presentation;
    if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
      metadataTrust = { status: 'unsigned', reason: 'presentation envelope was not an object' };
    } else {
      // Size-bound the envelope. 16KB matches the widget-transport limit.
      let serialized: string | null = null;
      try {
        serialized = JSON.stringify(envelope);
      } catch {
        serialized = null;
      }
      const bytes = serialized ? Buffer.byteLength(serialized, 'utf8') : Number.POSITIVE_INFINITY;
      if (!serialized) {
        metadataTrust = { status: 'unsigned', reason: 'presentation envelope was not serializable' };
      } else if (bytes > 16 * 1024) {
        metadataTrust = {
          status: 'unsigned',
          reason: `presentation envelope size ${bytes} bytes exceeds 16KB limit`,
        };
      } else {
        // Optional origin-bind: only attempted when reportedOrigin is
        // present and https AND the envelope carries a manifestDigest.
        const reportedOrigin =
          typeof body.reportedOrigin === 'string' && body.reportedOrigin.startsWith('https://')
            ? body.reportedOrigin
            : null;
        const declaredDigest =
          typeof envelope.manifestDigest === 'string' && envelope.manifestDigest.length > 0
            ? envelope.manifestDigest
            : null;
        if (reportedOrigin && declaredDigest) {
          try {
            // `owner` is derived from the signing key and resolves `{owner}`
            // in the published manifest. The envelope's owner is only a hint
            // compared against it, never a value.
            const bindResult = await fetchAndBindWellKnownManifest({
              reportedOrigin,
              declaredDigest,
              owner: Number.isInteger(chainId)
                ? `did:pkh:eip155:${chainId}:${keyAddress}`
                : undefined,
              ownerHint: typeof envelope.owner === 'string' ? envelope.owner : undefined,
            });
            if (bindResult.ok) {
              metadataTrust = {
                status: 'origin-bound',
                reason: `manifest at ${reportedOrigin}/.well-known/openkey-manifest.json matched declared digest`,
              };
              // Sol MAJOR-2: forward the declared secrets + permissions
              // block extracted from the origin-bound (digest-matched)
              // manifest. The widget uses this to decide whether a
              // scoped-secret grant matches an app declaration; absent
              // a match, the grant stays sensitive. Never used to
              // expand authority.
              const declaredAppScope =
                bindResult.manifest?.declaredSecrets || bindResult.manifest?.declaredPermissions
                  ? {
                      prefix: bindResult.manifest?.prefix,
                      defaultSpace: bindResult.manifest?.defaultSpace,
                      secrets: bindResult.manifest?.declaredSecrets,
                      permissions: bindResult.manifest?.declaredPermissions,
                    }
                  : undefined;
              // Sol MAJOR-4: never fall back to caller-supplied
              // envelope fields for `name` or `manifestId` while
              // marking trust `origin-bound`. Origin-bind proves the
              // FETCHED manifest matched the declared digest — it says
              // nothing about the envelope's displayName / manifestId.
              // Silently merging the envelope in would let a caller
              // present an unverified label to the operator inside a
              // field the widget renders as "from origin-bound
              // manifest". The widget layer adds envelope fallbacks
              // separately with a distinct `caller-supplied,
              // unverified` provenance tag.
              verifiedManifest = {
                name: bindResult.manifest?.name,
                appId: bindResult.manifest?.appId,
                manifestId: bindResult.manifest?.manifestId,
                manifestDigest: declaredDigest.toLowerCase(),
                reportedOrigin,
                declaredAppScope,
              };
              boundDeclaredAppId = bindResult.manifest?.declaredAppId;
              boundDeclaredKeysAppId = bindResult.manifest?.declaredKeysAppId;
              boundDeclaredKeys = bindResult.manifest?.declaredKeys;
            } else {
              metadataTrust = {
                status: 'unsigned',
                reason: `origin-bind failed: ${bindResult.reason ?? 'unknown reason'}`,
              };
            }
          } catch (bindErr) {
            logError('warn', 'delegate_origin_bind_failed', bindErr);
            metadataTrust = { status: 'unsigned', reason: 'origin-bind threw' };
          }
        } else {
          metadataTrust = {
            status: 'unsigned',
            reason: reportedOrigin
              ? 'presentation envelope has no manifestDigest to bind'
              : 'no https reportedOrigin supplied',
          };
        }
      }
    }
  }

  // `apps/` encryption key grants are admitted here. A successfully bound
  // manifest may narrow the app's keys; otherwise the browser origin supplies
  // the app namespace and the user's approval remains the authority boundary.
  let admittedAppKeys: AdmittedAppKey[] | undefined;
  if (appKeyCandidate) {
    const originAppId = appIdForOrigin(typeof body.requestOrigin === 'string' ? body.requestOrigin : '');
    const manifestBound = metadataTrust.status === 'origin-bound';
    const admission = admitAppKeys({
      siwe: body.siwe,
      resources: appKeyResourcesOf(body.siwe) ?? [],
      requestOrigin: body.requestOrigin,
      // A browser channel origin is sufficient when no signed manifest was
      // verified. `reportedOrigin` remains the origin-bind input when a
      // manifest was verified and an optional consistency check otherwise.
      reportedOrigin: body.reportedOrigin ?? (manifestBound ? undefined : body.requestOrigin),
      siweOriginChecked,
      ticket: Boolean(ticket),
      manifestBound: manifestBound || originAppId !== null,
      declaredAppId: manifestBound ? boundDeclaredAppId : originAppId ?? undefined,
      declaredKeysAppId: manifestBound ? boundDeclaredKeysAppId : originAppId ?? undefined,
      declaredKeys: manifestBound ? boundDeclaredKeys : originAppId ? {
        status: 'valid',
        declarations: [{ prefix: `apps/${originAppId}/`, abilities: ['key.create', 'decrypt', 'key.block', 'key.unblock'] }],
      } : undefined,
      ownerDid: `did:pkh:eip155:${chainId}:${keyAddress}`,
      expirationTime: immutable.expirationTime,
    });
    if (!admission.ok) {
      const refusal = appKeyAdmissionRefusal(admission.reason);
      return c.json(
        appKeyRefusalBody(refusal, admission.reason === 'non_browser' ? 'non_browser' : 'browser'),
        appKeyRefusalStatus(refusal),
      );
    }
    // Every `apps/` resource of the message, as the parser and the text scan
    // both see it, must be one of the admitted resources.
    const notAdmitted = appKeyRefusalForSiwe(body.siwe, originalEntries, admission.admitted);
    if (notAdmitted) return c.json(appKeyRefusalBody(notAdmitted, 'browser'), appKeyRefusalStatus(notAdmitted));
    admittedAppKeys = admission.admitted;
  }

  let signInRenewal: SignInRenewalRequest | undefined;
  try {
    signInRenewal = bindSignInRenewalRequest(body.renewal, {
      host: typeof body.host === 'string' ? body.host : '', handoff: Boolean(ticket), expiryChangeable: body.expiryChangeable === true,
    });
  } catch (error) {
    const refused = signInRenewalFailure(error);
    return c.json(refused.body, refused.status);
  }

  let issued: AuthorizationContextToken;
  try {
    issued = issueAuthorizationContext({
      userId: user.id,
      keyId: key.id,
      keyAddress,
      jwk: body.jwk,
      host: typeof body.host === 'string' ? body.host : '',
      spaceId,
      baselineAbilitiesDigest,
      immutableFieldsDigest: digestImmutableFields(immutable),
      allowedActionIds,
      initialSelectionActionIds,
      expirationTime: immutable.expirationTime,
      originalSiwe: body.siwe,
      handoffTicketHash,
      metadataTrust,
      verifiedManifest,
      // The widget-reported sender origin of the requesting app. Used only for
      // the per-sign-in count record; never for trust or authority.
      appOrigin: normalizeAppOrigin(body.reportedOrigin) ?? undefined,
      // The origin the SIWE was checked against above; decides whether OpenKey may set up the account on the node.
      requestOrigin: siweOriginChecked && typeof body.requestOrigin === 'string' ? body.requestOrigin : undefined,
      admittedAppKeys,
      expiryChangeable: body.expiryChangeable === true,
      signInRenewal,
    });
  } catch (issueErr) {
    logError('warn', 'delegate_authorization_context_issue_failed', issueErr);
    return c.json(
      { error: 'Failed to issue authorization context', code: 'authorization_context_failed' },
      500,
    );
  }
  if (ticket) {
    await activePreparedHandoffService.bindContext(ticket, user.id, {
      keyId: key.id, siwe: body.siwe, jwk: body.jwk, host: body.host ?? '',
      authorizationContextToken: issued.token,
    });
  }

  return c.json({
    authorizationContextToken: issued.token,
    expiresAt: issued.expiresAt,
    allowedActionIds: issued.allowedActionIds,
    initialSelectionActionIds: issued.initialSelectionActionIds,
    baselineAbilitiesDigest: issued.baselineAbilitiesDigest,
    // Echo the address the token is bound to so the widget can verify it
    // matches the signer it is about to use.
    address: keyAddress,
    spaceId,
    // Server-decided trust + verified manifest fields. The widget MUST
    // render trust from THIS value, not from the envelope it forwarded.
    metadataTrust: issued.metadataTrust,
    verifiedManifest: issued.verifiedManifest,
    // The renewal box is offered only when the ask is bound: leases on, and a node OpenKey sets leases up on.
    ...(signInRenewal ? { renewal: { leaseLifetimeSeconds: signInRenewal.leaseLifetimeSeconds } } : {}),
  });
});

/**
 * POST /api/delegate/authorize-sign
 *
 * Server-authoritative signing for OpenKey `authorizeTinyCloud` flow (Sol
 * CRITICAL-1). Sol continuation contract: the caller-echoed SIWE, JWK,
 * selection, host, or baseline are NEVER trusted as authority. This route
 * requires an opaque, expiring, single-use `authorizationContextToken` that
 * was issued by `/api/delegate/authorize-sign-prepare` and is bound to the
 * authenticated user, the signer key, the JWK, the immutable SIWE header
 * fields, the allowed action set, and the original SIWE bytes.
 *
 * Flow:
 *   1. Look up the user's candidate keys, then peek the context and reject
 *      a different owner before inspecting its selection.
 *   2. Rehydrate the ORIGINAL SIWE, JWK, and allowed action set from the
 *      bound context (never from the request body); validate all bindings.
 *   3. Narrow the original entries and check the preview approval and any
 *      external signature against the exact bytes to return.
 *   4. Atomically consume the checked context and preview approval together.
 *   5. Sign with the bound managed key or return the verified external signature.
 *   6. Return `{ protocolVersion, address, signature, signedMessage,
 *      selectedActionKeys, permissions }`.
 *
 * The old bug (widget approves narrow, signs broad) is prevented because
 * the server both selects the SIWE bytes to sign AND emits the effective
 * selection metadata — they are always consistent by construction.
 */
delegateRouter.post('/authorize-sign', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    /** REQUIRED: opaque single-use token from /authorize-sign-prepare. */
    authorizationContextToken?: string;
    /**
     * REQUIRED (Sol CRITICAL-1): opaque single-use token issued by
     * /authorize-sign-preview. Seals the exact selectedActionIds and
     * signedMessage the preview evaluated, so /authorize-sign cannot
     * independently accept a different selection or sign different bytes.
     */
    previewApprovalToken?: string;
    /** The action IDs the user finally selected. */
    selectedActionIds: unknown;
    /** Optional protocol marker; must be >= 1 when present. */
    protocolVersion?: number;
    /**
     * Sol MAJOR-1: for external-key completion. When present, the server
     * uses THIS signature over the exact regenerated bytes rather than
     * signing with a managed key. The signature MUST verify against
     * `signedMessage` for `keyAddress`. External keys never see the SIWE
     * bytes before the server has bound them into the authorization
     * context — the widget shows the SDK-supplied SIWE, the wallet signs
     * whatever bytes /authorize-sign returns after narrowing.
     *
     * For the external path, callers should first invoke this route with
     * `externalSignature: ""` (or omit it) to receive the preview bytes,
     * sign them with their wallet, and re-invoke with the signature.
     * However the token is single-use — so the preview + sign flow uses
     * the peek+preview API (see /authorize-sign-preview).
     */
    externalSignature?: string;
    /** Optional: repeats the renewal choice sealed with the preview; any other choice is refused. */
    renewal?: unknown;
    /** TC-3442: `{ challengeToken, response }` for the challenge the preview offered, when Approve needs the passkey. */
    passkeyAssertion?: unknown;
    ticket?: string;
    transportVersion?: number;
    callback?: unknown;
    delivery?: unknown;
    state?: unknown;
  }>();
  const deviceUnsupported = deviceTransactionUnsupportedError(body);
  if (deviceUnsupported) return c.json(deviceUnsupported, 400);
  const ticket = handoffTicket(body);

  if (typeof body.authorizationContextToken !== 'string' || !body.authorizationContextToken) {
    return c.json(
      { error: 'authorizationContextToken is required — call /authorize-sign-prepare first', code: 'missing_authorization_context_token' },
      400,
    );
  }
  // Sol CRITICAL-1: /authorize-sign REQUIRES a preview-approval token so
  // finalize cannot independently accept a selection or sign bytes the
  // user did not preview.
  if (typeof body.previewApprovalToken !== 'string' || !body.previewApprovalToken) {
    return c.json(
      {
        error:
          'previewApprovalToken is required — call /authorize-sign-preview and echo the returned token',
        code: 'missing_preview_approval_token',
      },
      400,
    );
  }
  if (
    !Array.isArray(body.selectedActionIds) ||
    body.selectedActionIds.some((id) => typeof id !== 'string')
  ) {
    return c.json(
      { error: 'selectedActionIds must be a string[]', code: 'invalid_selected_action_ids' },
      400,
    );
  }
  if (
    body.protocolVersion !== undefined &&
    (typeof body.protocolVersion !== 'number' || body.protocolVersion < 1)
  ) {
    return c.json(
      { error: 'protocolVersion must be >= 1 when supplied', code: 'invalid_protocol_version' },
      400,
    );
  }
  const selectedActionIds = new Set(body.selectedActionIds as string[]);

  // Sol MAJOR-1: accept BOTH managed and external keys. Managed keys
  // have sealedBlob != null; external keys have sealedBlob == null and
  // require a caller-supplied signature.
  const candidateKeys = await prisma.ethereumKey.findMany({
    where: {
      userId: user.id,
      archivedAt: null,
    },
    select: {
      id: true,
      userId: true,
      address: true,
      keyType: true,
      archivedAt: true,
      sealedBlob: true,
      sealingContext: true,
    },
  });
  if (candidateKeys.length === 0) {
    return c.json({ error: 'No keys found', code: 'key_not_found' }, 404);
  }

  // Peek only to identify the bound key; the checked context claim below
  // validates every binding before the atomic consume just before signing.
  const preview = peekAuthorizationContext(body.authorizationContextToken);
  if (!preview.ok) {
    if (ticket && preview.error === 'context-not-found') {
      return c.json({ code: 'handoff_context_unavailable', error: 'Authorization context is unavailable on this server; cancel and restart with a new handoff.' }, 409);
    }
    return c.json({ error: preview.message, code: preview.error }, 400);
  }
  const bound = preview.value;
  await assertHandoffContext(ticket, user.id, body.authorizationContextToken, bound.handoffTicketHash);
  // Peek is not an authority check. Reject another account before any
  // selection-dependent response, even when it has the same external
  // wallet linked under a different spelling of the address.
  if (bound.userId !== user.id) {
    return c.json({ error: 'Authorization context bound to a different user', code: 'user_mismatch' }, 400);
  }
  const key = candidateKeys.find(
    (k) => k.id === bound.keyId && ensureEip55(k.address).toLowerCase() === bound.keyAddress.toLowerCase(),
  );
  if (!key) {
    return c.json({ error: 'Bound key not found', code: 'key_not_found' }, 404);
  }
  // Managed keys require sealedBlob; external keys require an
  // externalSignature. Fail closed if the request/key state doesn't
  // match.
  const isExternal = key.keyType === 'EXTERNAL';
  if (isExternal) {
    if (typeof body.externalSignature !== 'string' || !body.externalSignature) {
      return c.json(
        {
          error: 'External keys require an externalSignature in the /authorize-sign body',
          code: 'external_signature_required',
        },
        400,
      );
    }
  } else {
    if (!key.sealedBlob) {
      return c.json(
        { error: 'Managed key has no sealed blob', code: 'key_state_invalid' },
        500,
      );
    }
  }
  const boundAddress = ensureEip55(key.address);

  // Re-parse the bound original SIWE to derive required action IDs.
  let originalEntries: RecapEntry[];
  try {
    originalEntries = parsePreparedRecap(bound.originalSiwe);
  } catch (e) {
    return c.json(
      {
        error: e instanceof Error ? e.message : 'Bound SIWE could not be re-parsed',
        code: 'bound_siwe_parse_failed',
      },
      500,
    );
  }
  // Parse chainId from the bound original SIWE — never hard-code.
  const chainIdMatch = bound.originalSiwe.match(/^Chain ID:\s*(\d+)\s*$/m);
  const chainId = chainIdMatch?.[1] ? Number(chainIdMatch[1]) : 1;
  const immutable = extractImmutableSiweFields(bound.originalSiwe, {
    chainId,
    spaceId: bound.spaceId,
  });
  if (appKeyGroupPartial(
    admittedAppKeyActionIds(originalEntries, bound.admittedAppKeys, computeActionKey),
    groupRuleActionIds(originalEntries, ticket),
    selectedActionIds,
  )) {
    return c.json({ error: APP_KEY_GROUP_PARTIAL_MESSAGE, code: APP_KEY_GROUP_PARTIAL_CODE }, 400);
  }

  // Sol MAJOR-4: attenuation-subset check against the caveat-inclusive
  // baseline. We build the candidate attenuation from the SELECTED
  // entries (paired with the ORIGINAL caveats for each surviving
  // (resource, ability) pair) so the check can verify:
  //   1. baselineAttenuation digest matches what /prepare recorded, AND
  //   2. candidateAttenuation is a strict subset (narrowing OK, broadening
  //      or caveat-dropping rejected).
  const baselineAttenuation = extractRecapAttenuationFromSiwe(bound.originalSiwe);
  const candidateAttenuation = buildCandidateAttenuation(
    originalEntries,
    selectedActionIds,
    baselineAttenuation,
  );

  // Validate the bound context without using it up. Every remaining
  // refusal, including the preview approval and external signature, must
  // run before the checked context is consumed.
  const check = checkAuthorizationContext({
    token: body.authorizationContextToken,
    userId: user.id,
    handoffTicketHash: bound.handoffTicketHash,
    keyId: key.id,
    keyAddress: boundAddress,
    jwk: bound.jwk,
    host: bound.host,
    spaceId: bound.spaceId,
    selectedActionIds,
    candidateImmutableFieldsDigest: digestImmutableFields(immutable),
    candidateAttenuation,
    baselineAttenuation,
    requiredActionIds: requiredActionIdSet(originalEntries),
  });
  if (!check.ok) {
    return c.json({ error: check.message, code: check.error }, 400);
  }
  // Context validation takes precedence for required actions and unknown IDs:
  // [] with required actions is required-action-missing, and an unknown ID
  // is action-not-in-baseline. Only a valid empty selection reaches this guard.
  if (selectedActionIds.size === 0) {
    return c.json(
      { error: 'No selected actions map to any capability in the SIWE', code: 'empty_selection' },
      400,
    );
  }
  const selectedEntries = entriesForSelectedActions(originalEntries, selectedActionIds);
  if (selectedEntries.length === 0) {
    return c.json(
      { error: 'No selected actions map to any capability in the SIWE', code: 'empty_selection' },
      400,
    );
  }

  // Sol critical-2 (exact bytes / unchanged-selection branch): if the
  // caller's selection EXACTLY matches the baseline (no narrowing), sign
  // the ORIGINAL SIWE bytes verbatim. This preserves the exact-byte
  // guarantee for callers that opened /authorize-sign purely to obtain a
  // signature (never edited the review UI) — a legacy signMessage-shaped
  // callback consumer must not receive re-serialized bytes that only
  // differ in whitespace, statement text, or line ordering.
  const originalActionKeys = new Set<string>();
  for (const entry of originalEntries) {
    for (const action of entry.actions) {
      originalActionKeys.add(computeActionKey(entry, action));
    }
  }
  const selectionUnchanged =
    selectedActionIds.size === originalActionKeys.size &&
    [...selectedActionIds].every((id) => originalActionKeys.has(id));

  // Sol continuation contract (caveats): removing a whole ability or a
  // whole resource is allowed even when the baseline carries meaningful
  // caveats — the removed caveats leave with their ability/resource.
  // The narrower is responsible for splicing the ORIGINAL caveat multiset
  // onto every surviving (resource, ability) pair (WASM's regenerator
  // emits `[{}]` regardless of input caveats, so we cannot trust its
  // payload). See `narrowSiwePreservingImmutable` + `rewriteRecapLineCaveats`.

  let signedMessage: string;
  if (selectionUnchanged) {
    // Sign the server-bound original SIWE bytes verbatim.
    signedMessage = bound.originalSiwe;
  } else {
    // Sol CRITICAL-1: narrow via the preservation splice. The prior
    // implementation rejected every real production SIWE because the
    // ReCap-derived `statement` line is non-empty on every prepared
    // SIWE. We now use `narrowSiwePreservingImmutable`, which regenerates
    // the SIWE via WASM `prepareSession` for the narrowed abilities and
    // splices ONLY the ReCap-derived statement + `- urn:recap:` lines
    // back into the ORIGINAL SIWE bytes. Every immutable header field
    // (URI, Version, Chain ID, Nonce, Issued At, Expiration Time, Not
    // Before, Request ID, non-ReCap resources) survives byte-for-byte.
    //
    // Sol continuation contract (caveats, final): the narrower is given
    // `baselineCaveats` so the ORIGINAL caveat multiset survives on every
    // (resource, ability) pair that remains. Whole-ability and
    // whole-resource removals drop their caveats with them (legal).
    const narrowed = narrowSiwePreservingImmutable({
      originalSiwe: bound.originalSiwe,
      narrowedEntries: selectedEntries,
      address: boundAddress,
      chainId,
      domain: immutable.domain,
      issuedAt: immutable.issuedAt,
      expirationTime: immutable.expirationTime,
      spaceId: bound.spaceId,
      jwk: check.jwk,
      baselineCaveats: baselineAttenuation,
      ...(immutable.notBefore ? { notBefore: immutable.notBefore } : {}),
    });
    if (!narrowed.ok) {
      return c.json({ error: narrowed.message, code: narrowed.code }, 400);
    }
    // Sol MAJOR-2: cross-check that the regenerated candidate preserves
    // EVERY TRULY IMMUTABLE header field. The SIWE `statement` line is a
    // text encoding of the ReCap contents (the "I further authorize..."
    // prose the WASM emits from the abilities map), so it LEGITIMATELY
    // changes when the caller narrows. We compare the digest with
    // `statement` stripped out. All other header fields — URI, Version,
    // Chain ID, Nonce, Issued At, Expiration Time, Not Before, Request
    // ID, domain, address, spaceId, non-ReCap resources — must match
    // byte-for-byte.
    const candidateImmutable = extractImmutableSiweFields(narrowed.siwe, {
      chainId,
      spaceId: bound.spaceId,
    });
    const digestExcludingStatement = (f: ReturnType<typeof extractImmutableSiweFields>) =>
      digestImmutableFields({ ...f, statement: '' });
    if (digestExcludingStatement(candidateImmutable) !== digestExcludingStatement(immutable)) {
      return c.json(
        {
          error:
            'Regenerated SIWE altered immutable header fields — refusing to sign',
          code: 'regenerated_immutable_drift',
        },
        400,
      );
    }
    // Sol MAJOR-4: re-verify the regenerated bytes' attenuation is still a
    // subset of the baseline. This catches any WASM emitter drift that
    // might silently add abilities under a resource we did not narrow.
    const regeneratedAttenuation = extractRecapAttenuationFromSiwe(narrowed.siwe);
    const regenSubsetFailure = attenuationSubsetOrFailure(
      regeneratedAttenuation,
      baselineAttenuation,
    );
    if (regenSubsetFailure) {
      return c.json(
        {
          error: `Regenerated SIWE ReCap broadens baseline: ${regenSubsetFailure}`,
          code: 'regenerated_broadens_baseline',
        },
        400,
      );
    }
    signedMessage = narrowed.siwe;
  }

  // TC-2272: the expiry the user chose at preview is sealed in the preview
  // approval's bytes. Re-apply it here; checkPreviewApproval then holds the
  // signed bytes to exactly those bytes.
  const sealedExpiry = peekPreviewApprovalExpiry(body.previewApprovalToken!, {
    userId: user.id,
    authorizationContextToken: body.authorizationContextToken,
  });
  if (sealedExpiry !== undefined && sealedExpiry !== immutable.expirationTime) {
    const checked = validateExpirationOverride(sealedExpiry, immutable, 0);
    const withExpiry = checked.ok ? withExpirationTime(signedMessage, checked.value) : null;
    if (!withExpiry) {
      return c.json(
        { error: 'The chosen approval expiry is no longer in the future — preview again', code: 'invalid_expiration_time' },
        400,
      );
    }
    signedMessage = withExpiry;
  }

  // The pre-sign rule on the exact bytes about to be signed:
  // signed ⊆ requested ⊆ the owner's selection.
  const signSubset = checkSignedSubset({
    requested: bound.originalSiwe,
    signed: signedMessage,
    selectedActionIds,
    ownerPickedExpiration: sealedExpiry !== immutable.expirationTime ? sealedExpiry : undefined,
    longerExpiryAllowed: (bound.expiryChangeable === true || siweBroadOnceTier(bound.originalSiwe, bound.keyAddress)) && !bound.handoffTicketHash,
  });
  if (!signSubset.ok) {
    return c.json({ error: signSubset.message, code: signSubset.code, reason: signSubset.reason }, 400);
  }
  // The preview brought a grant on secret keys back to 7 days; bytes that still ask for more are refused.
  const signedLifetimeReach = exceedsSecretLifetime(signedMessage, Date.now());
  if (signedLifetimeReach) return c.json(secretLifetimeBody(signedLifetimeReach), 400);

  // Validate the single-use preview approval without consuming it. The
  // final selection and bytes must match exactly what the user previewed.
  const previewCheck = checkPreviewApproval({
    token: body.previewApprovalToken!,
    authorizationContextToken: body.authorizationContextToken!,
    userId: user.id,
    keyAddress: boundAddress,
    selectedActionIds,
    candidateSignedMessage: signedMessage,
  });
  if (!previewCheck.ok) {
    return c.json({ error: previewCheck.message, code: previewCheck.error }, 400);
  }
  if (previewCheck.broadOnceExpiryPick && !(Date.parse(sealedExpiry ?? '') <= Date.now() + SECRET_GRANT_MAX_MS)) {
    return c.json(secretLifetimeBody('network'), 400);
  }
  // The renewal choice sealed with the preview: the body may repeat it, never change it. A leased choice needs
  // leases on, checked before anything is signed.
  const sealedRenewal = previewCheck.renewal;
  confirmBoundRenewal(body.renewal, sealedRenewal);
  if (sealedRenewal?.choice === 'leased' && !renewalLeasesEnabled()) {
    return c.json({ error: renewalUnavailableMessage('sign-in', 'before-signing'), code: 'renewal_disabled' }, 400);
  }

  // External signatures must recover to the bound signer over these exact
  // bytes before either single-use token is consumed.
  if (isExternal) {
    // Sol MAJOR-1: the caller supplied a signature over what THEY claim
    // to be the bytes we'll return. Verify it against `signedMessage`
    // and `boundAddress` — if the wallet signed different bytes, refuse.
    try {
      const recovered = verifyMessage(signedMessage, body.externalSignature!);
      if (recovered.toLowerCase() !== boundAddress.toLowerCase()) {
        return c.json(
          {
            error: `External signature recovered ${recovered}, expected ${boundAddress}`,
            code: 'external_signature_mismatch',
          },
          400,
        );
      }
    } catch (e) {
      return c.json(
        {
          error: e instanceof Error ? e.message : 'External signature verification failed',
          code: 'external_signature_invalid',
        },
        400,
      );
    }
  }

  // Derive the response from the actual candidate bytes before consumption,
  // so even a malformed regenerated ReCap cannot burn a pending approval.
  // Effective grants + selection derived from the ACTUAL signed bytes.
  // `service` is canonicalized to the `tinycloud.<short>` form so the wire
  // shape agrees with `selectedActionKeys` (which come from
  // `computeActionKey` → `permissionKey` → `canonicalizeServiceName`). The
  // widget's `validatePreviewSelection` projects each permission through
  // `actionId(service, space, path, ability)` and requires the projected
  // set to equal `selectedActionKeys`; if these disagreed the review UI
  // would throw "permissions disagree with selectedActionKeys" before
  // ever displaying anything to the user.
  const effectiveEntries = parsePreparedRecap(signedMessage);
  // The response is reported in the consumer's encoding (`reportedEntry`); the
  // signed bytes and the ids the window sent are unaffected.
  const reportedEntries = effectiveEntries.map(reportedEntry);
  const effectiveGrants = reportedEntries.map((entry) => ({
    service: canonicalizeServiceName(entry.service),
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));
  const effectiveSelectedActionKeys = reportedEntries.flatMap((entry) =>
    entry.actions.map((action) => computeActionKey(entry, action)),
  );
  const signedAppKeyRefusal = appKeyRefusalForSiwe(signedMessage, effectiveEntries, bound.admittedAppKeys);
  if (signedAppKeyRefusal) {
    return c.json(appKeyRefusalBody(signedAppKeyRefusal, ticket ? 'non_browser' : 'browser'), appKeyRefusalStatus(signedAppKeyRefusal));
  }
  const signEncryptionRefusal = ticket ? null : exactShareKeyRefusal(signedMessage);
  if (signEncryptionRefusal) {
    return c.json(appKeyRefusalBody(signEncryptionRefusal, 'browser'), appKeyRefusalStatus(signEncryptionRefusal));
  }
  const invalidSignedSiwe = invalidSiweMessage(signedMessage, 'characters');
  if (invalidSignedSiwe) return c.json(invalidSignedSiwe, 400);
  // The preview sealed which extra permissions the owner explicitly allowed (TC-2927). The bytes are the previewed
  // ones, so this holds already; it is checked again here so no signature covers an elevated permission the owner
  // did not decide on.
  if (!ticket && !elevatedDecided(effectiveEntries, previewCheck.elevatedAllowed)) {
    return c.json(elevatedNotDecidedBody(), 403);
  }
  // A message that hosts a space is the ability to create it, so the same rule as POST /api/keys/:id/sign applies, from
  // the origin the context was bound to at /authorize-sign-prepare (the SIWE was checked against it there). A request
  // with no checked origin, a handoff ticket included, is another site.
  if (await refusesSpaceHost({ message: signedMessage, key, authority: () => originProvisionAuthority(bound.requestOrigin) })) {
    return c.json(HOST_SIGNING_REFUSAL_BODY, 403);
  }
  // TC-3442: the account's passkey setting, checked before any token is spent or key unsealed. An external wallet's
  // own signature is its confirmation. A passkey sign-in this web sign flow was opened with covers the check for
  // five minutes; the cover is spent the moment this approval passes the gate.
  const webFlow = webFlowIdFromHeader(c.req.header(FLOW_PASSKEY_HEADER));
  if (!isExternal) {
    const gate = await checkApprovalPasskeySpendingFlow(
      prisma,
      { userId: user.id, sessionId: c.get('session')?.id ?? null },
      authorizeSignPasskeyBinding(body.authorizationContextToken, body.previewApprovalToken!, boundAddress, signedMessage),
      messageApprovalSensitivity(signedMessage, boundAddress),
      body.passkeyAssertion,
      webFlow,
    );
    if (gate.refusal) return c.json(gate.refusal, 403);
  }
  await clearFlowPasskey(prisma, webFlow);
  // Both checked claims still have to reference the stored records. This
  // synchronous call compares both, checks both expiries, then deletes both
  // without an await between either comparison and either deletion. Only
  // the winner of a concurrent race may proceed to signing.
  // The database CAS is the cross-worker signing gate. No signing or state
  // release can follow a lost race against cancellation or another context.
  // A prepared handoff is held in SIGNING while the key signs and is spent only
  // once a signature exists, so the tokens are spent after signing: a signing
  // that fails releases the handoff and the owner approves again with them.
  if (ticket) await activePreparedHandoffService.reserveSigning(ticket, user.id, body.authorizationContextToken, key.id);
  const spendTokens = () => consumeCheckedAuthorizationContext(check.claim, previewCheck.claim);
  if (!ticket) {
    const consumed = spendTokens();
    if (!consumed.ok) {
      return c.json({ error: consumed.message, code: consumed.error }, 400);
    }
  }

  let signature: string;
  if (isExternal) {
    signature = body.externalSignature!;
  } else {
    try {
      signature = await signManagedKey(key, key.sealedBlob!, signedMessage);
    } catch (e) {
      if (ticket) await activePreparedHandoffService.releaseSigning(ticket, user.id, body.authorizationContextToken, key.id);
      return c.json(
        { error: e instanceof Error ? e.message : 'Signing failed', code: 'sign_failed' },
        500,
      );
    }
  }
  if (ticket) {
    const consumed = spendTokens();
    if (!consumed.ok) {
      // A signature now exists for this handoff, so it is not released: it stays SIGNING until it
      // expires, and the signature is discarded. Only a failed signing releases (see releaseSigning).
      return c.json({ error: consumed.message, code: consumed.error }, 400);
    }
  }
  // Reference computePermissionKey so it doesn't get flagged as unused
  // during typecheck; permissionOptions may consume it in the future.
  void computePermissionKey;
  // A leased sign-in returns the grant only with the owner lease for exactly that grant (or, for an external
  // wallet, the lease it signs next). OpenKey records the signed lease so every stop can revoke it; the app registers
  // the grant and has its node admit the lease. If the lease can't be prepared or recorded, no signature is returned.
  let signInLease: SignInLease | undefined;
  if (sealedRenewal?.choice === 'leased') {
    try {
      signInLease = await setUpSignInLease(prisma, {
        userId: user.id,
        sessionId: c.get('session')?.id ?? null,
        host: bound.host,
        jwk: bound.jwk,
        spaceId: bound.spaceId,
        signedMessage,
        signature,
        leaseLifetimeSeconds: sealedRenewal.leaseLifetimeSeconds,
        sensitiveConfirmed: sealedRenewal.sensitiveConfirmed === true,
        signOwner: isExternal ? undefined : (message) => signManagedKey(key, key.sealedBlob!, message),
      });
    } catch (error) {
      const refused = signInRenewalFailure(error);
      return c.json(refused.body, refused.status);
    }
  }

  // An approved sign-in by a managed key hosts the account at the node before the signature is returned, as
  // POST /api/keys/:id/sign does. Only here, once a signature exists and the lease (if any) is recorded: a
  // refused or failed sign hosts nothing. An external wallet's account is the wallet's to host.
  if (!isExternal) {
    await bootstrapApprovedManagedSignIn({ userId: user.id, key, message: signedMessage, authority: originProvisionAuthority(bound.requestOrigin) });
  }

  const handoffDelivery = ticket
    ? await activePreparedHandoffService.completeSigning(ticket, user.id, body.authorizationContextToken, key.id)
    : null;
  recordAppSignIn(prisma, user.id, bound.appOrigin);
  return c.json({
    protocolVersion: 1,
    address: boundAddress,
    signature,
    signedMessage,
    selectedActionKeys: effectiveSelectedActionKeys,
    permissions: effectiveGrants,
    ...(handoffDelivery ?? {}),
    ...(sealedRenewal ? { renewalChoice: sealedRenewal.choice } : {}),
    ...(signInLease ?? {}),
  });
});

/**
 * POST /api/delegate/authorize-sign-release
 *
 * A web sign page that is cancelled, refused or closed without approving ends the passkey cover its own sign-in
 * recorded (`x-openkey-passkey-flow`), so a later approval in that flow asks for a passkey. Only the calling
 * session's cover for the named flow is ended; any other value in the header ends nothing.
 */
delegateRouter.post('/authorize-sign-release', async (c) => {
  await releaseFlowPasskey(
    prisma,
    { userId: c.get('user').id, sessionId: c.get('session')?.id ?? null },
    webFlowIdFromHeader(c.req.header(FLOW_PASSKEY_HEADER)),
  );
  return c.json({ released: true });
});

/**
 * POST /api/delegate/authorize-sign-renewal
 *
 * The external wallet's signature on the renewal lease of a leased sign-in, after /authorize-sign returned the
 * signed grant with `renewalSignature`. The lease is taken once, only by the same user, with a signature that
 * recovers to the grant's owner; another wallet's signature leaves it waiting. The signed lease is recorded, so every
 * stop can revoke it, and returned for the app to have its node admit.
 */
delegateRouter.post('/authorize-sign-renewal', async (c) => {
  if (!renewalLeasesEnabled()) return c.json({ error: renewalUnavailableMessage('sign-in', 'after-signing'), code: 'renewal_disabled' }, 400);
  const user = c.get('user');
  const body: unknown = await c.req.json().catch(() => null);
  const fields = body !== null && typeof body === 'object' ? body as Record<string, unknown> : {};
  if (typeof fields.signature !== 'string' || !fields.signature) {
    return c.json({ error: 'A signature is required.', code: 'invalid_request' }, 400);
  }
  const pending = takePendingSignInLease(fields.renewalToken, user.id, fields.signature);
  if (pending === 'expired') return c.json({ error: 'This renewal request expired. Sign in again to turn on renewal.', code: 'renewal_expired' }, 410);
  if (pending === 'wrong_signer') {
    return c.json({ error: "That signature isn't from the wallet you signed in with. Sign with that wallet to turn on renewal.", code: 'invalid_signature' }, 400);
  }
  try {
    return c.json({ renewalChoice: 'leased', renewal: await recordedSignInLease(prisma, pending.owner, signLease(pending.stage, fields.signature), 'wallet') });
  } catch (error) {
    const refused = signInRenewalFailure(error);
    return c.json(refused.body, refused.status);
  }
});

/**
 * POST /api/delegate/authorize-sign-preview
 *
 * Sol CRITICAL-2 / MAJOR-1: return the exact bytes the server would sign
 * for a given `selectedActionIds` against a bound authorization context,
 * WITHOUT consuming the token. This lets the widget:
 *   - render a "signing this exactly" preview before the user approves,
 *   - hand the preview bytes to an external wallet for signing,
 *   - resubmit to /authorize-sign with the resulting `externalSignature`.
 *
 * The route is idempotent (safe to call multiple times) and does NOT
 * extend the token TTL. Since preview does not consume the token, it
 * does not perform every consume-time check (no immutable-fields
 * digest comparison, no required-action check) — the ONLY authority
 * gate is the token binding itself. /authorize-sign checks every binding
 * and refusal before consuming the context and preview approval together.
 */
delegateRouter.post('/authorize-sign-preview', async (c) => {
  const user = c.get('user');
  const body = await c.req.json<{
    authorizationContextToken?: string;
    selectedActionIds?: unknown;
    /** TC-2272: the approval expiry the user chose (ISO-8601 UTC); the app's own is the default. */
    expirationTime?: unknown;
    /** TC-2927: `{ allowed: ActionId[] }`, the extra permissions the owner explicitly allowed on the warning screen. */
    elevatedDecision?: unknown;
    /** The owner's renewal choice, for a sign-in whose app asked for renewal: `{ choice: 'finite' }` or `{ choice: 'leased', leaseLifetimeSeconds }`. */
    renewal?: unknown;
    ticket?: string;
    transportVersion?: number;
    callback?: unknown;
    delivery?: unknown;
    state?: unknown;
  }>();
  const deviceUnsupported = deviceTransactionUnsupportedError(body);
  if (deviceUnsupported) return c.json(deviceUnsupported, 400);
  const ticket = handoffTicket(body);

  if (typeof body.authorizationContextToken !== 'string' || !body.authorizationContextToken) {
    return c.json(
      { error: 'authorizationContextToken is required', code: 'missing_authorization_context_token' },
      400,
    );
  }
  if (!Array.isArray(body.selectedActionIds) || body.selectedActionIds.some((id) => typeof id !== 'string')) {
    return c.json(
      { error: 'selectedActionIds must be a string[]', code: 'invalid_selected_action_ids' },
      400,
    );
  }
  const selectedActionIds = new Set(body.selectedActionIds as string[]);

  const preview = peekAuthorizationContext(body.authorizationContextToken);
  if (!preview.ok) {
    if (ticket && preview.error === 'context-not-found') {
      return c.json({ code: 'handoff_context_unavailable', error: 'Authorization context is unavailable on this server; cancel and restart with a new handoff.' }, 409);
    }
    return c.json({ error: preview.message, code: preview.error }, 400);
  }
  const bound = preview.value;
  await assertHandoffContext(ticket, user.id, body.authorizationContextToken, bound.handoffTicketHash);
  // The peek does not verify the caller. Cross-check the userId against
  // the authenticated session so a leaked token cannot be probed by a
  // different user.
  if (bound.userId !== user.id) {
    return c.json({ error: 'Authorization context bound to a different user', code: 'user_mismatch' }, 400);
  }
  // The renewal box's state is sealed with this preview, so signing can only use what the owner saw here.
  let renewalChoice: BoundRenewalChoice | undefined;
  try {
    renewalChoice = parseRenewalChoice(body.renewal, bound.signInRenewal, renewalLeasesEnabled(), 'sign-in') ?? undefined;
  } catch (error) {
    const refused = signInRenewalFailure(error);
    return c.json(refused.body, refused.status);
  }

  let originalEntries: RecapEntry[];
  try {
    originalEntries = parsePreparedRecap(bound.originalSiwe);
  } catch (e) {
    return c.json(
      { error: e instanceof Error ? e.message : 'Bound SIWE could not be re-parsed', code: 'bound_siwe_parse_failed' },
      500,
    );
  }
  const chainIdMatch = bound.originalSiwe.match(/^Chain ID:\s*(\d+)\s*$/m);
  const chainId = chainIdMatch?.[1] ? Number(chainIdMatch[1]) : 1;
  const immutable = extractImmutableSiweFields(bound.originalSiwe, {
    chainId,
    spaceId: bound.spaceId,
  });
  // A request in the one-hour tier (a grant that reaches all secrets or all encrypted data) is
  // expiry-changeable whatever the app sent; the tier is read from the request's own grants.
  const boundOnceTier = siweBroadOnceTier(bound.originalSiwe, bound.keyAddress);
  let ownerPickedExpiry = false;
  let expirationOverride: string | undefined;
  if (body.expirationTime !== undefined) {
    // An app that did not opt in (`expiryChangeable: true` at prepare) gets the expiry it asked for, unless the
    // request is in the one-hour tier. A prepared handoff has no app opt-in: its ceiling is the time the CLI asked for.
    if (!ticket && !bound.expiryChangeable && !boundOnceTier) {
      return c.json(
        { error: 'The requesting app did not opt in to a changed expiry', code: 'expiry_not_changeable' },
        400,
      );
    }
    const checked = validateExpirationOverride(body.expirationTime, immutable, MIN_EXPIRATION_LEAD_MS);
    if (!checked.ok) {
      return c.json(
        { error: 'expirationTime must be a future ISO-8601 UTC time after the request was issued', code: 'invalid_expiration_time' },
        400,
      );
    }
    // A prepared handoff's CLI refuses a grant longer than it asked for: that time is the ceiling.
    if (ticket && Date.parse(checked.value) > Date.parse(immutable.expirationTime)) {
      return c.json(
        { error: 'expirationTime is later than the time the CLI asked for', code: 'expiry_exceeds_handoff' },
        400,
      );
    }
    expirationOverride = checked.value;
    ownerPickedExpiry = true;
  }
  // Secret grants and owner-picked expiries in the one-hour tier last up to 7 days from this preview.
  const broadOnceExpiryPick = boundOnceTier && ownerPickedExpiry;
  const secretCap = secretCapExpirationTime(bound.originalSiwe, Date.now(), broadOnceExpiryPick);
  if (secretCap !== null && !(Date.parse(expirationOverride ?? immutable.expirationTime) <= Date.parse(secretCap))) {
    expirationOverride = secretCap;
  }
  if (appKeyGroupPartial(
    admittedAppKeyActionIds(originalEntries, bound.admittedAppKeys, computeActionKey),
    groupRuleActionIds(originalEntries, ticket),
    selectedActionIds,
  )) {
    return c.json({ error: APP_KEY_GROUP_PARTIAL_MESSAGE, code: APP_KEY_GROUP_PARTIAL_CODE }, 400);
  }
  // Every requested selected action MUST be in the bound allowed set.
  const allowedSet = new Set(bound.allowedActionIds);
  for (const id of selectedActionIds) {
    if (!allowedSet.has(id)) {
      return c.json(
        { error: `Selected action ${id} is not part of the prepared baseline.`, code: 'action-not-in-baseline' },
        400,
      );
    }
  }
  const selectedEntries = entriesForSelectedActions(originalEntries, selectedActionIds);
  if (selectedEntries.length === 0) {
    return c.json(
      { error: 'No selected actions map to any capability in the SIWE', code: 'empty_selection' },
      400,
    );
  }

  // Same unchanged-selection / caveats logic as /authorize-sign.
  const originalActionKeys = new Set<string>();
  for (const entry of originalEntries) {
    for (const action of entry.actions) {
      originalActionKeys.add(computeActionKey(entry, action));
    }
  }
  const selectionUnchanged =
    selectedActionIds.size === originalActionKeys.size &&
    [...selectedActionIds].every((id) => originalActionKeys.has(id));
  // Sol continuation contract (caveats): whole-ability/whole-resource
  // removal is allowed. Surviving abilities keep the ORIGINAL caveat
  // multiset (spliced back by the narrower). See /authorize-sign for
  // the full contract.

  let preparedSignedMessage: string;
  if (selectionUnchanged) {
    preparedSignedMessage = bound.originalSiwe;
  } else {
    // Sol CRITICAL-1: preview via the preservation splice. Real production
    // SIWEs always carry a ReCap-derived statement; the previous guard
    // rejected them all, which meant the preview never returned any bytes
    // for a narrowed selection in production.
    const previewBaselineCaveats = extractRecapAttenuationFromSiwe(bound.originalSiwe);
    const previewNarrowed = narrowSiwePreservingImmutable({
      originalSiwe: bound.originalSiwe,
      narrowedEntries: selectedEntries,
      address: ensureEip55(bound.keyAddress),
      chainId,
      domain: immutable.domain,
      issuedAt: immutable.issuedAt,
      expirationTime: immutable.expirationTime,
      spaceId: bound.spaceId,
      jwk: bound.jwk,
      baselineCaveats: previewBaselineCaveats,
      ...(immutable.notBefore ? { notBefore: immutable.notBefore } : {}),
    });
    if (!previewNarrowed.ok) {
      return c.json({ error: previewNarrowed.message, code: previewNarrowed.code }, 400);
    }
    // Verify no immutable-header drift in the preview candidate. `statement`
    // is EXCLUDED from the comparison because it is a text encoding of the
    // ReCap contents and legitimately changes with narrowing.
    const candidateImmutable = extractImmutableSiweFields(previewNarrowed.siwe, {
      chainId,
      spaceId: bound.spaceId,
    });
    const digestExcludingStatement = (f: ReturnType<typeof extractImmutableSiweFields>) =>
      digestImmutableFields({ ...f, statement: '' });
    if (digestExcludingStatement(candidateImmutable) !== digestExcludingStatement(immutable)) {
      return c.json(
        {
          error: 'Regenerated SIWE altered immutable header fields — refusing to preview',
          code: 'regenerated_immutable_drift',
        },
        400,
      );
    }
    // Sol MAJOR-4: assert the regenerated attenuation is a strict subset of
    // the baseline. Broadening at preview time is a wire-format bug we
    // must fail closed on rather than let the user "approve" bytes we
    // would then refuse to sign at /authorize-sign.
    const previewBaseline = extractRecapAttenuationFromSiwe(bound.originalSiwe);
    const previewCandidate = extractRecapAttenuationFromSiwe(previewNarrowed.siwe);
    const previewSubsetFailure = attenuationSubsetOrFailure(previewCandidate, previewBaseline);
    if (previewSubsetFailure) {
      return c.json(
        {
          error: `Regenerated SIWE ReCap broadens baseline: ${previewSubsetFailure}`,
          code: 'regenerated_broadens_baseline',
        },
        400,
      );
    }
    preparedSignedMessage = previewNarrowed.siwe;
  }

  const selectedOnceTier = selectionUnchanged ? boundOnceTier : siweBroadOnceTier(preparedSignedMessage, bound.keyAddress);
  const appRenewalWindow = !ownerPickedExpiry && renewalChoice?.choice === 'leased' && selectedOnceTier
    ? preparedSignedMessage
    : undefined;

  // A selection in the one-hour tier starts at one hour when the owner picked nothing.
  // An app that asked for an hour or less keeps its time. A chosen renewal uses the app's window.
  if (!ownerPickedExpiry && renewalChoice?.choice !== 'leased' && selectedOnceTier) {
    const onceStartMs = Date.now() + 60 * 60 * 1000;
    if (Date.parse(immutable.expirationTime) > onceStartMs) {
      expirationOverride = new Date(onceStartMs).toISOString();
    }
  }

  // TC-2272: the user's chosen approval expiry replaces the Expiration Time
  // line of the bytes to sign; the preview approval seals the result.
  if (expirationOverride !== undefined) {
    const withExpiry = withExpirationTime(preparedSignedMessage, expirationOverride);
    if (!withExpiry) {
      return c.json({ error: 'Bound SIWE has no single Expiration Time line', code: 'bound_siwe_parse_failed' }, 400);
    }
    preparedSignedMessage = withExpiry;
  }

  // The pre-sign rule on the exact bytes about to reach the owner's wallet:
  // signed ⊆ requested ⊆ the owner's selection.
  const previewSubset = checkSignedSubset({
    requested: bound.originalSiwe,
    signed: preparedSignedMessage,
    selectedActionIds,
    ownerPickedExpiration: expirationOverride,
    longerExpiryAllowed: (bound.expiryChangeable === true || boundOnceTier) && !bound.handoffTicketHash,
  });
  if (!previewSubset.ok) {
    return c.json({ error: previewSubset.message, code: previewSubset.code, reason: previewSubset.reason }, 400);
  }
  // TC-3821: the lease these exact bytes would carry is refused here, before the owner sees the preview, when the
  // grant reaches secrets without the owner's confirm or with a window over 7 days.
  if (renewalChoice?.choice === 'leased') {
    try {
      // Check the app's requested renewal window before a finite secret cap can shorten it.
      assertLeaseableGrant(appRenewalWindow ?? preparedSignedMessage, renewalChoice.sensitiveConfirmed === true);
    } catch (error) {
      const refused = signInRenewalFailure(error);
      return c.json(refused.body, refused.status);
    }
  }

  // Preview grants + selection. `service` is canonicalized to the
  // `tinycloud.<short>` form so the wire shape agrees with
  // `selectedActionKeys` (see the /authorize-sign response for the full
  // rationale — the widget's `validatePreviewSelection` requires the
  // per-permission projection to equal the returned selected keys).
  const previewEntries = parsePreparedRecap(preparedSignedMessage);
  const previewAppKeyRefusal = appKeyRefusalForSiwe(preparedSignedMessage, previewEntries, bound.admittedAppKeys);
  if (previewAppKeyRefusal) {
    return c.json(appKeyRefusalBody(previewAppKeyRefusal, ticket ? 'non_browser' : 'browser'), appKeyRefusalStatus(previewAppKeyRefusal));
  }
  const previewEncryptionRefusal = ticket ? null : exactShareKeyRefusal(preparedSignedMessage);
  if (previewEncryptionRefusal) {
    return c.json(appKeyRefusalBody(previewEncryptionRefusal, 'browser'), appKeyRefusalStatus(previewEncryptionRefusal));
  }
  // The extra permissions of the warning screen (TC-2927) are decided after this preview is first fetched, so the
  // preview records which ones the owner allowed and /authorize-sign refuses to sign any the preview did not
  // record as allowed. A rejected one is not in these bytes, so it needs nothing.
  const elevatedAllowed = ticket ? new Set<string>() : allowedElevatedIds(body.elevatedDecision);
  const previewGrants = previewEntries.map((entry) => ({
    service: canonicalizeServiceName(entry.service),
    space: entry.space,
    path: entry.path,
    actions: [...entry.actions],
  }));
  const previewSelectedActionKeys = previewEntries.flatMap((entry) =>
    entry.actions.map((action) => computeActionKey(entry, action)),
  );

  // Sol CRITICAL-1: issue a preview-approval token that seals the exact
  // selection AND signed-bytes candidate. /authorize-sign requires this
  // token; without it, finalize could independently accept a different
  // selection or sign different bytes than the preview evaluated.
  const previewApproval = issuePreviewApproval({
    authorizationContextToken: body.authorizationContextToken!,
    userId: user.id,
    keyAddress: ensureEip55(bound.keyAddress),
    selectedActionIds,
    signedMessage: preparedSignedMessage,
    broadOnceExpiryPick,
    elevatedAllowed,
    renewal: renewalChoice,
  });
  // TC-3442: whether Approve needs the passkey, with the challenge for exactly these bytes. Re-issued with every
  // preview, so a changed selection or expiry gets its own. None when this web sign flow's own passkey sign-in covers it.
  const boundKey = await prisma.ethereumKey.findFirst({
    where: { id: bound.keyId, userId: user.id, archivedAt: null },
    select: { keyType: true },
  });
  const passkey = !boundKey || boundKey.keyType === 'EXTERNAL'
    ? { required: false as const }
    : await approvalPasskeyOfferInFlow(
      prisma,
      { userId: user.id, sessionId: c.get('session')?.id ?? null },
      authorizeSignPasskeyBinding(body.authorizationContextToken!, previewApproval.token, ensureEip55(bound.keyAddress), preparedSignedMessage),
      messageApprovalSensitivity(preparedSignedMessage, bound.keyAddress),
      webFlowIdFromHeader(c.req.header(FLOW_PASSKEY_HEADER)),
    );

  return c.json({
    protocolVersion: 1,
    address: ensureEip55(bound.keyAddress),
    // The exact bytes the server would sign for this selection.
    signedMessage: preparedSignedMessage,
    selectedActionKeys: previewSelectedActionKeys,
    permissions: previewGrants,
    // Echo the token so callers can round-trip it back into
    // /authorize-sign without re-parsing.
    authorizationContextToken: body.authorizationContextToken,
    // Sol CRITICAL-1: preview-approval token bound to (selection, bytes).
    previewApprovalToken: previewApproval.token,
    previewApprovalExpiresAt: previewApproval.expiresAt,
    signedMessageDigest: previewApproval.signedMessageDigest,
    ...(renewalChoice ? { renewal: renewalChoice } : {}),
    passkey,
  });
});
