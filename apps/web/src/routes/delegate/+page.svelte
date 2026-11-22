<script lang="ts">
  import { onMount } from 'svelte';
  import { afterNavigate } from '$app/navigation';
  import { page } from '$app/stores';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import CodeBox from '$lib/components/approval/code-box.svelte';
  import DonePage, { type ReceiptRow } from '$lib/components/approval/done-page.svelte';
  import Loader from '$lib/components/approval/loader.svelte';
  import SignInCard from '$lib/components/approval/sign-in-card.svelte';
  import Slip from '$lib/components/approval/slip.svelte';
  import StopPage from '$lib/components/approval/stop-page.svelte';
  import { APPROVAL_EXPIRY, CODE, DONE, ONE_SECRET, STOPS, STOP_PARTS, UNVERIFIED_REQUESTER, approvalStop, codeDestinationWord, fill, safeCode, stopForReply, supportLine, type StopView } from '@openkey/sdk/approval-copy';
  import { formatLocalAccessEnd } from '$lib/access-end';
  import { classifyDelegateError } from '$lib/delegate-error-classification';
  import {
    delegateFailureText,
    delegateResponseFailureText,
    delegateServerMessage,
    deviceRelayFailureText,
    DeviceRelayDeliveryError,
    OwnerMessageError,
  } from '$lib/delegate-failure-text';
  import { apiBusyOrEndedMessage } from '$lib/api-busy-or-ended';
  import { PasskeyPromptError, answerApprovalPasskey, isPasskeyApprovalRefusal, type ApprovalPasskeyNeed } from '$lib/approval-passkey';
  import KeyPicker from '$lib/components/keys/KeyPicker.svelte';
  import SiweMessage from '$lib/components/ui/siwe-message.svelte';
  import CliSigningAdapter from '$lib/components/signing/cli-signing-adapter.svelte';
  import PreparedHandoff from './PreparedHandoff.svelte';
  import OwnerRevocationHandoff from './OwnerRevocationHandoff.svelte';
  import DeviceRequestNotice from '$lib/components/device/device-request-notice.svelte';
  import { publicDelegationForCode } from '$lib/delegation-code-body';
  import { approvedDevicePermissions, cleanConsentText, delegationPasteCode, readDelegatePermissionsParam, DeviceLinkError, deviceRequestDefaultSeconds, deviceRequestReason, deviceRequestTtlSeconds, loadVerifiedDeviceRequest } from '$lib/device-authorization';
  import DelegateLinkNotice from '$lib/components/delegate/delegate-link-notice.svelte';
  import {
    KNOWN_NODE_ORIGINS,
    REGISTERED_CALLBACK_ENDPOINTS,
    checkDelegateCallback,
    approvalRequester,
    delegateRequester,
    checkDelegateHost,
    isCanonicalHttpsEndpoint,
    isCanonicalHttpsOrigin,
    isLoopbackHostname,
    isEd25519DidKey,
    TINYCLOUD_ONE_REQUESTER_DIDS,
    withConfiguredEntries,
  } from '$lib/delegate-link-policy';
  import { preparedMatchesSelection, reviewSelectionToActionKeys, selectedServerActionIds } from '$lib/delegate-review-selection';
  import { expectedSigner } from '$lib/delegate-expected-signer';
  import { activeKeys, autoSelectKey } from '$lib/delegate-key-selection';
  import DelegateSigningHint from '$lib/components/signing/delegate-signing-hint.svelte';
  import { shouldShowLoopbackHint } from '$lib/delegate-signing-hint';
  import { startCodeCountdown, remainingFromServerClock, CODE_AND_APPROVAL_EXPIRED_TEXT, type CodeCountdownSnapshot } from '$lib/delegate-code-countdown';
  import { MAX_LEASE_MS, MIN_EXPIRY_MS, accessLastsLine, approvalRequestStartSeconds, defaultLeaseMs, formatDuration, remainingAccessMs, requestedExpiryMs } from '$lib/approval-expiry';
  import {
    parseSpaceSetup,
    spaceReadinessResult,
    spaceSetupNoticeText,
    type SpaceSetupNotice,
  } from '$lib/delegate-space-setup';
  import { ownFolderOnlyLine } from '$lib/delegate-own-folder';
  import {
    approvalLifetimeCapSeconds,
    parseCapabilityReview,
    defaultSelection,
    siweExpirationTime,
    type CapabilityReviewModel,
  } from '@openkey/capability-review';
  import { renewalStartsTicked } from '$lib/renewal-default';
  import { ServerReplyError } from '$lib/server-reply';
  import { compareWallets, shortWallet, stopKeyName } from '$lib/approval-stop';
  import { isTermsRequired } from '$lib/terms';
  import { termsRefused } from '$lib/terms-gate';

  interface EIP6963ProviderInfo {
    uuid: string;
    name: string;
    icon: string;
    rdns: string;
  }

  interface EIP6963ProviderDetail {
    info: EIP6963ProviderInfo;
    provider: any;
  }

  interface DelegatePermissionAction {
    key: string;
    action: string;
    ability: string;
    required: boolean;
  }

  interface DelegatePermission {
    key: string;
    label: string;
    resourcePath: string;
    actions: DelegatePermissionAction[];
  }

  class DelegateResponseError extends Error {
    readonly code: unknown;
    readonly status: number;
    readonly serverMessage: string | undefined;
    readonly requestedSpaceOwner: string | undefined;
    constructor(message: string, code: unknown, status: number, serverMessage?: string, requestedSpaceOwner?: string) {
      super(message);
      this.code = code;
      this.status = status;
      this.serverMessage = serverMessage;
      this.requestedSpaceOwner = requestedSpaceOwner;
    }
  }
  function delegateErrorClassification(cause: unknown, refreshAttempted = false) {
    return cause instanceof DelegateResponseError
      ? classifyDelegateError(cause.status, cause.code, refreshAttempted)
      : 'error';
  }

  async function readDelegateSuccess(response: Response, valid: (data: any) => boolean) {
    const body = await response.json().catch(() => null);
    if (!body || !valid(body)) throw new ServerReplyError(response.status);
    return body;
  }

  function stopApproval(view: StopView, retry?: () => void | Promise<void>, wantedWallet?: string) {
    if (view.placement === 'sign-in') {
      sessionEnded = true;
    } else if (view.placement === 'inline') {
      return [view.title, view.body].filter(Boolean).join('. ');
    } else {
      failure = { view, retry, wantedWallet };
    }
    return '';
  }

  function delegateErrorMessage(cause: unknown, retry?: () => void | Promise<void>, editingReview = false) {
    if (cause instanceof DeviceRelayDeliveryError) {
      if (cause.status === 409 || cause.status === 410 || cause.status === 401) {
        return stopApproval(stopForReply({ status: cause.status, code: cause.code }));
      }
      return deviceRelayFailureText(cause.status, cause.code);
    }
    // TC-3442: a dismissed passkey prompt and the API's passkey refusals each carry the words to show.
    if (cause instanceof PasskeyPromptError) return cause.message;
    if (cause instanceof DelegateResponseError && isPasskeyApprovalRefusal(cause)) return cause.message;
    if (cause instanceof DelegateResponseError) {
      const refusedOwner = cause.requestedSpaceOwner ? shortWallet(cause.requestedSpaceOwner) : '';
      const options = {
        status: cause.status, code: cause.code, values: { ...stopValues, wanted: refusedOwner || wanted }, requester: expiredRequesterName,
        permissionsEditable: reviewEditing,
        expiryChangeable: expiryChangeControlVisible,
        renewalChangeable: renewalMaxLeaseMs !== null,
        detail: cause.serverMessage,
      };
      const wrongOwner = selectedKey && cause.code === 'invalid_permissions' &&
        (refusedOwner || (expectedAddress && !selectedMatchesExpected) || cause.serverMessage === 'Requested spaces must belong to the signing account');
      if (wrongOwner) return stopApproval(approvalStop('S18', options), undefined, refusedOwner || wanted);
      const view = stopForReply(options);
      if (editingReview && view.id === 'S26') return delegateResponseFailureText(cause.status, cause.code);
      return stopApproval(view, retry);
    }
    if (cause instanceof ServerReplyError) return stopApproval(approvalStop('S27', { status: cause.status }), retry);
    if (retry && !editingReview && !(cause instanceof OwnerMessageError)) return stopApproval(approvalStop('S26'), retry);
    return delegateFailureText(cause);
  }

  async function readDelegateFailure(response: Response) {
    const body = await response.json().catch(() => null);
    if (isTermsRequired(response.status, body)) termsRefused();
    const owner = body?.requestedSpaceOwner;
    const passkeyMessage = isPasskeyApprovalRefusal(body) && typeof body?.error === 'string' ? body.error : undefined;
    return new DelegateResponseError(
      passkeyMessage ?? apiBusyOrEndedMessage(response.status) ?? `HTTP ${response.status}`,
      body?.code, response.status, delegateServerMessage(body),
      typeof owner === 'string' && /^0x[0-9a-fA-F]{40}$/.test(owner) ? owner : undefined,
    );
  }

  const session = authClient.useSession();

  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let selectedKey = $state<EthereumKey | null>(null);
  let error = $state('');
  let failure = $state<{ view: StopView; retry?: () => void | Promise<void>; wantedWallet?: string } | null>(null);
  let requestExpired = $state(false);
  let approveBlockedByFailure = $state(false);
  let keysLoaded = $state(false);
  let initialized = $state(false);
  let signingIn = $state(false);
  // The server answered 401 to an approval call: the sign-in card comes back with the signed-out heading.
  let sessionEnded = $state(false);
  let delegating = $state(false);
  let done = $state(false);
  let pasteCode = $state('');
  let shortCode = $state('');
  let shortCodeFailure = $state<{ status: number; code: unknown } | null>(null);
  let spaceSetup = $state<SpaceSetupNotice | null>(null);
  let ownFolderLine = $state<string | null>(null);
  let spaceReadiness = $state<ReturnType<typeof spaceReadinessResult>>(null);
  let callbackFailed = $state(false);
  let callbackInFlight = $state(false);
  let step = $state<'select-key' | 'link-wallet' | 'consent' | 'choose-wallet' | 'done'>('select-key');
  let preparedData = $state<any>(null);
  // TC-3442: from the latest /prepare, whether Approve needs the passkey, with the challenge for that preview.
  let passkeyNeed = $state<ApprovalPasskeyNeed | null>(null);
  let siweMessage = $state('');
  let preparing = $state(false);
  let permissionOptions = $state<DelegatePermission[]>([]);
  let selectedActionKeys = $state<string[]>([]);
  let editingPermissions = $state(false);
  let codeDeadline = $state<number | null>(null);
  let codeCountdown = $state<CodeCountdownSnapshot | null>(null);
  let codeAnnouncement = $state('');
  let delegationPayload = $state.raw<any>(null);
  let codeRenewing = $state(false);
  let codeRenewFailed = $state(false);
  let approvalExpiryNow = $state(Date.now());
  const delegationExpiry = $derived(Date.parse(delegationPayload?.expirationTime ?? delegationPayload?.expiresAt ?? delegationPayload?.expiry ?? ''));
  const delegationExpired = $derived(!Number.isFinite(delegationExpiry) || delegationExpiry <= approvalExpiryNow);

  // Countdown for the short code. Stopped when the deadline changes or the page is destroyed.
  $effect(() => {
    const deadline = codeDeadline;
    if (deadline === null) return;
    codeAnnouncement = '';
    return startCodeCountdown({
      deadline,
      onUpdate: (snapshot) => {
        codeCountdown = snapshot;
        if (snapshot.announcement) {
          // Read at expiry: the approval-expiry effect below updates `delegationExpired` only after this tick.
          const approvalEnded = snapshot.expired && !(Number.isFinite(delegationExpiry) && delegationExpiry > Date.now());
          codeAnnouncement = approvalEnded ? CODE_AND_APPROVAL_EXPIRED_TEXT : snapshot.announcement;
        }
      },
    });
  });

  $effect(() => {
    if (!codeCountdown?.expired) return;
    const now = Date.now();
    approvalExpiryNow = now;
    if (!Number.isFinite(delegationExpiry) || delegationExpiry <= now) return;
    const timer = setTimeout(() => { approvalExpiryNow = Date.now(); }, Math.min(delegationExpiry - now, 2_147_483_647));
    return () => clearTimeout(timer);
  });
  let updatingPermissions = $state(false);
  let permissionsEdited = $state(false);
  let authorizationContextToken = $state<string | null>(null);
  // Sol MAJOR-9: `reviewModel` is the STABLE baseline model built from
  // the ORIGINAL prepared SIWE. It never gets re-derived from a later
  // narrowed SIWE — otherwise removed optional actions would silently
  // disappear from the review UI. `reviewSelection` is the effective
  // subset the user picked; only that changes when the user narrows.
  let reviewModel = $state<CapabilityReviewModel | null>(null);
  const expiredRequesterName = $derived(reviewModel?.requester.displayName?.trim() || '');
  let baselineSiweForReview = $state<string | null>(null);
  let reviewSelection = $state(new Set<string>());
  let reviewEditing = $state(false);
  const expiryChangeControlVisible = $derived(
    reviewModel?.protocol === 'tinycloud-siwe-recap' &&
    requestedExpiryMs(reviewModel.immutable?.issuedAt, reviewModel.immutable?.expirationTime) !== null,
  );
  const approvalRequestMode = $page.route.id === '/a/[id]';
  const approvalRequestId = approvalRequestMode ? $page.params.id || '' : '';
  const delegateReturnTo = $derived(approvalRequestMode ? $page.url.pathname : $page.url.pathname + $page.url.search + $page.url.hash);
  const registerHref = $derived(`/auth/register?returnTo=${encodeURIComponent(delegateReturnTo)}`);
  const emailSignInHref = $derived(`/auth/login?redirect=${encodeURIComponent(delegateReturnTo)}`);
  let actionRow: HTMLDivElement | null = $state(null);
  let showScrollToApprove = $state(false);

  // Link wallet state
  let wallets = $state<EIP6963ProviderDetail[]>([]);
  let selectedWallet = $state<EIP6963ProviderDetail | null>(null);
  let linking = $state(false);

  // Parse query params
  let approvalRequestLoading = $state(approvalRequestMode);
  let approvalRequestLoaded = $state(false);
  // The owner declined this request (TC-2459): from the Decline button, or the link was declined before.
  let declined = $state(false);
  let declining = $state(false);
  // The complete link, in memory only (the page scrubs it from the URL); Decline sends it in the body, never a URL.
  let approvalReference = '';
  const preparedTransport = !approvalRequestMode && $page.url.searchParams.has('transportVersion');
  let preparedStorageError = $state(!approvalRequestMode && $page.url.searchParams.get('transportVersion') === 'storage-error');
  let dispatchReady = $state(false);
  let preparedMode = $state(false);
  let preparedFragment = $state('');
  let ownerRevocationSelected = $state(false);
  const ownerRevocationMode = $derived.by(() => {
    if (!preparedFragment.startsWith('#tv2=') || preparedFragment.length > 8192) return false;
    try {
      const value: unknown = JSON.parse(atob(preparedFragment.slice(5).replace(/-/g, '+').replace(/_/g, '/')));
      return !!value && typeof value === 'object' && 'request' in value &&
        !!value.request && typeof value.request === 'object' && 'kind' in value.request &&
        value.request.kind === 'owner-revocation';
    } catch { return false; }
  });
  let reloadingFragment = false;
  function captureClientFragment(): boolean {
    if (reloadingFragment) return true;
    if (!location.hash.startsWith('#tv')) return false;
    reloadingFragment = true;
    dispatchReady = false;
    const fragment = location.hash;
    // The document-head bootstrap does not run during SvelteKit navigation.
    // Scrub before persisting, then reload so the existing auth continuation
    // starts without ever entering the legacy delegation branch.
    history.replaceState(history.state, '', location.pathname);
    try {
      sessionStorage.setItem('openkey.delegate.tv2.pending', fragment);
    } catch {
      try { sessionStorage.removeItem('openkey.delegate.tv2.pending'); } catch { /* No stale request is resumed from the error route. */ }
      delete document.documentElement.dataset.preparedHandoff;
      history.replaceState(history.state, '', `${location.pathname}?transportVersion=storage-error`);
      location.reload();
      return true;
    }
    history.replaceState(history.state, '', `${location.pathname}?transportVersion=2`);
    location.reload();
    return true;
  }
  function dispatchClientNavigation(): boolean {
    if (approvalRequestMode) return false;
    if (captureClientFragment()) return true;
    if (location.search === '?transportVersion=storage-error') {
      preparedStorageError = true;
      try { sessionStorage.removeItem('openkey.delegate.tv2.pending'); } catch { /* The error route cannot claim a stale request. */ }
      delete document.documentElement.dataset.preparedHandoff;
      return false;
    }
    // The bare route is the only auth return that resumes tab-scoped v2.
    // A newly opened explicit legacy link wins over an older pending request.
    if (!location.search || location.search === '?transportVersion=2') return false;
    let stored: string | null = null;
    try { stored = sessionStorage.getItem('openkey.delegate.tv2.pending'); } catch { /* No persistent fallback. */ }
    if (stored === null && !preparedMode && document.documentElement.dataset.preparedHandoff !== '1') return false;
    try { sessionStorage.removeItem('openkey.delegate.tv2.pending'); } catch { /* No persistent fallback. */ }
    delete document.documentElement.dataset.preparedHandoff;
    dispatchReady = false;
    // Reinitialize the legacy query-bound state even for same-route SPA links.
    location.reload();
    return true;
  }
  afterNavigate(() => { if (typeof window !== 'undefined') dispatchClientNavigation(); });
  onMount(() => {
    if (approvalRequestMode) {
      dispatchReady = true;
      void loadApprovalRequest();
      return;
    }
    if (dispatchClientNavigation()) return;
    const onHashChange = () => { dispatchClientNavigation(); };
    window.addEventListener('hashchange', onHashChange);
    if (document.documentElement.dataset.preparedHandoffStorageError === '1') preparedStorageError = true;
    let stored: string | null = null;
    try { stored = sessionStorage.getItem('openkey.delegate.tv2.pending'); } catch { /* The approval page reports unavailable tab storage. */ }
    if (!preparedStorageError && (document.documentElement.dataset.preparedHandoff === '1' || stored !== null)) {
      preparedMode = true;
      preparedFragment = stored ?? '';
    }
    dispatchReady = true;
    return () => window.removeEventListener('hashchange', onHashChange);
  });
  let did = $state($page.url.searchParams.get('did') || '');
  const jwkB64 = $page.url.searchParams.get('jwk') || '';
  const callback = $page.url.searchParams.get('callback') || '';
  let host = $state($page.url.searchParams.get('host') || 'https://node.tinycloud.xyz');
  const reasonParam = $page.url.searchParams.get('reason') || '';
  // Optional caller-supplied delegation lifetime. The CLI encodes this as
  // an ms-format string ("7d", "30m") or a millisecond integer. Validation
  // and clamping (30 days at most) are owned by the API to keep the source
  // of truth in one place; we just forward it.
  let expiryParam = $state($page.url.searchParams.get('expiry') || '');
  // `expiryChangeable=true` on a /delegate link: the CLI that built it accepts a delegation longer than the
  // link's `expiry`. Without it a pick can only be shorter (a CLI refuses a longer one and saves nothing).
  const linkExpiryChangeable = $page.url.searchParams.get('expiryChangeable') === 'true';
  // TC-2272: the time the user picked on the approval screen (ms from approval), or null for the
  // requested one. A pick is sent as `expiry` with `expiryChosen`, which skips the 30-day clamp meant
  // for link parameters; a signed request or device approval still bounds it to what was signed.
  let expiryChoiceMs = $state<number | null>(null);
  let expiryChosen = $state(false);
  let requestedExpiryParam: string | null = null;
  // The longest the requester signed (a signed approval request or a device request); null on a plain link.
  let expiryMaxMs = $state<number | null>(null);
  let approvalRequestStartMs = $state<number | null>(null);
  // TC-2933: the renewal checkbox, offered only when the approval request signed a renewal request
  // (its longest lease). `renewalLeaseMs` is the owner's lease, null while the box is unticked.
  let renewalMaxLeaseMs = $state<number | null>(null);
  let renewalPurpose: unknown = undefined;
  let renewalDefaulted = false;
  let renewalLeaseMs = $state<number | null>(null);
  // Spec D12: standing access starts ticked; D7: never in the Once tier (secrets or decrypt); D11: no purpose is a task.
  // Ticking it re-prepares, so the preview the owner approves is the one that carries the lease.
  $effect(() => {
    if (renewalDefaulted || renewalMaxLeaseMs === null || !reviewModel) return;
    renewalDefaulted = true;
    if (renewalStartsTicked(renewalPurpose, reviewModel.permissions)) {
      void changeRenewal(defaultLeaseMs(renewalMaxLeaseMs));
    }
  });
  // The owner's choice as /prepare binds it into the preview; null when the request did not ask for renewal.
  function renewalChoiceBody() {
    if (renewalMaxLeaseMs === null) return null;
    return renewalLeaseMs === null ? { choice: 'finite' } : { choice: 'leased', leaseLifetimeSeconds: Math.round(renewalLeaseMs / 1000) };
  }
  const RENEWAL_NOT_SET_UP = "Renewal wasn't set up, so nothing was approved. Try again.";
  // While an external wallet signs the lease: how long renewal lasts, shown in the prompt.
  let renewalSigningMs = $state<number | null>(null);
  // A changed lease (and, from the sensitive-access step, the window) is a new preview: prepare once with both.
  async function changeRenewal(leaseMs: number | null, windowMs?: number | null) {
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }
    const previous = { lease: renewalLeaseMs, choice: expiryChoiceMs, chosen: expiryChosen, param: expiryParam, requested: requestedExpiryParam };
    renewalLeaseMs = leaseMs;
    if (windowMs !== undefined) {
      requestedExpiryParam ??= expiryParam;
      expiryChoiceMs = windowMs;
      expiryChosen = windowMs !== null;
      expiryParam = windowMs === null ? requestedExpiryParam : `${Math.round(windowMs / 1000)}s`;
    }
    updatingPermissions = true;
    error = '';
    try {
      const data = await prepareDelegation(selectedKey, permissionsEdited ? selectedActionKeys : undefined);
      applyPreparedDelegation(data);
    } catch (e: any) {
      renewalLeaseMs = previous.lease;
      expiryChoiceMs = previous.choice;
      expiryChosen = previous.chosen;
      expiryParam = previous.param;
      requestedExpiryParam = previous.requested;
      error = delegateErrorMessage(e, () => changeRenewal(leaseMs, windowMs), true);
    } finally {
      updatingPermissions = false;
    }
  }
  async function changeApprovalExpiry(ms: number | null) {
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }
    requestedExpiryParam ??= expiryParam;
    const previous = { chosen: expiryChosen, param: expiryParam };
    expiryChosen = ms !== null;
    expiryParam = ms === null ? requestedExpiryParam : `${Math.round(ms / 1000)}s`;
    updatingPermissions = true;
    error = '';
    try {
      const data = await prepareDelegation(selectedKey, permissionsEdited ? selectedActionKeys : undefined);
      applyPreparedDelegation(data);
      expiryChoiceMs = ms;
    } catch (e: any) {
      expiryChosen = previous.chosen;
      expiryParam = previous.param;
      error = delegateErrorMessage(e, () => changeApprovalExpiry(ms), true);
    } finally {
      updatingPermissions = false;
    }
  }
  const deviceTransactionId = approvalRequestMode ? '' : $page.url.searchParams.get('deviceTransactionId') || '';
  const deviceShareOrigin = $page.url.searchParams.get('deviceShareOrigin') || '';
  const deviceUserCode = $page.url.searchParams.get('deviceUserCode') || '';
  const relayJwkB64 = $page.url.searchParams.get('relayJwk') || '';

  // Decode JWK from base64url
  let jwk = $state<object | null>(null);
  if (jwkB64 && !approvalRequestMode) {
    try {
      jwk = JSON.parse(atob(jwkB64.replace(/-/g, '+').replace(/_/g, '/')));
    } catch {
      // Will show error in UI
    }
  }
  const incompleteLegacyRequest = $derived(!approvalRequestMode && !deviceTransactionId && !jwk);

  let relayPublicJwk: JsonWebKey | null = null;
  let relayInvalid = false;
  if (relayJwkB64 && !approvalRequestMode) {
    try {
      relayPublicJwk = JSON.parse(atob(relayJwkB64.replace(/-/g, '+').replace(/_/g, '/'))) as JsonWebKey;
    } catch {
      relayInvalid = true;
    }
  }

  function encodeBase64Url(bytes: ArrayBuffer | Uint8Array): string {
    const value = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let binary = '';
    for (const byte of value) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function encryptDeviceRelay(payload: unknown) {
    if (!relayPublicJwk || !deviceTransactionId) throw new Error('The CLI relay encryption binding is missing.');
    const recipient = await crypto.subtle.importKey(
      'jwk',
      relayPublicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const ephemeral = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    const sharedSecret = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: recipient },
      ephemeral.privateKey,
      256,
    );
    const material = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode(deviceTransactionId),
        info: new TextEncoder().encode('openkey-device-relay-v1'),
      },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(deviceTransactionId) },
      key,
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    return {
      version: 1,
      algorithm: 'ECDH-P256-A256GCM',
      ephemeralPublicJwk: await crypto.subtle.exportKey('jwk', ephemeral.publicKey),
      nonce: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ciphertext),
    };
  }

  // Decode the optional permissions request from base64url JSON. The CLI's
  // `tc auth request` flow encodes a `{ permissions: PermissionEntry[] }`
  // payload here so the user can grant just the missing capabilities — see
  // packages/cli/src/auth/browser-auth.ts in tinycloudlabs/js-sdk.
  interface RequestedPermission {
    service: string;
    space: string;
    path: string;
    actions: string[];
  }
  let requestedPermissions = $state<RequestedPermission[]>([]);
  let requestReason = $state(normalizeReason(reasonParam));
  // The signer of a one-tap request, as the API checked it at /load; it alone can name the requester.
  let approvalIssuer = $state('');
  // Set when a `permissions` parameter is present (even empty) but
  // unreadable: the request is refused rather than falling back to the
  // default abilities, which apply only when the parameter is absent.
  let permissionsParamError = '';
  try {
    // UTF-8 JSON: `atob` alone would mangle non-ASCII reasons.
    const payload = approvalRequestMode ? null : readDelegatePermissionsParam($page.url.searchParams);
    if (payload) {
      requestedPermissions = payload.permissions;
      const payloadReason = normalizeReason(payload.reason);
      if (payloadReason) {
        requestReason = payloadReason;
      }
    }
  } catch {
    permissionsParamError = 'Could not decode the requested permissions. Restart the CLI command to get a new link.';
    error = permissionsParamError;
  }

  // TC-547: an ordinary link (no device transaction) may only return the
  // delegation to this device or a registered app, and a node OpenKey does
  // not recognize must be acknowledged. Device links are bound by the
  // server-verified device request instead.
  const callbackCheck = $derived(approvalRequestMode || deviceTransactionId
    ? null
    : checkDelegateCallback(callback, withConfiguredEntries(REGISTERED_CALLBACK_ENDPOINTS, import.meta.env.VITE_DELEGATE_CALLBACK_URLS, isCanonicalHttpsEndpoint)));
  const hostCheck = $derived(deviceTransactionId
    ? null
    : checkDelegateHost(host, withConfiguredEntries(KNOWN_NODE_ORIGINS, import.meta.env.VITE_DELEGATE_NODE_ORIGINS, isCanonicalHttpsOrigin)));
  const linkPolicyError = $derived(callbackCheck?.ok === false
    ? callbackCheck.reason
    : hostCheck?.ok === false ? hostCheck.reason : '');
  const approvedCallback = $derived(callbackCheck?.ok ? callbackCheck.callback : null);
  const requester = $derived(approvalRequestMode
    ? approvalRequester(approvalIssuer, withConfiguredEntries(TINYCLOUD_ONE_REQUESTER_DIDS, import.meta.env.VITE_TINYCLOUD_ONE_REQUESTER_DIDS, isEd25519DidKey))
    : delegateRequester(approvedCallback));
  // A one-tap request for one named secret names TinyCloud One in its heading only when One's key signed it.
  const oneSecretWords = $derived(approvalRequestMode
    ? {
        headline: requester ? fill(ONE_SECRET.heading, { requester: requester.displayName }) : ONE_SECRET.headingUnnamed,
        hint: ONE_SECRET.hint,
        decryptNote: ONE_SECRET.decryptNote,
      }
    : null);
  const showLoopbackHint = $derived(
    shouldShowLoopbackHint({ delegating, approvedCallback, deviceTransactionId, callbackInFlight, pasteCode }),
  );
  const hostNeedsAcknowledgment = $derived(hostCheck?.ok === true && !hostCheck.recognized);
  let hostAcknowledged = $state(false);
  const delegationExpiresAt = $derived(siweExpirationTime(siweMessage) ?? '');
  // The raw-SIWE fallback signs the message as written, so the access lasts until its own Expiration Time.
  const fallbackAccessMs = $derived(remainingAccessMs(delegationExpiresAt));

  // Device approvals never trust the link: the reason and every binding it
  // carries must come from (or equal) the server's pending request. Key
  // selection waits for this check.
  if (deviceTransactionId) requestReason = '';
  // True while a device link is checked against the server's own record.
  let deviceLinkPending = $state(false);
  let deviceRequestVerified = Promise.resolve();
  async function verifyDeviceRequest() {
    const record = await loadVerifiedDeviceRequest(import.meta.env.VITE_API_URL || '', deviceUserCode, {
      transactionId: deviceTransactionId,
      sessionDid: did,
      publicJwk: jwk,
      relayPublicJwk,
      nodeOrigin: host,
      shareOrigin: deviceShareOrigin,
      permissions: requestedPermissions,
      expiry: expiryParam,
    });
    requestReason = normalizeReason(deviceRequestReason(record));
    expiryMaxMs = deviceRequestTtlSeconds(record) * 1000;
    expiryParam = `${deviceRequestDefaultSeconds(record)}s`;
  }
  function startDeviceVerification() {
    deviceLinkPending = true;
    deviceRequestVerified = verifyDeviceRequest();
    void deviceRequestVerified.then(
      () => { deviceLinkPending = false; },
      (cause: unknown) => {
        if (cause instanceof DeviceLinkError) stopApproval(approvalStop(cause.stopId));
        else stopApproval(approvalStop('S26'), startDeviceVerification);
        deviceLinkPending = false;
      },
    );
  }
  if (deviceTransactionId && !relayInvalid && !permissionsParamError) startDeviceVerification();

  // The wallet the CLI requested: the one owner (chain and address) every
  // requested space and raw encryption network resolves to. Owners that
  // disagree make the request unsignable for any wallet, so it is refused
  // like an unreadable one (see expectedSigner).
  const requestSigner = $derived(expectedSigner(requestedPermissions));
  const expectedAddress = $derived(requestSigner.kind === 'owner' ? requestSigner.address : null);
  const requestOwnerError = $derived(requestSigner.kind === 'conflict'
    ? `This request names more than one account (${requestSigner.owners.join(', ')}). Restart the CLI command to get a new link.`
    : '');
  const expectedAddressShort = $derived(
    expectedAddress
      ? `${expectedAddress.slice(0, 6)}...${expectedAddress.slice(-4)}`
      : '',
  );
  // True once we've completed the auto-select attempt for the expected wallet.
  // Used to avoid showing the "wallet not connected" warning before keys load.
  let preselectAttempted = $state(false);
  // With no wallet named, KeyPicker offers the primary key; the other keys
  // (separate account owners) stay hidden until the user asks for them.
  let showOtherKeys = $state(false);
  const selectedMatchesExpected = $derived(
    !expectedAddress ||
      (selectedKey?.address?.toLowerCase() === expectedAddress),
  );

  function normalizeReason(value: unknown): string {
    if (typeof value !== 'string') return '';
    return cleanConsentText(value).slice(0, 500);
  }

  async function loadApprovalRequest() {
    approvalRequestLoading = true;
    try {
      let fragment = location.hash;
      const hasQuery = !!location.search;
      // Scrub even when storage is blocked or the reference is malformed.
      history.replaceState(history.state, '', location.pathname);
      if (hasQuery || !/^[a-z2-7]{26}$/.test(approvalRequestId)) {
        stopApproval(approvalStop('S1'));
        return;
      }
      const storageKey = `openkey.approval.${approvalRequestId}`;
      try {
        if (document.documentElement.dataset.approvalStorageError === '1') throw new Error();
        fragment ||= sessionStorage.getItem(storageKey) || '';
        if (fragment) sessionStorage.setItem(storageKey, fragment);
      } catch {
        stopApproval(approvalStop('S2'));
        return;
      }
      if (!fragment) {
        stopApproval(approvalStop('S3'));
        return;
      }
      const reference = location.pathname + fragment;
      approvalReference = reference;
      const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/approval-requests/${approvalRequestId}/load`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'omit',
        redirect: 'error',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        body: JSON.stringify({ reference }),
      });
      const result = await response.json().catch(() => null);
      if (!response.ok) {
        const view = stopForReply({ status: response.status, code: result?.code, phase: 'load' });
        if (view.id === 'S4') sessionStorage.removeItem(storageKey);
        stopApproval(view, loadApprovalRequest);
        return;
      }
      if (!result?.request) throw new ServerReplyError(response.status);
      if (result.approved) {
        done = true;
        step = 'done';
      }
      if (result.denied === true) {
        // Older API responses carry no `denied`; they read as an open request, as before.
        declined = true;
        done = true;
        sessionStorage.removeItem(storageKey);
      }
      const request = result.request;
      did = request.targetDid;
      jwk = request.targetPublicJwk;
      host = request.nodeOrigin;
      requestedPermissions = request.permissions;
      approvalIssuer = typeof request.issuer === 'string' ? request.issuer : '';
      requestReason = normalizeReason(request.reason);
      // A request that decrypts secrets lasts 7 days at most, whatever it signed; the server refuses more.
      const maxSeconds = approvalLifetimeCapSeconds(request.permissions, request.grantLifetimeSeconds);
      expiryMaxMs = maxSeconds * 1000;
      const startSeconds = approvalRequestStartSeconds(maxSeconds, request.suggestedLifetimeSeconds);
      approvalRequestStartMs = Math.max(MIN_EXPIRY_MS, startSeconds * 1000);
      expiryParam = `${startSeconds}s`;
      // The box only shows where this OpenKey has leases on (`renewalAvailable`); otherwise the plain line, and finite.
      if (request.renewal && result.renewalAvailable === true) {
        renewalMaxLeaseMs = Math.min(request.renewal.leaseLifetimeSeconds * 1000, MAX_LEASE_MS);
        renewalPurpose = request.purpose;
      }
      approvalRequestLoaded = true;
    } catch (cause) {
      stopApproval(cause instanceof ServerReplyError ? approvalStop('S27', { status: cause.status }) : approvalStop('S6'), loadApprovalRequest);
    } finally {
      approvalRequestLoading = false;
    }
  }

  function shortService(service: string): string {
    return service.startsWith('tinycloud.') ? service.slice('tinycloud.'.length) : service;
  }
  function shortSpace(space: string): string {
    return space.startsWith('tinycloud:') ? space.slice(space.lastIndexOf(':') + 1) : space;
  }
  function shortAction(service: string, action: string): string {
    return action.startsWith(`${service}/`) ? action.slice(service.length + 1) : action;
  }

  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      // Discover wallets via EIP-6963
      window.addEventListener('eip6963:announceProvider', ((event: CustomEvent<EIP6963ProviderDetail>) => {
        const detail = event.detail;
        if (!wallets.find(w => w.info.uuid === detail.info.uuid)) {
          wallets = [...wallets, detail];
        }
      }) as EventListener);
      window.dispatchEvent(new Event('eip6963:requestProvider'));
    }
  });

  $effect(() => {
    if (typeof window === 'undefined') return;

    const updateScrollAffordance = () => {
      if (step !== 'consent' || !actionRow) {
        showScrollToApprove = false;
        return;
      }

      const documentElement = document.documentElement;
      const pageCanScroll = documentElement.scrollHeight > window.innerHeight + 8;
      const actionRect = actionRow.getBoundingClientRect();
      showScrollToApprove = pageCanScroll && actionRect.bottom > window.innerHeight - 24;
    };

    const scheduleUpdate = () => requestAnimationFrame(updateScrollAffordance);

    scheduleUpdate();
    window.addEventListener('scroll', scheduleUpdate, { passive: true });
    window.addEventListener('resize', scheduleUpdate);

    return () => {
      window.removeEventListener('scroll', scheduleUpdate);
      window.removeEventListener('resize', scheduleUpdate);
    };
  });

  function scrollToApprove() {
    if (typeof window === 'undefined' || !actionRow) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    actionRow.scrollIntoView({
      behavior: prefersReducedMotion ? 'auto' : 'smooth',
      block: 'end',
    });
  }

  // Reactively load keys when session becomes available
  $effect(() => {
    if (dispatchReady && (!approvalRequestMode || approvalRequestLoaded) && !declined && !linkStop && !deviceLinkPending && !failure && !preparedMode && $session.data && !keysLoaded) {
      keysLoaded = true;
      loadKeys();
    }
  });

  async function loadKeys() {
    loading = true;
    try {
      const reviewEmail = $session.data?.user.email.trim().toLowerCase();
      if (reviewEmail && ['openai-review@tinycloud.xyz', 'google-review@tinycloud.xyz'].includes(reviewEmail)) {
        const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/delegate/prepare`, { credentials: 'include' });
        if (!response.ok) throw new Error('Could not load the review account.');
        const { key } = await response.json() as { key: { address: string; did: string } };
        keys = [{
          id: 'reviewer', address: key.address, publicKey: key.address, keyIndex: 0,
          label: null, keyType: 'MANAGED', createdAt: '', isPrimary: true,
        }];
      } else {
        const result = await api.listKeys();
        keys = activeKeys(result.keys);
      }
    } catch (e: any) {
      error = delegateErrorMessage(e, loadKeys);
    } finally {
      loading = false;
    }
  }

  // Auto-select the CLI-requested wallet, otherwise the user's only active
  // key. With several keys the owner chooses, with the primary offered first.
  // Only runs on the initial 'select-key' step so revisiting the picker
  // doesn't trap the user in an auto-advance loop.
  $effect(() => {
    if (!dispatchReady || (approvalRequestMode && !approvalRequestLoaded) || linkStop || deviceLinkPending || failure || done || preparedMode || loading || preselectAttempted || !$session.data) return;
    if (step !== 'select-key') return;
    preselectAttempted = true;
    const match = autoSelectKey(keys, expectedAddress);
    if (match) {
      onKeySelect(match);
    }
  });

  async function generateAndSelect() {
    loading = true;
    error = '';
    try {
      const { key } = await api.generateKey();
      if (!keys.some((k) => k.id === key.id)) keys = [...keys, key];
      loading = false;
      await onKeySelect(key);
    } catch (e: any) {
      error = delegateErrorMessage(e, generateAndSelect);
      loading = false;
    }
  }

  async function onKeySelect(key: EthereumKey) {
    if (!jwk) {
      stopApproval(approvalStop('S1'));
      return;
    }

    selectedKey = key;
    if (expectedAddress && !selectedMatchesExpected) {
      stopApproval(approvalStop('S18', { values: stopValues }));
      return;
    }
    error = '';
    preparing = true;

    try {
      await deviceRequestVerified;
      const data = await prepareDelegation(key);
      applyPreparedDelegation(data);
      editingPermissions = false;
      step = 'consent';
    } catch (e: any) {
      error = delegateErrorMessage(e, () => onKeySelect(key));
      if (!failure) selectedKey = null;
    } finally {
      preparing = false;
    }
  }

  async function prepareDelegation(key: EthereumKey, actionKeys?: string[]) {
    // Every signing path starts here: never prepare the default abilities
    // for a request whose permissions could not be read.
    if (permissionsParamError) throw new OwnerMessageError(permissionsParamError);
    if (approvalRequestMode && !approvalRequestLoaded) throw new OwnerMessageError('Open the approval link again.');
    if (linkPolicyError) throw new OwnerMessageError(linkPolicyError);
    if (requestOwnerError) throw new OwnerMessageError(requestOwnerError);
    const API_URL = import.meta.env.VITE_API_URL || '';
    const body: Record<string, unknown> = {
      keyId: key.id,
      jwk,
      host,
      prefix: 'default',
    };
    if (approvalRequestMode) body.approvalRequestId = approvalRequestId;
    if (actionKeys) {
      body.actionKeys = actionKeys;
    }
    // CLI-driven flow (e.g. tc auth request): forward the requested caps
    // verbatim. The API uses these instead of the default abilities, so the
    // baseline-edit UI surface is bypassed for CLI requests.
    if (requestedPermissions.length > 0) {
      body.permissions = requestedPermissions;
    }
    if (requestReason) {
      body.reason = requestReason;
    }
    if (expiryParam) {
      body.expiry = expiryParam;
      if (expiryChosen) {
        body.expiryChosen = true;
        body.linkExpiry = requestedExpiryParam ?? '';
        if (linkExpiryChangeable) body.expiryChangeable = true;
      }
    }
    // TC-2933: the renewal choice is bound into this preview; approving reads it from there.
    if (approvalRequestMode && renewalChoiceBody()) body.renewal = renewalChoiceBody();
    // The API refuses a device delegation outside the transaction's lifetime.
    if (deviceTransactionId) body.deviceTransactionId = deviceTransactionId;

    const res = await fetch(`${API_URL}/api/delegate/prepare`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) throw await readDelegateFailure(res);

    return readDelegateSuccess(res, (data) => typeof data.prepared?.siwe === 'string');
  }

  function applyPreparedDelegation(data: any) {
    const permissions = Array.isArray(data.permissions)
      ? (data.permissions as DelegatePermission[])
      : [];
    preparedData = data.prepared;
    passkeyNeed = data.passkey && typeof data.passkey === 'object' ? data.passkey as ApprovalPasskeyNeed : null;

    siweMessage = data.prepared?.siwe || '';
    spaceSetup = parseSpaceSetup(data.spaceSetup);
    ownFolderLine = ownFolderOnlyLine(data);
    permissionOptions = permissions;
    selectedActionKeys = Array.isArray(data.selectedActionKeys)
      ? data.selectedActionKeys.filter((key: unknown): key is string => typeof key === 'string')
      : permissions.flatMap((permission) => permission.actions.map((action) => action.key));
    permissionsEdited = Boolean(data.edited);
    // Versioned protocol: capture the opaque single-use token so /complete
    // can re-validate every bound invariant server-side.
    authorizationContextToken =
      typeof data.authorizationContext?.token === 'string'
        ? data.authorizationContext.token
        : null;
    // Sol MAJOR-9: build the STABLE baseline review model from the FIRST
    // prepared SIWE only. Re-derivation on every narrowing would drop
    // optional actions the user removed and make them un-selectable
    // again — which silently changes the presented authority. Later
    // /prepare responses are used only for `siweMessage`,
    // `authorizationContextToken`, and `selectedActionKeys`; the review
    // model itself is frozen at the first prepare so the user retains
    // the full add/remove surface.
    if (baselineSiweForReview === null && siweMessage && selectedKey) {
      try {
        const model = parseCapabilityReview({
          message: siweMessage,
          signer: {
            label: selectedKey.label ?? `Key ${selectedKey.keyIndex}`,
            address: selectedKey.address,
            chainId: 1,
            provenance: selectedKey.keyType === 'EXTERNAL' ? 'external' : 'managed',
          },
          editable: true,
          metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' },
          reason: { text: requestReason, source: requestReason ? 'caller' : 'none' },
          requester: {
            displayName: requester?.displayName ?? '',
            verifiedOrigin: null,
            appId: null,
            manifestName: null,
            manifestNameProvenance: 'none',
            manifestId: null,
            manifestIdProvenance: 'none',
            manifestDigest: null,
            domainWarning: false,
            originWarning: false,
          },
        });
        reviewModel = model;
        reviewSelection = defaultSelection(model);
        baselineSiweForReview = siweMessage;
      } catch {
        reviewModel = null;
      }
    } else if (!siweMessage) {
      reviewModel = null;
    } else if (reviewModel && siweMessage && siweMessage !== reviewModel.rawMessage) {
      // The stable baseline (grant selection surface) is kept from the
      // first prepared SIWE. But the displayed raw bytes MUST reflect the
      // CURRENT preparedData.siwe — after a narrowing round-trip the
      // server returned new bytes, and those are the bytes the signer
      // will produce a signature over. Rendering the stale first-prepare
      // bytes here means the user reviews text that no longer matches
      // what will be signed. Assign a fresh model object so Svelte
      // reactivity picks up the change.
      reviewModel = { ...reviewModel, rawMessage: siweMessage, expiry: siweExpirationTime(siweMessage) ?? reviewModel.expiry };
    }
    approveBlockedByFailure = false;
  }

  function resetDelegationState() {
    preparedData = null;
    siweMessage = '';
    spaceSetup = null;
    ownFolderLine = null;
    spaceReadiness = null;
    permissionOptions = [];
    selectedActionKeys = [];
    editingPermissions = false;
    updatingPermissions = false;
    permissionsEdited = false;
    // Sol MAJOR-9: clear the stable baseline so the next selectKey()
    // start-fresh flow rebuilds it from the new prepared SIWE.
    baselineSiweForReview = null;
    reviewModel = null;
    reviewSelection = new Set<string>();
    // TC-2272: the next prepare starts again from what the request asked for, so the picker's
    // requested window (and the signed-request maximum) is not the previous pick.
    expiryChoiceMs = null;
    expiryChosen = false;
    if (requestedExpiryParam !== null) expiryParam = requestedExpiryParam;
    requestedExpiryParam = null;
  }

  function showLinkWallet() {
    step = 'link-wallet';
    error = '';
    selectedWallet = null;
  }

  function goBack() {
    selectedKey = null;
    step = 'select-key';
    error = '';
    resetDelegationState();
  }

  const DECLINE_FAILED = 'Could not decline right now. Nothing was changed. Try again.';
  async function declineRequest() {
    if (declining || declined || !approvalRequestMode || !approvalReference) return;
    declining = true;
    error = '';
    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/approval-requests/${approvalRequestId}/deny`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        redirect: 'error',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        body: JSON.stringify({ reference: approvalReference }),
      });
      if (response.ok) {
        sessionStorage.removeItem(`openkey.approval.${approvalRequestId}`);
        approvalReference = '';
        declined = true;
        done = true;
      } else if (response.status === 409) {
        stopApproval(approvalStop('S13', { status: response.status }));
      } else if (response.status === 410) {
        // Same end as /load answering expired: the request is gone, so the page shows the expired message alone.
        sessionStorage.removeItem(`openkey.approval.${approvalRequestId}`);
        approvalReference = '';
        approvalRequestLoaded = false;
        stopApproval(approvalStop('S4', { status: response.status, requester: expiredRequesterName }));
      } else {
        error = DECLINE_FAILED;
      }
    } catch {
      error = DECLINE_FAILED;
    } finally {
      declining = false;
    }
  }

  function selectWallet(wallet: EIP6963ProviderDetail) {
    selectedWallet = wallet;
    error = '';
  }

  function getProvider(): any {
    if (selectedWallet) return selectedWallet.provider;
    return (window as any).ethereum;
  }

  async function connectAndLink() {
    const provider = getProvider();
    if (!provider) {
      error = 'No wallet detected. Please install a browser wallet and try again.';
      return;
    }

    linking = true;
    error = '';

    try {
      const accounts: string[] = await provider.request({ method: 'eth_requestAccounts' });
      if (!accounts || accounts.length === 0) {
        throw new OwnerMessageError('No accounts returned from wallet');
      }
      const account = accounts[0];

      const challenge = await api.getLinkChallenge();

      const signature: string = await provider.request({
        method: 'personal_sign',
        params: [challenge.message, account],
      });

      await api.linkWallet({
        address: account,
        signature,
        message: challenge.message,
      });

      // Reload keys and go back to selection
      await loadKeys();
      step = 'select-key';
    } catch (e: any) {
      if (e.code === 4001) {
        error = 'Wallet connection was rejected.';
      } else {
        error = delegateErrorMessage(e);
      }
    } finally {
      linking = false;
    }
  }

  // Wallet chosen by user for external key signing (distinct from selectedWallet used in link-wallet flow)
  let signingWallet = $state<EIP6963ProviderDetail | null>(null);

  function getSigningProvider(): any {
    if (signingWallet) return signingWallet.provider;
    return (window as any).ethereum;
  }

  function approveDelegate() {
    if (approveBlockedByFailure) return;
    if (hostNeedsAcknowledgment && !hostAcknowledged) {
      error = 'Confirm that you run or trust this TinyCloud node.';
      return;
    }
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }
    if (updatingPermissions) {
      error = 'Permissions are still updating.';
      return;
    }
    if (approveBlockedReason) {
      error = approveBlockedReason;
      return;
    }
    if (permissionOptions.length > 0 && selectedActionKeys.length === 0) {
      error = 'At least one permission is required.';
      return;
    }
    // Defense-in-depth: the Approve button is already disabled in this case,
    // but block here too so a stray invocation can't slip through.
    if (walletMismatchReason) {
      stopApproval(approvalStop('S18', { values: stopValues }));
      return;
    }

    if (selectedKey.keyType === 'MANAGED') {
      doManagedDelegate();
    } else {
      // External key: need a wallet to sign
      if (wallets.length > 1 && !signingWallet) {
        // Multiple wallets detected — let user choose
        step = 'choose-wallet';
        error = '';
      } else {
        doExternalDelegate();
      }
    }
  }

  function onSigningWalletSelect(wallet: EIP6963ProviderDetail) {
    signingWallet = wallet;
    error = '';
  }

  function confirmSigningWallet() {
    if (!signingWallet && wallets.length > 0) {
      error = 'Please select a wallet.';
      return;
    }
    doExternalDelegate();
  }

  function backToConsent() {
    step = 'consent';
    error = '';
  }

  function isActionSelected(key: string): boolean {
    return selectedActionKeys.includes(key);
  }

  function selectedActions(permission: DelegatePermission): DelegatePermissionAction[] {
    return permission.actions.filter((action) => isActionSelected(action.key));
  }

  // Translate a capability-review selection into the server's actionKey
  // strings (see reviewSelectionToActionKeys for the ID correlation).
  function mapReviewSelectionToActionKeys(selection: Set<string>): string[] {
    return reviewModel ? reviewSelectionToActionKeys(reviewModel, permissionOptions, selection) : [];
  }

  // Approve signs the last prepared SIWE. If the visible selection differs
  // from it (a narrowing /prepare failed or never ran), block approval until
  // a /prepare for the visible selection succeeds. While one is in flight,
  // `approving` already disables Approve.
  const walletMismatchReason = $derived(
    expectedAddress && !selectedMatchesExpected
      ? `This request is for wallet ${expectedAddressShort}. Choose a key for that wallet, or ask the app or command for a new request.`
      : null,
  );
  const approveBlockedReason = $derived(
    walletMismatchReason ??
    (reviewModel && !updatingPermissions &&
      !preparedMatchesSelection(reviewModel, permissionOptions, reviewSelection, selectedActionKeys)
      ? 'The permissions shown have not been prepared for signing. Change a permission or Reset to try again.'
      : null),
  );

  async function toggleAction(action: DelegatePermissionAction) {
    if (action.required) return;

    const nextKeys = isActionSelected(action.key)
      ? selectedActionKeys.filter((selectedKey) => selectedKey !== action.key)
      : [...selectedActionKeys, action.key];

    if (nextKeys.length === 0) {
      error = 'At least one permission is required.';
      return;
    }

    await updatePermissions(nextKeys);
  }

  async function updatePermissions(nextKeys: string[]) {
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }

    updatingPermissions = true;
    error = '';

    try {
      const data = await prepareDelegation(selectedKey, nextKeys);
      applyPreparedDelegation(data);
      editingPermissions = true;
    } catch (e: any) {
      error = delegateErrorMessage(e, () => updatePermissions(nextKeys), true);
    } finally {
      updatingPermissions = false;
    }
  }

  async function resetPermissions() {
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }

    updatingPermissions = true;
    error = '';

    try {
      const data = await prepareDelegation(selectedKey);
      applyPreparedDelegation(data);
      editingPermissions = false;
    } catch (e: any) {
      error = delegateErrorMessage(e, resetPermissions, true);
    } finally {
      updatingPermissions = false;
    }
  }

  async function refreshAuthorizationContext(key: EthereumKey, actions: string[]) {
    const data = await prepareDelegation(key, actions);
    const expected = new Set(actions);
    if (!reviewModel || !Array.isArray(data.selectedActionKeys) ||
      data.selectedActionKeys.length !== expected.size ||
      new Set(data.selectedActionKeys).size !== expected.size ||
      !data.selectedActionKeys.every((action: unknown) => typeof action === 'string' && expected.has(action)) ||
      typeof data.authorizationContext?.token !== 'string' || !data.authorizationContext.token ||
      typeof data.prepared?.siwe !== 'string' || !data.prepared.siwe.trim() ||
      !Array.isArray(data.permissions) ||
      !preparedMatchesSelection(reviewModel, data.permissions, reviewSelection, data.selectedActionKeys)) {
      throw new OwnerMessageError('The request could not be prepared with the approved selection.');
    }
    const refreshed = parseCapabilityReview({
      message: data.prepared.siwe,
      signer: reviewModel.signer,
      requester: reviewModel.requester,
      reason: reviewModel.reason,
      metadataTrust: reviewModel.metadataTrust,
      editable: true,
    });
    const signedActions = selectedServerActionIds(refreshed,
      new Set(refreshed.permissions.flatMap(grant => grant.actions.map(action => action.id))));
    if (refreshed.protocol !== 'tinycloud-siwe-recap' || !refreshed.immutable ||
      refreshed.parseWarnings.some(warning => warning.code !== 'unknown-service') ||
      refreshed.immutable.address.toLowerCase() !== key.address.toLowerCase() ||
      signedActions.length !== expected.size || !signedActions.every(action => expected.has(action))) {
      throw new OwnerMessageError('The refreshed message does not match the approved selection.');
    }
    applyPreparedDelegation(data);
  }

  async function doManagedDelegate(refreshAttempted = false) {
    delegating = true;
    error = '';
    const key = selectedKey;
    const actions = [...selectedActionKeys];

    try {
      // Blocker 1: the widget MUST forward the prepared SIWE bytes and the
      // opaque /prepare token to the server so the managed-approval path
      // signs the exact bytes the review UI displayed. Without them the
      // server would regenerate a fresh preview with new
      // issuedAt/expirationTime — different bytes than the user just
      // reviewed. We entered this flow by way of applyPreparedDelegation
      // (see step === 'consent'), so both fields MUST be present. Fail
      // closed rather than silently degrading to the legacy regenerate path.
      if (!preparedData) {
        throw new OwnerMessageError('No prepared session data. Please go back and try again.');
      }
      if (!authorizationContextToken) {
        throw new OwnerMessageError('Missing authorization context token from /prepare. Please restart the delegation.');
      }

      const API_URL = import.meta.env.VITE_API_URL || '';
      const passkeyAssertion = await answerApprovalPasskey(passkeyNeed);
      const body: Record<string, unknown> = {
        keyId: selectedKey!.id,
        jwk,
        host,
        prefix: 'default',
        // Blocker 1: bind the caller-echoed prepared block + selected
        // action set + token so the server signs the exact preview bytes
        // instead of regenerating a new SIWE.
        prepared: preparedData,
        authorizationContextToken,
        selectedActionIds: selectedActionKeys,
        protocolVersion: 1,
        ...(passkeyAssertion ? { passkeyAssertion } : {}),
      };
      if (approvalRequestMode) body.approvalRequestId = approvalRequestId;
      if (permissionsEdited) {
        body.actionKeys = selectedActionKeys;
      }
      if (requestedPermissions.length > 0) {
        body.permissions = requestedPermissions;
      }
      if (requestReason) {
        body.reason = requestReason;
      }
      if (expiryParam) {
        body.expiry = expiryParam;
        if (expiryChosen) {
          body.expiryChosen = true;
          body.linkExpiry = requestedExpiryParam ?? '';
          if (linkExpiryChangeable) body.expiryChangeable = true;
        }
      }
      if (deviceTransactionId) body.deviceTransactionId = deviceTransactionId;

      const res = await fetch(`${API_URL}/api/delegate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!res.ok) throw await readDelegateFailure(res);

      const data = await readDelegateSuccess(res, (body) => body.hostActivated === true || typeof body.delegationHeader?.Authorization === 'string');
      if (!data.hostActivated) {
        await activateWithHost(host, data.delegationHeader);
      }
      await finishDelegate(data);
    } catch (cause) {
      const classification = delegateErrorClassification(cause, refreshAttempted);
      if (classification === 'panel-after-failed-refresh') {
        requestExpired = true;
      } else if (classification === 'refresh-once') {
        if (!key) {
          error = delegateErrorMessage(cause);
          return;
        }
        try {
          await refreshAuthorizationContext(key, actions);
        } catch (refreshCause) {
          const refreshClassification = delegateErrorClassification(refreshCause, true);
          if (refreshClassification === 'panel-after-failed-refresh') requestExpired = true;
          else error = delegateErrorMessage(refreshCause, () => doManagedDelegate());
          return;
        }
        await doManagedDelegate(true);
      } else {
        error = delegateErrorMessage(cause, () => doManagedDelegate());
        // The refused challenge is spent: prepare again for a new one, and keep the API's words on screen.
        if (key && isPasskeyApprovalRefusal(cause)) {
          const refusal = error;
          try { await refreshAuthorizationContext(key, actions); } catch { /* the next Approve is refused with the API's words */ }
          error = refusal;
        }
      }
    } finally {
      delegating = false;
    }
  }

  async function doExternalDelegate(refreshAttempted = false) {
    if (!preparedData) {
      error = 'No prepared session data. Please go back and try again.';
      return;
    }
    if (approveBlockedReason) {
      error = approveBlockedReason;
      return;
    }
    // Sign and complete exactly what is prepared now: a /prepare response
    // landing during the wallet prompts must not change the signed bytes or
    // the selection reported with them.
    const prepared = preparedData;
    const contextToken = authorizationContextToken;
    const selectedActionIds = [...selectedActionKeys];
    const edited = permissionsEdited;
    const key = selectedKey;

    delegating = true;
    error = '';

    try {
      const provider = getSigningProvider();
      if (!provider) {
        throw new OwnerMessageError(STOPS.S32.lines.noWallet);
      }

      // Try each wallet to find the matching account
      let matchingAccount: string | undefined;
      let matchingProvider = provider;

      // If multiple wallets and no explicit choice, try all of them
      const providersToTry = signingWallet
        ? [signingWallet.provider]
        : wallets.length > 0
          ? wallets.map(w => w.provider)
          : [provider];

      for (const p of providersToTry) {
        try {
          const accounts: string[] = await p.request({ method: 'eth_requestAccounts' });
          const found = accounts.find(
            (a: string) => a.toLowerCase() === selectedKey!.address.toLowerCase()
          );
          if (found) {
            matchingAccount = found;
            matchingProvider = p;
            break;
          }

          // Try requesting more accounts
          try {
            await p.request({
              method: 'wallet_requestPermissions',
              params: [{ eth_accounts: {} }],
            });
            const moreAccounts: string[] = await p.request({ method: 'eth_accounts' });
            const found2 = moreAccounts.find(
              (a: string) => a.toLowerCase() === selectedKey!.address.toLowerCase()
            );
            if (found2) {
              matchingAccount = found2;
              matchingProvider = p;
              break;
            }
          } catch {
            // wallet_requestPermissions not supported or rejected
          }
        } catch {
          // This provider failed, try next
        }
      }

      if (!matchingAccount) {
        throw new OwnerMessageError(
          fill(STOPS.S32.lines.walletLacks, { short: shortWallet(selectedKey!.address) }),
        );
      }

      const signature: string = await matchingProvider.request({
        method: 'personal_sign',
        params: [prepared.siwe, matchingAccount],
      });

      const API_URL = import.meta.env.VITE_API_URL || '';
      const compRes = await fetch(`${API_URL}/api/delegate/complete`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prepared,
          signature,
          host,
          jwk,
          edited,
          reason: requestReason || undefined,
          // Forward the requested baseline so the server checks the signed
          // SIWE against it; without it the server checks the own folder.
          ...(requestedPermissions.length > 0
            ? { permissions: requestedPermissions }
            : {}),
          // Versioned protocol: echo the /prepare token so the server can
          // re-verify every bound invariant (user, key, JWK, host, immutable
          // SIWE fields, allowed action set, required action set).
          ...(contextToken
            ? {
                authorizationContextToken: contextToken,
                selectedActionIds,
              }
            : {}),
          ...(deviceTransactionId ? { deviceTransactionId } : {}),
          ...(approvalRequestMode ? { approvalRequestId } : {}),
        }),
      });

      if (!compRes.ok) throw await readDelegateFailure(compRes);

      let data = await readDelegateSuccess(compRes, (body) =>
        body.hostActivated === true || typeof body.delegationHeader?.Authorization === 'string' || !!body.renewalSignature,
      );
      if (data.renewalSignature) {
        // TC-2933: the wallet signs the renewal lease too; declining it approves nothing.
        renewalSigningMs = data.renewalSignature.leaseLifetimeSeconds * 1000;
        let leaseSignature: string;
        try {
          leaseSignature = await matchingProvider.request({
            method: 'personal_sign',
            params: [data.renewalSignature.message, matchingAccount],
          });
        } catch {
          throw new OwnerMessageError(RENEWAL_NOT_SET_UP);
        } finally {
          renewalSigningMs = null;
        }
        const leaseRes = await fetch(`${API_URL}/api/approval-requests/${approvalRequestId}/renewal-signature`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ signature: leaseSignature }),
        });
        if (!leaseRes.ok) throw new OwnerMessageError(RENEWAL_NOT_SET_UP);
        data = await leaseRes.json();
      }
      if (!data.hostActivated) {
        await activateWithHost(host, data.delegationHeader);
      }
      await finishDelegate(data);
    } catch (cause) {
      const classification = delegateErrorClassification(cause, refreshAttempted);
      if (classification === 'panel-after-failed-refresh') {
        requestExpired = true;
      } else if (classification === 'refresh-once') {
        if (!key) {
          error = delegateErrorMessage(cause);
          return;
        }
        try {
          await refreshAuthorizationContext(key, selectedActionIds);
        } catch (refreshCause) {
          const refreshClassification = delegateErrorClassification(refreshCause, true);
          if (refreshClassification === 'panel-after-failed-refresh') requestExpired = true;
          else error = delegateErrorMessage(refreshCause, () => doExternalDelegate());
          return;
        }
        // A fresh prepare changes the signed bytes; obtain a fresh wallet signature.
        await doExternalDelegate(true);
      } else if (cause && typeof cause === 'object' && 'code' in cause && cause.code === 4001) {
        error = STOPS.S32.lines.walletDeclined;
      } else {
        error = delegateErrorMessage(cause, () => doExternalDelegate());
      }
    } finally {
      delegating = false;
    }
  }

  // Mints a short code for this delegation. The first mint records a refusal for the
  // fallback text; a renewal (reportError) shows its own retry line instead.
  async function mintShortCode(payload: any, reportError = false) {
    codeRenewFailed = false;
    try {
      const API_URL = import.meta.env.VITE_API_URL || '';
      const response = await fetch(`${API_URL}/api/delegation-codes`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ delegation: publicDelegationForCode(payload) }),
      });
      if (!response.ok) {
        if (!reportError) {
          const body: unknown = await response.json().catch(() => null);
          const code = typeof body === 'object' && body !== null && 'code' in body ? body.code : undefined;
          shortCodeFailure = { status: response.status, code };
        }
        throw new Error('Mint request failed');
      }
      const result = await response.json();
      if (typeof result.code !== 'string' || !/^[a-z2-7]{4}-[a-z2-7]{4}$/i.test(result.code)) throw new Error('Invalid code response');
      const remainingMs = typeof result.expiresAt === 'string'
        ? remainingFromServerClock(result.expiresAt, response.headers.get('date'))
        : null;
      shortCode = result.code.toUpperCase();
      codeCountdown = null;
      // Read at receipt: the countdown runs on the monotonic clock from here.
      codeDeadline = performance.now() + (remainingMs ?? 300_000);
    } catch {
      // The full delegation remains available when the broker is unreachable.
      if (reportError) codeRenewFailed = true;
    }
  }

  async function getNewCode() {
    if (!codeCountdown?.expired || codeRenewing || delegationExpired || !delegationPayload) return;
    codeRenewing = true;
    try {
      await mintShortCode(delegationPayload, true);
    } finally {
      codeRenewing = false;
    }
  }
  async function finishDelegate(data: any) {
    const payload = permissionsEdited ? { ...data, edited: true } : data;
    spaceReadiness = spaceReadinessResult(payload, spaceSetup);
    if (approvalRequestMode) {
      // The authenticated API has durably encrypted and saved this exact
      // delegation before returning; the CLI independently verifies and ACKs.
      done = true;
      step = 'done';
      sessionStorage.removeItem(`openkey.approval.${approvalRequestId}`);
      return;
    }

    if (deviceTransactionId) {
      const API_URL = import.meta.env.VITE_API_URL || '';
      const delegationExpiresAt = payload.expiresAt ?? payload.expirationTime ?? payload.expiry;
      if (typeof delegationExpiresAt !== 'string') throw new OwnerMessageError('The approved delegation has no expiry binding.');
      // The owner may have unchecked capabilities: bind and relay exactly
      // what the signed delegation grants, in the request's manifest form.
      const approvedPermissions = approvedDevicePermissions(requestedPermissions, payload.permissions);
      const relay = await encryptDeviceRelay({ ...payload, permissions: approvedPermissions });
      let response: Response;
      try {
        response = await fetch(`${API_URL}/api/device-authorizations/${encodeURIComponent(deviceTransactionId)}/approve`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            relay,
            binding: {
              transactionId: deviceTransactionId,
              sessionDid: did,
              nodeOrigin: host,
              shareOrigin: deviceShareOrigin,
              permissions: approvedPermissions,
              delegationExpiresAt,
            },
          }),
        });
      } catch {
        throw new DeviceRelayDeliveryError(null, undefined);
      }
      if (!response.ok) {
        const body: unknown = await response.json().catch(() => null);
        if (isTermsRequired(response.status, body)) termsRefused();
        const fields = body && typeof body === 'object' ? body as { error?: unknown; code?: unknown } : null;
        const code = safeCode(fields?.error) ?? fields?.code;
        throw new DeviceRelayDeliveryError(response.status, code);
      }
      done = true;
      step = 'done';
      return;
    }

    if (approvedCallback) {
      callbackInFlight = true;
      try {
        const cbRes = await fetch(approvedCallback, {
          method: 'POST',
          // A redirect must not carry the delegation to another address.
          redirect: 'error',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (!cbRes.ok) {
          throw new Error('Failed to send delegation data to CLI');
        }

        done = true;
        step = 'done';
        return;
      } catch {
        callbackFailed = true;
      } finally {
        callbackInFlight = false;
      }
    }

    pasteCode = delegationPasteCode(payload);
    delegationPayload = Object.freeze(payload);
    await mintShortCode(payload);
    done = true;
    step = 'done';
  }

  async function signInWithPasskey() {
    signingIn = true;
    error = '';
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) {
        error = authErrorMessage(result.error, 'Passkey sign-in failed');
      } else {
        resumeSignIn();
      }
    } catch (e: any) {
      error = delegateErrorMessage(e);
    } finally {
      signingIn = false;
    }
  }

  async function activateWithHost(
    targetHost: string,
    delegationHeader: { Authorization: string }
  ): Promise<void> {
    try {
      const res = await fetch(`${targetHost}/delegate`, {
        method: 'POST',
        headers: delegationHeader,
      });
      if (!res.ok) {
        const errorText = await res.text().catch(() => res.statusText);
        console.warn(`[Delegate] Browser activation warning: ${errorText}`);
      }
    } catch (e) {
      console.warn(`[Delegate] Browser activation failed:`, e);
    }
  }

  // The end pages. `requesterName` is the app or command the review named.
  const requesterName = $derived(expiredRequesterName || requester?.displayName || '');
  // The full code was opened in place of the short one; its countdown no longer ends the page.
  let fullCodeOpen = $state(false);
  const codeExpired = $derived(!!shortCode && !!codeCountdown?.expired && !fullCodeOpen);
  const codeLine = $derived(
    callbackFailed ? fill(CODE.lineNotReached, { destination: codeDestinationWord() })
      : !shortCode ? CODE.lineNoShortCode
      : fill(CODE.line, { requester: requesterName }),
  );
  const codeSupport = $derived(!shortCode && shortCodeFailure ? supportLine(shortCodeFailure) : '');
  // Only what this page knows for certain: what was signed, with which key, and where it went.
  const receiptRows = $derived.by(() => {
    const words = DONE.receipt;
    const rows: ReceiptRow[] = [];
    const count = selectedActionKeys.length;
    if (count > 0) {
      const permissions = fill(count === 1 ? words.permissions.one : words.permissions.other, { n: count });
      const spaces = new Set(selectedActionKeys.map((key) => key.split('\0')[1]));
      const spaceId = typeof preparedData?.spaceId === 'string' ? preparedData.spaceId : '';
      const space = spaces.size === 1 && spaces.has(spaceId) ? spaceId.split(':').at(-1) : '';
      rows.push({ label: words.access, value: space ? fill(words.inSpace, { permissions, space }) : permissions });
    }
    if (delegationExpiresAt) rows.push({ label: words.ends, value: formatLocalAccessEnd(delegationExpiresAt) });
    if (selectedKey && keys.length > 1) {
      rows.push({ label: words.signedWith, value: `${selectedKey.label ?? `Key ${selectedKey.keyIndex}`} ${formatAddress(selectedKey.address)}` });
    }
    const sentTo = approvalRequestMode ? (requesterName ? fill(words.sentToValues.requester, { requester: requesterName }) : '')
      : deviceTransactionId ? words.sentToValues.terminalThatShowedCode
      : approvedCallback ? (isLoopbackHostname(new URL(approvedCallback).hostname)
        ? words.sentToValues.terminalThisDevice
        : fill(words.sentToValues.host, { host: new URL(approvedCallback).host }))
      : '';
    if (sentTo) rows.push({ label: words.sentTo, value: sentTo });
    return rows;
  });

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }

  const wanted = $derived(expectedAddress ? shortWallet(expectedAddress) : '');
  const stopValues: Record<string, string> = $derived({
    email: $session.data?.user.email ?? '',
    wanted,
    keyName: selectedKey ? stopKeyName(selectedKey) : '',
  });
  const linkStop = $derived.by(() => {
    if (preparedStorageError) return approvalStop('S2');
    if (preparedMode) return null;
    if (preparedTransport) {
      if ($page.url.search === '?transportVersion=2') return approvalStop('S3');
      const version = safeCode($page.url.searchParams.get('transportVersion'));
      return approvalStop('S12', { values: version ? { value: version } : {} });
    }
    if (incompleteLegacyRequest || relayInvalid) return approvalStop('S1', { legacy: incompleteLegacyRequest });
    if (permissionsParamError) return approvalStop('S11');
    if (callbackCheck?.ok === false) {
      return approvalStop('S9', { unsafeCallback: !callbackCheck.endpoint, values: { originPath: callbackCheck.endpoint ?? '' } });
    }
    if (hostCheck?.ok === false) return approvalStop('S10', { values: { host: hostCheck.hostname ?? '' } });
    if (requestSigner.kind === 'conflict') return approvalStop('S8', { values: { owners: requestSigner.owners.join(', ') } });
    return null;
  });
  const walletMissing = $derived(step === 'select-key' && preselectAttempted && !$session.isPending && $session.data &&
    expectedAddress && !keys.some((key) => key.address.toLowerCase() === expectedAddress));
  const stop = $derived(linkStop ?? failure?.view
    ?? (requestExpired ? approvalStop('S4', { requester: expiredRequesterName }) : null)
    ?? (walletMissing ? approvalStop('S17', { values: { ...stopValues, wanted: fill(STOP_PARTS.wantsWallet, { short: wanted }) } }) : null));

  async function retryStop() {
    const retry = failure?.retry;
    failure = null;
    await retry?.();
  }

  function resumeSignIn() {
    if (sessionEnded) {
      keys = [];
      keysLoaded = false;
      loading = true;
      preselectAttempted = false;
      goBack();
    }
    sessionEnded = false;
  }

  async function switchAccount() {
    const result = await authClient.signOut().catch(() => null);
    if (!result || result.error) return;
    keys = [];
    keysLoaded = false;
    loading = true;
    preselectAttempted = false;
    failure = null;
    goBack();
  }

  // What the page shows while it waits, and where it is in the three steps.
  type LoaderPhase = 'link' | 'session' | 'keys' | 'prepare';
  const loaderPhases: readonly LoaderPhase[] = approvalRequestMode || deviceTransactionId
    ? ['link', 'session', 'keys', 'prepare']
    : ['session', 'keys', 'prepare'];
  const showLoader = $derived(
    step !== 'done' && (deviceLinkPending || $session.isPending || (!!$session.data && !sessionEnded && (loading || preparing))),
  );
  const showSignIn = $derived(step !== 'done' && !showLoader && (!$session.data || sessionEnded));
  const loaderLit: LoaderPhase = $derived(
    deviceLinkPending || (approvalRequestMode && approvalRequestLoading) ? 'link'
      : !dispatchReady || $session.isPending ? 'session'
      : preparing ? 'prepare' : 'keys',
  );
  const slipAt = $derived(showLoader ? 0 : showSignIn ? 1 : step === 'done' ? (pasteCode ? 3 : 4) : 2);
  const slipLast = $derived(step === 'done' && pasteCode ? 'code' : deviceTransactionId ? 'terminal' : 'agent');
  const chipEmail = $derived(!showLoader && !showSignIn && step !== 'done' ? ($session.data?.user.email ?? null) : null);
</script>

{#if approvalRequestMode && !approvalRequestLoaded && approvalRequestLoading}
  <Slip at={0} center>
    <Loader phases={loaderPhases} lit="link" />
  </Slip>
{:else if !dispatchReady}
  <Slip at={0} center>
    <Loader phases={loaderPhases} lit={loaderLit} />
  </Slip>
{:else if stop}
  <Slip at={linkStop || !approvalRequestLoaded && approvalRequestMode ? 1 : 2} last={slipLast} stopped
    email={linkStop ? null : $session.data?.user.email} onSignOut={switchAccount}>
    {#key stop}
      <StopPage {stop}
        wanted={stop.id === 'S18' ? (failure?.wantedWallet ?? wanted) : stop.id === 'S17' ? wanted : ''}
        compared={stop.id === 'S17' ? compareWallets(keys) : stop.id === 'S18' && selectedKey ? compareWallets([selectedKey]) : []}
        retry={failure?.retry ? retryStop : undefined}
        {switchAccount}
        linkWallet={showLinkWallet}
        chooseKey={() => { failure = null; goBack(); }}
      />
    {/key}
  </Slip>
{:else if declined}
  <Slip at={3} last="agent" center>
    <DonePage outcome="declined" requester={requesterName} line={requester ? '' : UNVERIFIED_REQUESTER.declinedLine} />
  </Slip>
{:else if preparedMode}
  {#if ownerRevocationMode || ownerRevocationSelected}
    <OwnerRevocationHandoff encoded={preparedFragment} onClear={() => { ownerRevocationSelected = true; preparedFragment = ''; }} />
  {:else}
    <PreparedHandoff encoded={preparedFragment} onClear={() => { preparedFragment = ''; }} />
  {/if}
{:else}
<Slip at={slipAt} last={slipLast} stopped={codeExpired && delegationExpired} center={showLoader || step === 'done'} email={chipEmail} onSignOut={() => { void authClient.signOut(); }}>
      {#if step === 'done' && pasteCode}
        <CodeBox
          {shortCode}
          fullCode={pasteCode}
          eyebrow={CODE.eyebrow}
          line={codeLine}
          countdown={codeCountdown}
          announcement={codeAnnouncement}
          expired={codeExpired}
          approvalEnded={delegationExpired}
          onNewCode={getNewCode}
          newCodeBusy={codeRenewing}
          newCodeFailed={codeRenewFailed}
          bind:showFull={fullCodeOpen}
          support={codeSupport}
          spaceNote={spaceReadiness}
        />
      {:else if step === 'done'}
        <DonePage outcome="approved" requester={requesterName} returnTo={requester?.returnTo} line={requester ? '' : UNVERIFIED_REQUESTER.approvedLine} rows={receiptRows} spaceNote={spaceReadiness} />

      {:else if showLoader}
        <Loader phases={loaderPhases} lit={loaderLit} />

      {:else if showSignIn}
        <SignInCard
          emailHref={emailSignInHref}
          {registerHref}
          {error}
          {signingIn}
          signedOut={sessionEnded}
          onPasskey={signInWithPasskey}
          onBegin={() => { error = ''; }}
          onSignedIn={resumeSignIn}
        />

      {:else if step === 'link-wallet'}
        <!-- Link external wallet -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">Link External Wallet</h1>
          <p class="text-surface-500 text-sm mt-1">Connect a browser wallet to your account</p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-4">
          <p class="text-surface-500 text-sm">
            Select a wallet to link. You'll sign a verification message.
          </p>

          {#if wallets.length > 0}
            <div class="flex flex-col gap-2">
              {#each wallets as wallet}
                <button
                  class="flex items-center gap-3 p-3 bg-white border rounded-xl w-full text-left cursor-pointer transition-all hover:bg-surface-50"
                  class:border-surface-900={selectedWallet?.info.uuid === wallet.info.uuid}
                  class:bg-surface-50={selectedWallet?.info.uuid === wallet.info.uuid}
                  class:border-surface-200={selectedWallet?.info.uuid !== wallet.info.uuid}
                  onclick={() => selectWallet(wallet)}
                >
                  <img src={wallet.info.icon} alt={wallet.info.name} class="w-8 h-8 rounded" />
                  <span class="text-surface-900 font-medium text-sm">{wallet.info.name}</span>
                </button>
              {/each}
            </div>
          {:else}
            <div class="bg-amber-50 border border-amber-200 text-amber-700 px-4 py-3 rounded-xl text-sm">
              No wallet detected. Please install a browser wallet.
            </div>
          {/if}

          <div class="flex gap-3 mt-1">
            <Button variant="secondary" onclick={goBack} disabled={linking} class="flex-1 rounded-xl">
              Back
            </Button>
            <Button onclick={connectAndLink} disabled={linking || (wallets.length > 0 && !selectedWallet) || wallets.length === 0} class="flex-1 rounded-xl">
              {linking ? 'Linking...' : 'Connect Wallet'}
            </Button>
          </div>
        </div>

      {:else if step === 'choose-wallet' && selectedKey}
        <!-- Wallet selection for external key signing -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">Choose Wallet</h1>
          <p class="text-surface-500 text-sm mt-1">Select the wallet that holds <code class="font-mono text-xs">{formatAddress(selectedKey.address)}</code></p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-3">
          {#each wallets as wallet}
            <button
              class="flex items-center gap-3 p-3 bg-white border rounded-xl w-full text-left cursor-pointer transition-all hover:bg-surface-50"
              class:border-surface-900={signingWallet?.info.uuid === wallet.info.uuid}
              class:bg-surface-50={signingWallet?.info.uuid === wallet.info.uuid}
              class:border-surface-200={signingWallet?.info.uuid !== wallet.info.uuid}
              onclick={() => onSigningWalletSelect(wallet)}
            >
              <img src={wallet.info.icon} alt={wallet.info.name} class="w-8 h-8 rounded" />
              <span class="text-surface-900 font-medium text-sm">{wallet.info.name}</span>
              {#if signingWallet?.info.uuid === wallet.info.uuid}
                <svg class="w-5 h-5 text-surface-900 ml-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              {/if}
            </button>
          {/each}

          <div class="flex gap-3 mt-1">
            <Button variant="secondary" onclick={backToConsent} disabled={delegating} class="flex-1 rounded-xl">
              Back
            </Button>
            <Button onclick={confirmSigningWallet} disabled={delegating || !signingWallet} class="flex-1 rounded-xl">
              {#if delegating}
                Signing...
              {:else}
                Continue
              {/if}
            </Button>
          </div>
        </div>

      {:else if step === 'consent' && selectedKey}
        <!--
          CLI-only facts. With a review model they render in the shared
          SigningApproval context slot, which also owns the header, reason,
          signer line and the single error display (TC-659).
        -->
        {#snippet cliContext()}
        {#if selectedKey}
        {#if expectedAddress && !selectedMatchesExpected}
          <div class="w-full bg-amber-50 border border-amber-200 text-amber-800 px-4 py-3 rounded-xl text-sm" role="alert">
            <div class="font-medium mb-1">Wallet mismatch</div>
            <p class="leading-relaxed">
              This request is for wallet
              <code class="font-mono text-xs">{expectedAddressShort}</code>,
              but the key you picked is for
              <code class="font-mono text-xs">{formatAddress(selectedKey.address)}</code>.
              Choose a key for
              <code class="font-mono text-xs">{expectedAddressShort}</code>,
              or ask the app or command for a new request.
            </p>
            <button
              type="button"
              class="mt-2 text-xs text-amber-900 underline bg-transparent border-none cursor-pointer p-0"
              onclick={goBack}
            >
              Choose a different wallet
            </button>
          </div>
        {/if}

        {#if deviceTransactionId}
          <DeviceRequestNotice nodeOrigin={host} shareOrigin={deviceShareOrigin} expiry={expiryParam} />
        {:else}
          <DelegateLinkNotice {host} hostRecognized={!hostNeedsAcknowledgment} callback={approvedCallback} requesterRelay={approvalRequestMode} relayTo={requester?.displayName} expiresAt={delegationExpiresAt} showExpires={!(reviewModel?.immutable && reviewModel.protocol === 'tinycloud-siwe-recap')} bind:acknowledged={hostAcknowledged} />
        {/if}

        {#if selectedKey.keyType === 'EXTERNAL'}
          <div class="p-3 bg-blue-50 border border-blue-200 rounded-xl text-sm text-blue-700" role={renewalSigningMs !== null ? 'status' : undefined}>
            {#if renewalSigningMs !== null}
              Sign once more to turn on renewal for up to {formatDuration(renewalSigningMs)}
            {:else}
              Your browser wallet will prompt you to sign a message to authorize this delegation.
            {/if}
          </div>
        {/if}
        {#if ownFolderLine}
          <div role="note" class="p-3 border rounded-xl text-sm bg-surface-50 border-surface-200 text-surface-700">{ownFolderLine}</div>
        {/if}
        {#if spaceSetup}
          <div
            role="note"
            class={`p-3 border rounded-xl text-sm ${spaceSetup.plan === 'setup' ? 'bg-blue-50 border-blue-200 text-blue-700' : 'bg-surface-50 border-surface-200 text-surface-700'}`}
          >
            {spaceSetupNoticeText(spaceSetup)}
          </div>
        {/if}
        <DelegateSigningHint show={showLoopbackHint} />
        {/if}
        {/snippet}

        {#if reviewModel}
          <!--
            Shared authorization view: the same SigningApproval content as the
            widget popup and iframe. CliSigningAdapter owns the review
            selection/editing state, the delegate approve path, and the
            selection-change → prepare re-issue glue; toggling an action maps
            back to the server's actionKeys and re-issues /prepare so subset
            validation still runs on the API.
          -->
          <div bind:this={actionRow}>
            <CliSigningAdapter
              model={reviewModel}
              initialSelection={reviewSelection}
              context={cliContext}
              onEditingStateChange={(editing) => { reviewEditing = editing; }}
              showSigner={keys.length > 1}
              oneSecret={oneSecretWords}
              unverifiedRequester={approvalRequestMode && !requester ? UNVERIFIED_REQUESTER : null}
              transport={{
                approving: delegating || updatingPermissions,
                error,
                approveBlockedReason,
                approveBlockedByFailure,
                approveDelegate,
                goBack,
                ...(approvalRequestMode ? { decline: declineRequest, declining } : {}),
                updateSelection: (next) => {
                  reviewSelection = next;
                  const nextServerKeys = mapReviewSelectionToActionKeys(next);
                  if (nextServerKeys.length === 0) {
                    error = 'At least one permission is required.';
                    return;
                  }
                  return updatePermissions(nextServerKeys);
                },
                expiry: {
                  chosenMs: expiryChoiceMs,
                  onceDefault: true,
                  // The requester signed its longest time (signed request, device), or the link asked for exactly
                  // this much: a link without `expiryChangeable=true` is shorter-only.
                  bounded: approvalRequestMode || Boolean(deviceTransactionId) || !linkExpiryChangeable,
                  // The most the requester signed; the default shown can be shorter (its suggestion).
                  maxMs: expiryMaxMs,
                  shortenOnly: approvalRequestStartMs === null ? null : {
                    startMs: approvalRequestStartMs,
                    onceNote: APPROVAL_EXPIRY.onceStart,
                    limitNote: (ms) => fill(APPROVAL_EXPIRY.shortenLimit, { duration: formatDuration(ms) }),
                    lengthNote: (startMs, maxMs) => startMs < maxMs
                      ? fill(APPROVAL_EXPIRY.lengthen, { start: formatDuration(startMs), max: formatDuration(maxMs) })
                      : fill(APPROVAL_EXPIRY.lengthFixed, { max: formatDuration(maxMs) }),
                  },
                  onChange: changeApprovalExpiry,
                },
                ...(renewalMaxLeaseMs !== null ? {
                  renewal: {
                    leaseMs: renewalLeaseMs,
                    maxLeaseMs: renewalMaxLeaseMs,
                    onChange: (ms: number | null, windowMs?: number | null) => { void changeRenewal(ms, windowMs); },
                  },
                } : {}),
              }}
            />
          </div>
        {:else}
        <!-- Legacy raw-SIWE fallback when the request does not parse into a review model. -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">Authorize CLI Access</h1>
          <p class="text-surface-500 text-sm mt-1">Review what the CLI will be able to do</p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="mb-4 flex flex-col gap-4">
          {@render cliContext()}
        </div>

        <div class="flex flex-col gap-4">
          <div class="p-3 bg-surface-50 border border-surface-200 rounded-xl">
            <div class="text-xs text-surface-400 mb-1">Reason provided by CLI</div>
            <p class="text-sm text-surface-700 leading-relaxed">
              {requestReason || 'No additional context was provided by the CLI.'}
            </p>
          </div>

          <!-- Signing key -->
          <div class="p-3 bg-surface-50 border border-surface-200 rounded-xl">
            <div class="text-xs text-surface-400 mb-1">Signing key</div>
            <div class="flex justify-between items-center">
              <span class="font-medium text-sm text-surface-900 flex items-center gap-2">
                {selectedKey.label || `Key ${selectedKey.keyIndex}`}
                {#if selectedKey.keyType === 'EXTERNAL'}
                  <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-100 text-surface-500">(External)</span>
                {/if}
              </span>
              <code class="font-mono text-surface-500 text-xs">{formatAddress(selectedKey.address)}</code>
            </div>
          </div>

          {#if siweMessage}
            <div class="flex flex-col gap-3">
              {#if fallbackAccessMs !== null}
                <p class="text-sm text-surface-700" data-testid="approval-access-line">{accessLastsLine('app', fallbackAccessMs)}</p>
              {/if}
              <SiweMessage message={siweMessage} theme="light" hidePermissions={permissionOptions.length > 0} />
            </div>

            <!-- Actions (legacy raw-SIWE fallback) -->
            <div class="flex gap-3 mt-1" bind:this={actionRow}>
              <Button variant="secondary" onclick={goBack} disabled={delegating} class="flex-1 rounded-xl">
                Back
              </Button>
              <Button onclick={approveDelegate} disabled={delegating || updatingPermissions || approveBlockedByFailure || selectedActionKeys.length === 0 || !selectedMatchesExpected || (hostNeedsAcknowledgment && !hostAcknowledged)} class="flex-1 rounded-xl">
                {#if delegating}
                  Signing...
                {:else if updatingPermissions}
                  Updating...
                {:else if !selectedMatchesExpected}
                  Wallet mismatch
                {:else}
                  Approve
                {/if}
              </Button>
            </div>
          {/if}
        </div>
        {/if}

        {#if showScrollToApprove}
          <button
            type="button"
            data-testid="scroll-to-approve"
            aria-label="Scroll to approve"
            onclick={scrollToApprove}
            class="fixed bottom-[max(1rem,env(safe-area-inset-bottom))] right-[max(1rem,env(safe-area-inset-right))] z-40 inline-flex items-center gap-1.5 rounded-full bg-surface-900 px-3 py-2 text-xs font-medium text-white shadow-lg shadow-surface-900/15 transition-all hover:bg-surface-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-surface-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white"
          >
            <span>Scroll to approve</span>
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 5v14m0 0l-5-5m5 5l5-5" />
            </svg>
          </button>
        {/if}

      {:else}
        <!-- Key selection -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">TinyCloud access request</h1>
            <p class="text-surface-500 text-sm mt-1">Select a key to review the requested access</p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        {#if keys.length === 0}
          <div class="flex flex-col items-center justify-center text-center py-4">
            <p class="text-surface-500 text-sm mb-5">No keys found. Generate your first key to connect.</p>
            <Button onclick={generateAndSelect} class="w-full rounded-xl">
              Generate Key
            </Button>
            <Button variant="secondary" onclick={showLinkWallet} class="w-full rounded-xl mt-3">
              Link External Wallet
            </Button>
          </div>
        {:else}
          <KeyPicker
            {keys}
            {expectedAddress}
            bind:showOtherKeys
            onselect={onKeySelect}
            primaryHeading="Sign in with your primary key:"
            listHeading="Select a key to authorize:"
            otherKeysWarning="Each key is a separate account owner, with its own data and spaces. Signing in with a different key does not give the CLI the data in your primary key."
          >
            {#snippet actions()}
              <Button variant="secondary" onclick={showLinkWallet} class="rounded-xl">
                Link External Wallet
              </Button>
            {/snippet}
          </KeyPicker>
        {/if}
      {/if}
</Slip>
{/if}
