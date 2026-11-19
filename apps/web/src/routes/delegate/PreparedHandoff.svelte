<script lang="ts">
  import { onMount } from 'svelte';
  import { afterNavigate, replaceState } from '$app/navigation';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import KeyPicker from '$lib/components/keys/KeyPicker.svelte';
  import { buildStatements, parseEncryptionResource, parseCapabilityReview, defaultSelection, renderLiteral, renderSiweLiteral, splitStatementCode, type CapabilityGrant, type CapabilityReviewModel } from '@openkey/capability-review';
  import { validatePreviewSelection } from '$lib/preview-review';
  import { requestedActionIds } from '$lib/widget-selection';
  import { timeUntilExpiry } from '$lib/siwe-parser';
  import { ServerReplyError, hasSignResult, hasText } from '$lib/server-reply';
  import { fitsPreparedLinkBudget } from '$lib/prepared-link';
  import { remainingFromServerClock } from '$lib/delegate-code-countdown';
  import { ApprovalReplyError, compareWallets, readHandoffReply, shortWallet, stopForApprovalError, stopKeyName } from '$lib/approval-stop';
  import { OwnerMessageError } from '$lib/delegate-failure-text';
  import StopPage from '$lib/components/approval/stop-page.svelte';
  import { expiryAtCapped, requestedExpiryMs, siweExpiration } from '$lib/approval-expiry';
  import ApprovalExpiryControl from '$lib/components/signing/approval-expiry-control.svelte';
  import { formatLocalAccessEnd } from '$lib/access-end';
  import CodeBox from '$lib/components/approval/code-box.svelte';
  import DonePage, { type ReceiptRow } from '$lib/components/approval/done-page.svelte';
  import Loader from '$lib/components/approval/loader.svelte';
  import SignInCard from '$lib/components/approval/sign-in-card.svelte';
  import SignedInCard from '$lib/components/approval/signed-in-card.svelte';
  import Slip from '$lib/components/approval/slip.svelte';
  import { CODE, DONE, STOP_PARTS, STOPS, approvalStop, type StopView, codeDestinationWord, fill } from '@openkey/sdk/approval-copy';

  let { encoded, onClear }: { encoded: string; onClear: () => void } = $props();
  const session = authClient.useSession();
  const apiUrl = import.meta.env.VITE_API_URL || '';
  type Request = { protocolVersion: 1; siwe: string; jwk: Record<string, unknown>; host: string; sessionDid: string; keyId?: string; presentation?: Record<string, unknown> };
  type Claim = { transportVersion: 2; request: Request; delivery: { handoffId: string; state: string; cancelSecret: string; callback?: string } };
  type Handoff = { request: Request; delivery: { callback?: string }; expiresAt: string };
  type Result = { protocolVersion: 1; address: string; signature: string; signedMessage: string; selectedActionKeys: string[]; permissions: unknown[] };
  type KeyChoice = { key: EthereumKey; review: CapabilityReviewModel };
  const pendingKey = 'openkey.delegate.tv2.pending';
  function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }
  function ownKeyFolder(grant: CapabilityGrant): string | null {
    const parsed = parseEncryptionResource(grant.space);
    return parsed?.kind === 'prefix' && parsed.network === 'default' && grant.ownedBySelf
      ? parsed.keyPath
      : null;
  }
  function isClaim(value: unknown): value is Claim {
    if (!isRecord(value) || !isRecord(value.request) || !isRecord(value.delivery)) return false;
    const request = value.request;
    const delivery = value.delivery;
    const opaque = (item: unknown) => typeof item === 'string' && /^[A-Za-z0-9_-]{43}$/.test(item);
    return value.transportVersion === 2 && request.protocolVersion === 1 &&
      typeof request.siwe === 'string' && typeof request.host === 'string' &&
      typeof request.sessionDid === 'string' && isRecord(request.jwk) &&
      (request.keyId === undefined || typeof request.keyId === 'string') &&
      (request.presentation === undefined || isRecord(request.presentation)) &&
      opaque(delivery.handoffId) && opaque(delivery.state) && opaque(delivery.cancelSecret) &&
      (delivery.callback === undefined || (typeof delivery.callback === 'string' && validCallback(delivery.callback)));
  }
  let handoff = $state<Handoff | null>(null);
  let pending = $state<Claim | null>(null);
  let ticket = $state('');
  let initialized = $state(false);
  let pendingTimeout: ReturnType<typeof setTimeout> | undefined;
  let handoffTimeout: ReturnType<typeof setTimeout> | undefined;
  // When the CLI's prepared request stops being claimable: its issued-at plus five minutes.
  let preparedExpiryMs = NaN;
  // The `Date` header of the latest server reply: the server's clock, read at receipt.
  let serverDate: string | null = null;
  let routerReady = false;
  let markerNeeded = false;
  afterNavigate(() => {
    routerReady = true;
    if (markerNeeded) {
      markerNeeded = false;
      replaceState(`${location.pathname}?transportVersion=2`, {});
    }
  });
  const signedExpiry = $derived.by(() => {
    const value = (phase === 'preview' ? siweExpiration(previewMessage) : null) ?? siweExpiration(handoff?.request.siwe ?? '');
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : { local: date.toLocaleString(), relative: timeUntilExpiry(value).text };
  });
  // The exact end the open fold shows after the choice: what the preview signs, else what a pick would give
  // from now, else what the CLI asked for.
  const foldEndsAt = $derived.by(() => {
    if (phase === 'preview') return siweExpiration(previewMessage) ?? null;
    if (expiryChoiceMs !== null) return new Date(Date.now() + expiryChoiceMs).toISOString();
    return siweExpiration(handoff?.request.siwe ?? '') ?? null;
  });
  let key = $state<EthereumKey | null>(null);
  let keyChoices = $state<KeyChoice[]>([]);
  // How many keys the account has: the receipt names the signing key only when there was a choice.
  let accountKeyCount = $state(0);
  let model = $state<CapabilityReviewModel | null>(null);
  // TC-2272: how long from approval the user chose; null keeps the app's own expiry.
  let expiryChoiceMs = $state<number | null>(null);
  const expiryRequestedMs = $derived(requestedExpiryMs(model?.immutable?.issuedAt, model?.immutable?.expirationTime));
  // A choice after the preview is sealed would not be in what gets signed.
  const expiryEditable = $derived.by(() => phase === 'review' && !busy && !submitted);
  let selected = $state(new Set<string>());
  let contextToken = $state('');
  let previewToken = $state('');
  let previewMessage = $state('');
  let previewActions = $state<string[]>([]);
  let code = $state('');
  let callbackFailed = $state(false);
  let delivered = $state(false);
  let error = $state('');
  let stop = $state<StopView | null>(null);
  let retry = $state<(() => Promise<void>) | undefined>();
  let signedOut = $state(false);
  let retryClaimAfterSignIn = false;
  let wanted = $state('');
  let compared = $state<ReturnType<typeof compareWallets>>([]);
  const expiredStop = () => approvalStop('S4', { preparedSignIn: true });

  function report(cause: unknown, action?: () => Promise<void>, claiming = false) {
    const view = stopForApprovalError(cause, {
      phase: claiming ? 'claim' : 'approve', preparedSignIn: true,
      permissionsEditable: phase === 'review', expiryChangeable: phase === 'review',
      values: { email: $session.data?.user.email ?? '', keyName: key ? stopKeyName(key) : '' },
    });
    if (cause instanceof ServerReplyError) console.error(cause.message);
    if (cause instanceof OwnerMessageError) {
      error = cause.message;
    } else if (view.placement === 'sign-in') {
      signedOut = true;
      retryClaimAfterSignIn = claiming;
    } else if (view.placement === 'inline' && (!claiming || !!handoff)) {
      error = [view.title, view.body].filter(Boolean).join('. ');
    } else {
      stop = view.placement === 'inline' ? approvalStop('S26', { status: 409, code: 'handoff_signing' }) : view;
      retry = action;
    }
  }

  async function retryStop() {
    const action = retry;
    stop = null;
    retry = undefined;
    await action?.();
  }

  async function switchAccount() {
    const result = await authClient.signOut().catch(() => null);
    if (!result || result.error) return;
    stop = null;
    loaded = false;
  }

  function resumeSignIn() {
    if (retryClaimAfterSignIn) loaded = false;
    retryClaimAfterSignIn = false;
    signedOut = false;
    loginRequired = false;
  }
  let busy = $state(false);
  let loginRequired = $state(false);
  let cancelled = $state(false);
  let loaded = $state(false);
  let submitted = $state(false);
  let signingIn = $state(false);
  let phase = $state<'review' | 'preview' | 'done'>('review');
  function validCallback(callback: string): boolean {
    if (!/^http:\/\/(?:127\.0\.0\.1|\[::1\]):[0-9]{4,5}\/callback\/[A-Za-z0-9_-]{22}$/.test(callback)) return false;
    const port = Number(new URL(callback).port);
    return port >= 1024 && port <= 65535;
  }
  function clearPending(): void {
    if (pendingTimeout !== undefined) clearTimeout(pendingTimeout);
    try { sessionStorage.removeItem(pendingKey); } catch { /* No persistent fallback for approval material. */ }
    onClear();
    if (routerReady) replaceState(`${location.pathname}?transportVersion=2`, {});
    else markerNeeded = true;
  }

  onMount(() => {
    try {
      if (document.documentElement.dataset.preparedHandoffStorageError === '1') {
        stop = approvalStop('S2');
        return;
      }
      if (!encoded.startsWith('#tv2=')) throw new Error('Unsupported prepared sign-in transport. Restart the CLI command.');
      if (!fitsPreparedLinkBudget(location, encoded)) {
        throw new Error('Prepared sign-in link is too large. Restart the CLI command.');
      }
      let value: unknown;
      try {
        const binary = atob(encoded.slice(5).replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
        value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      } catch {
        throw new Error('Invalid prepared sign-in request. Restart the CLI command.');
      }
      if (!isClaim(value)) throw new Error('Invalid prepared sign-in request. Restart the CLI command.');
      // Freshness is decided on the server's clock once the first reply arrives (see `load`), never the device clock.
      const issuedAt = /^Issued At:[ \t]*(.+)$/m.exec(value.request.siwe)?.[1]?.trim();
      preparedExpiryMs = Date.parse(issuedAt ?? '') + 300_000;
      if (!Number.isFinite(preparedExpiryMs)) {
        clearPending();
        stop = expiredStop();
        return;
      }
      pending = value;
      // Bounds how long the unclaimed request stays in this tab: five minutes from mount on a plain timer.
      pendingTimeout = setTimeout(() => {
        pending = null;
        clearPending();
        stop = expiredStop();
        retry = undefined;
      }, 300_000);
    } catch (cause) {
      clearPending();
      stop = approvalStop(encoded ? 'S1' : 'S3');
    } finally {
      initialized = true;
    }
    return () => {
      if (pendingTimeout !== undefined) clearTimeout(pendingTimeout);
      if (handoffTimeout !== undefined) clearTimeout(handoffTimeout);
    };
  });

  function cancelPending(): void {
    pending = null;
    clearPending();
    cancelled = true;
  }

  function expireHandoff(): void {
    // A signing in flight, or one that finished, decides its own outcome.
    if (!handoff || submitted || phase === 'done') return;
    handoff = null;
    contextToken = '';
    previewToken = '';
    previewMessage = '';
    phase = 'review';
    stop = expiredStop();
    retry = undefined;
  }

  // `needs` names the fields a successful answer must carry as text. With it, a
  // 2xx answer that is empty, not JSON, or without those fields is an unreadable
  // reply and nothing is approved.
  async function post(path: string, body: unknown, needs?: string[], valid?: (reply: Record<string, unknown>) => boolean): Promise<Record<string, unknown>> {
    const response = await fetch(`${apiUrl}/api/delegate/${path}`, {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    serverDate = response.headers?.get('date') ?? null;
    return readHandoffReply(response, (reply) => (!needs || hasText(reply, ...needs)) && (!valid || valid(reply)));
  }

  function selectedIds(): string[] {
    return requestedActionIds(model, selected);
  }
  function chooseKey(choice: KeyChoice) {
    if (contextToken) return;
    key = choice.key;
    model = choice.review;
    selected = defaultSelection(choice.review);
  }

  async function load() {
    const input = pending;
    if (!input) return;
    busy = true;
    try {
      const availability = await fetch(`${apiUrl}/api/delegate/handoffs/available`, {
        credentials: 'include', cache: 'no-store',
      });
      if (!availability.ok) throw new ApprovalReplyError(availability.status);
      const feature: unknown = await availability.json().catch(() => null);
      if (!isRecord(feature)) throw new ServerReplyError(availability.status);
      if (feature.transportVersion !== 2) {
        stop = approvalStop('S12');
        return;
      }
      // The availability reply carries the first server `Date`: the request is fresh or expired on that clock.
      const availableDate = availability.headers?.get('date') ?? null;
      const serverNowMs = availableDate === null ? NaN : Date.parse(availableDate);
      if (Number.isFinite(serverNowMs)) {
        const remaining = preparedExpiryMs - serverNowMs;
        if (remaining <= 0) {
          pending = null;
          clearPending();
          stop = expiredStop();
          return;
        }
      }
      if (pending !== input) return;
      const match = /(?:^|\n)([^\n]+) wants you to sign in with your Ethereum account:\n(0x[0-9a-fA-F]{40})(?:\n|$)/.exec(input.request.siwe);
      const chain = /^Chain ID: ([1-9][0-9]*)$/m.exec(input.request.siwe);
      if (!match || !chain) {
        stop = approvalStop('S11');
        return;
      }
      const { keys } = await api.listKeys();
      accountKeyCount = keys.length;
      const walletKeys = keys.filter(item => item.address.toLowerCase() === match[2]!.toLowerCase());
      if (!walletKeys.length) {
        wanted = shortWallet(match[2]!);
        compared = compareWallets(keys);
        stop = approvalStop('S17', { values: {
          email: $session.data?.user.email ?? '', wanted: fill(STOP_PARTS.wantsWallet, { short: wanted }),
        } });
        return;
      }
      const candidates = walletKeys.filter(item => !input.request.keyId || item.id === input.request.keyId);
      if (!candidates.length) {
        pending = null;
        clearPending();
        stop = approvalStop('S25', { fixedKey: true });
        return;
      }
      if (pending !== input) return;
      const claimed = await post('handoffs/claim', input, ['ticket', 'expiresAt'], (reply) =>
        reply.transportVersion === 2 && reply.ticket === input.delivery.handoffId &&
        typeof reply.expiresAt === 'string' && Number.isFinite(Date.parse(reply.expiresAt)),
      );
      if (pending !== input) return;
      ticket = input.delivery.handoffId;
      // Counted on the server's clock: the claim's expiry minus the server's own Date header, never the device clock.
      const remainingMs = remainingFromServerClock(claimed.expiresAt as string, serverDate);
      if (remainingMs !== null) handoffTimeout = setTimeout(expireHandoff, remainingMs);
      const resolved: Handoff = {
        request: input.request,
        delivery: input.delivery.callback ? { callback: input.delivery.callback } : {},
        expiresAt: claimed.expiresAt as string,
      };
      pending = null;
      clearPending();
      const choices = candidates.map(candidate => {
        const review = parseCapabilityReview({
          message: resolved.request.siwe,
          signer: { label: candidate.label ?? `Key ${candidate.keyIndex}`, address: candidate.address, chainId: Number(chain[1]), provenance: candidate.keyType === 'EXTERNAL' ? 'external' : 'managed' },
          editable: true,
          metadataTrust: { status: 'unsigned', reason: 'No verified manifest supplied' },
          reason: { text: '', source: 'none' },
          requester: { displayName: match[1]!, verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false },
        });
        if (review.protocol !== 'tinycloud-siwe-recap') throw new Error('The prepared SIWE contains no valid capability request.');
        return { key: candidate, review };
      });
      keyChoices = choices;
      handoff = resolved;
      if (choices.length === 1) chooseKey(choices[0]!);
    } catch (cause) {
      if (pending !== input && stop?.id === 'S4') return;
      report(cause, pending === input ? load : undefined, true);
      if (stop && !stop.buttons.includes('try-again')) {
        pending = null;
        clearPending();
      }
    } finally { busy = false; }
  }

  $effect(() => {
    if (!initialized || !pending || loaded || signedOut || stop || $session.isPending) return;
    if (!$session.data) {
      // A focus-triggered session refresh can finish before the email auth
      // redirect. Do not consume the one-use claim in the page being left.
      loginRequired = true;
    } else if (!loginRequired) {
      loaded = true;
      void load();
    }
  });

  function toggle(id: string) {
    if (phase !== 'review') return;
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    selected = next;
  }

  async function preview() {
    if (!handoff || !key || !model || busy || submitted) return;
    busy = true;
    error = '';
    try {
      const request = handoff.request;
      if (!contextToken) {
        const prepared = await post('authorize-sign-prepare', {
          ticket, keyId: key.id, siwe: request.siwe, jwk: request.jwk, host: request.host,
          ...(request.presentation ? { presentation: request.presentation } : {}),
        }, ['authorizationContextToken']);
        if (typeof prepared.authorizationContextToken !== 'string') throw new Error('Missing bound authorization context.');
        contextToken = prepared.authorizationContextToken;
      }
      const actions = selectedIds();
      if (!actions.length) throw new Error('Select at least one ability.');
      const candidate = await post('authorize-sign-preview', { ticket, authorizationContextToken: contextToken, selectedActionIds: actions, ...(expiryChoiceMs === null ? {} : { expirationTime: expiryAtCapped(expiryChoiceMs, siweExpiration(handoff.request.siwe)) }) }, ['signedMessage', 'previewApprovalToken']);
      if (typeof candidate.previewApprovalToken !== 'string' || typeof candidate.signedMessage !== 'string') throw new Error('Missing sealed signing preview.');
      validatePreviewSelection(candidate, actions);
      previewToken = candidate.previewApprovalToken;
      previewMessage = candidate.signedMessage;
      previewActions = actions;
      phase = 'preview';
    } catch (cause) {
      report(cause, preview);
    }
    finally { busy = false; }
  }

  function encode(value: unknown): string {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function approve() {
    if (!handoff || !key || !previewToken || !contextToken || busy || submitted) return;
    busy = true;
    error = '';
    try {
      const body: Record<string, unknown> = { ticket, authorizationContextToken: contextToken, previewApprovalToken: previewToken, selectedActionIds: previewActions, protocolVersion: 1 };
      if (key.keyType === 'EXTERNAL') {
        const provider = (window as Window & { ethereum?: { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> } }).ethereum;
        if (!provider) throw new OwnerMessageError(STOPS.S32.lines.noWallet);
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        if (!Array.isArray(accounts) || !accounts.every(value => typeof value === 'string')) throw new Error('Wallet returned invalid accounts.');
        const account = accounts.find(value => value.toLowerCase() === key!.address.toLowerCase());
        if (!account) throw new OwnerMessageError(fill(STOPS.S32.lines.walletLacks, { short: shortWallet(key.address) }));
        const signature = await provider.request({ method: 'personal_sign', params: [previewMessage, account] });
        if (typeof signature !== 'string') throw new Error('Wallet returned an invalid signature.');
        body.externalSignature = signature;
      }
      submitted = true;
      let signed: Record<string, unknown>;
      try {
        signed = await post('authorize-sign', body, ['signature', 'address', 'signedMessage', 'deliveryState'], hasSignResult);
      } catch (cause) {
        // A refusal or failure comes back with no signature. The server releases the handoff when the key failed to
        // sign, so the owner may approve again or cancel; if the key signed but the tokens could not be spent it stays
        // signing until it expires and a retry is refused. Only a 2xx reply that cannot be read may have been signed.
        if (!(cause instanceof ServerReplyError)) submitted = false;
        throw cause;
      }
      if (signed.protocolVersion !== 1 || typeof signed.signature !== 'string' || typeof signed.address !== 'string' ||
          !Array.isArray(signed.selectedActionKeys) || !signed.selectedActionKeys.every(value => typeof value === 'string') ||
          !Array.isArray(signed.permissions) ||
          signed.signedMessage !== previewMessage || signed.selectedKeyId !== key.id || typeof signed.deliveryState !== 'string') {
        throw new Error('Signed response differs from the reviewed request. Restart the CLI command.');
      }
      const result: Result = {
        protocolVersion: 1, address: signed.address, signature: signed.signature,
        signedMessage: previewMessage, selectedActionKeys: signed.selectedActionKeys, permissions: signed.permissions,
      };
      const envelope = { transportVersion: 2, state: signed.deliveryState, selectedKeyId: signed.selectedKeyId, result };
      code = encode(envelope);
      phase = 'done';
      if (handoff.delivery.callback) {
        try {
          const response = await fetch(handoff.delivery.callback, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) });
          const receipt: unknown = await response.json().catch(() => null);
          if (!response.ok || !receipt || typeof receipt !== 'object' || !('accepted' in receipt) || receipt.accepted !== true) {
            throw new Error('CLI did not accept the response.');
          }
          delivered = true;
        } catch { callbackFailed = true; }
      }
    } catch (cause) {
      if (cause && typeof cause === 'object' && 'code' in cause && cause.code === 4001) error = STOPS.S32.lines.walletDeclined;
      else report(cause, submitted ? undefined : approve);
    } finally { busy = false; }
  }

  async function cancel() {
    if (!handoff || busy || submitted) return;
    busy = true;
    error = '';
    try {
      const response = await post('handoffs/cancel-claimed', { ticket });
      if (response.cancelled !== true) throw new Error('The handoff was not cancelled.');
      handoff = null;
      contextToken = '';
      previewToken = '';
      previewMessage = '';
      phase = 'review';
      cancelled = true;
    } catch (cause) {
      report(cause, cancel);
    } finally { busy = false; }
  }

  async function signIn() {
    signingIn = true;
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) error = authErrorMessage(result.error, 'Passkey sign-in failed');
      else resumeSignIn();
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Passkey sign-in failed'; }
    finally { signingIn = false; }
  }
  // What the page shows: a loader, the sign-in card, the signed-in card, or the request itself.
  const ended = $derived(initialized && (cancelled || (!!error && !handoff && !pending)));
  const loaderOn = $derived(
    !initialized ||
    (!ended && !signedOut && ($session.isPending || (!!$session.data && !loginRequired && !handoff && !code && (busy || pending !== null)))),
  );
  const loaderLit = $derived(!initialized || $session.isPending ? 'session' : 'request');
  const cardOn = $derived(initialized && !ended && !$session.isPending && (!$session.data || signedOut));
  const signedInOn = $derived(initialized && !ended && !$session.isPending && !!$session.data && loginRequired && !signedOut);
  const slipAt = $derived(loaderOn ? 0 : cardOn || signedInOn ? 1 : cancelled ? 3 : handoff && phase === 'done' ? (delivered ? 4 : 3) : 2);
  const slipLast = $derived(handoff && phase === 'done' && !delivered && !cancelled ? 'code' : 'terminal');
  // The end pages: who asked, and what the receipt can say for certain.
  const requester = $derived(model?.requester.displayName ?? '');
  const receiptRows = $derived.by(() => {
    const rows: ReceiptRow[] = [];
    const ends = siweExpiration(previewMessage);
    if (ends) rows.push({ label: DONE.receipt.ends, value: formatLocalAccessEnd(ends) });
    if (key && accountKeyCount > 1) {
      rows.push({ label: DONE.receipt.signedWith, value: `${key.label ?? `Key ${key.keyIndex}`} ${key.address.slice(0, 6)}...${key.address.slice(-4)}` });
    }
    return rows;
  });
</script>

<Slip at={stop ? 2 : slipAt} last={slipLast} stopped={!!stop} email={stop && $session.data?.user.email}
  center={!stop && (loaderOn || cancelled || (!!handoff && phase === 'done'))}>
  {#if stop}
    {#key stop}
      <StopPage {stop} wanted={stop.id === 'S17' ? wanted : ''} compared={stop.id === 'S17' ? compared : []}
        retry={retry ? retryStop : undefined} {switchAccount}
        chooseKey={keyChoices.length > 1 ? () => { stop = null; key = null; phase = 'review'; } : undefined} />
    {/key}
  {:else if loaderOn}
    <Loader phases={['session', 'request']} lit={loaderLit} />
  {:else if cardOn}
    <SignInCard
      emailHref={`/auth/login?redirect=${encodeURIComponent('/delegate?transportVersion=2')}`}
      registerHref={`/auth/register?returnTo=${encodeURIComponent('/delegate?transportVersion=2')}`}
      {error}
      {signingIn}
      {signedOut}
      onPasskey={signIn}
      onSignedIn={() => { if (signedOut) resumeSignIn(); }}
      onBegin={() => { error = ''; }}
      onCancel={cancelPending}
    />
  {:else if signedInOn}
    <SignedInCard onReview={() => { loginRequired = false; }} onCancel={cancelPending} />
  {:else if cancelled}
    <DonePage outcome="cancelled" />
  {:else if handoff && phase === 'done' && delivered}
    <DonePage outcome="signedIn" {requester} rows={receiptRows} />
  {:else if handoff && phase === 'done'}
    <CodeBox
      fullCode={code}
      eyebrow={CODE.eyebrow}
      line={callbackFailed ? fill(CODE.lineNotReached, { destination: codeDestinationWord() }) : fill(CODE.line, { requester })}
    />
  {:else}
    <div class="space-y-5">
    <header><h1 class="text-xl font-semibold text-surface-900">Prepared CLI sign-in</h1></header>
    {#if error}<p role="alert" class="rounded-lg bg-red-50 p-3 text-red-800">{error}</p>{/if}
    {#if error && !handoff && !pending}
      <p>Start a new CLI sign-in to review a new request.</p>
    {:else if handoff && keyChoices.length > 1 && !key}
      <p class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">Only approve if you started this sign-in yourself on your own computer.</p>
      <dl class="space-y-2 text-sm break-all">
        <div><dt class="font-semibold">Session DID (display only)</dt><dd>{handoff.request.sessionDid}</dd></div>
        <div><dt class="font-semibold">Node host</dt><dd>{handoff.request.host}</dd></div>
        <div><dt class="font-semibold">Approval request expires</dt><dd>{new Date(handoff.expiresAt).toLocaleString()}</dd></div>
      </dl>
      {#if signedExpiry}
        <div class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm"><dt class="font-semibold">Access granted until</dt><dd>{signedExpiry.local} ({signedExpiry.relative})</dd></div>
      {:else}
        <p role="alert" class="rounded-lg border border-red-300 bg-red-50 p-3 text-sm">No expiry set</p>
      {/if}
      <h2 class="font-semibold">Choose an OpenKey signing key</h2>
      <KeyPicker
        keys={keyChoices.map((choice) => choice.key)}
        expectedAddress={keyChoices[0].key.address.toLowerCase()}
        onselect={(selected) => {
          const choice = keyChoices.find((choice) => choice.key.id === selected.id);
          if (choice) chooseKey(choice);
        }}
        listHeading="Choose which key signs this:"
        primaryHeading="Sign with your primary key:"
      />
      <h2 class="font-semibold">Requested abilities and spaces</h2>
      {#each keyChoices[0].review.permissions as grant}
        <div class="rounded-lg border p-3 text-sm">
          {#if ownKeyFolder(grant)}<p class="font-semibold">Your own encryption keys in <code>{ownKeyFolder(grant)}</code></p>{/if}
          {#each buildStatements(grant) as statement}<p>{#if statement.codeSpans}{#each splitStatementCode(statement.primaryText) as part}{#if part.code}<code class="font-mono">{part.text}</code>{:else}{part.text}{/if}{/each}{:else}{statement.primaryText}{/if}</p>{/each}
          <details><summary>Full grant</summary><pre class="whitespace-pre-wrap break-all">{renderLiteral(`${grant.service} · ${grant.space} · ${grant.path}: ${grant.actions.map(action => action.ability).join(', ')}`)}</pre></details>
        </div>
      {/each}
      <details><summary>Original SIWE message</summary>
        <pre class="whitespace-pre overflow-x-auto max-w-full min-w-0 rounded-lg bg-surface-50 p-3 text-xs">{renderSiweLiteral(handoff.request.siwe)}</pre>
      </details>
      <button disabled={busy || submitted} onclick={cancel}>Cancel</button>
    {:else if handoff && model && key}
      <p class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">Only approve if you started this sign-in yourself on your own computer.</p>
      <dl class="space-y-2 text-sm break-all">
        <div><dt class="font-semibold">Session DID (display only)</dt><dd>{handoff.request.sessionDid}</dd></div>
        <div><dt class="font-semibold">Node host</dt><dd>{handoff.request.host}</dd></div>
        <div><dt class="font-semibold">Approval request expires</dt><dd>{new Date(handoff.expiresAt).toLocaleString()}</dd></div>
        <div data-testid="prepared-signing-key">
          <dt class="font-semibold">Signing key</dt>
          <dd class="flex flex-wrap items-center gap-2">
            <span class="font-medium" title={key.address}>{key.label || `Key ending ${key.address.slice(-4)}`}</span>
          </dd>
        </div>
      </dl>
      {#if !signedExpiry}
        <p role="alert" class="rounded-lg border border-red-300 bg-red-50 p-3 text-sm">No expiry set</p>
      {:else if expiryRequestedMs === null}
        <!-- The expiry line below can't show a length, so the end date is shown here instead. -->
        <div class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm"><dt class="font-semibold">Access granted until</dt><dd>{signedExpiry.local} ({signedExpiry.relative})</dd></div>
      {/if}
      <ApprovalExpiryControl
        requestedMs={expiryRequestedMs}
        chosenMs={expiryChoiceMs}
        maxMs={expiryRequestedMs}
        disabled={!expiryEditable}
        onChange={(ms) => { if (expiryEditable) expiryChoiceMs = ms; }}
        endsAt={foldEndsAt}
      />
      <h2 class="font-semibold">Requested abilities and spaces</h2>
      {#each model.permissions as grant}
        <div class="rounded-lg border p-3 text-sm">
          {#if ownKeyFolder(grant)}<p class="font-semibold">Your own encryption keys in <code>{ownKeyFolder(grant)}</code></p>{/if}
          {#each buildStatements(grant) as statement}<p>{#if statement.codeSpans}{#each splitStatementCode(statement.primaryText) as part}{#if part.code}<code class="font-mono">{part.text}</code>{:else}{part.text}{/if}{/each}{:else}{statement.primaryText}{/if}</p>{/each}
          {#each grant.actions as action}
            <label class="flex gap-2 py-1"><input type="checkbox" checked={selected.has(action.id)} disabled={phase !== 'review' || !action.editable} onchange={() => toggle(action.id)} /><span class="break-all">{renderLiteral(action.ability, 120)}</span></label>
          {/each}
          <details><summary>Full grant</summary><pre class="whitespace-pre-wrap break-all">{renderLiteral(`${grant.service} · ${grant.space} · ${grant.path}: ${grant.actions.map(action => action.ability).join(', ')}`)}</pre></details>
        </div>
      {/each}
      <details><summary>Original SIWE message</summary>
        <pre class="whitespace-pre overflow-x-auto max-w-full min-w-0 rounded-lg bg-surface-50 p-3 text-xs">{renderSiweLiteral(handoff.request.siwe)}</pre>
      </details>
      {#if phase === 'preview'}
        <details>
          <summary class="font-semibold">Exact candidate signedMessage</summary>
          <pre class="whitespace-pre overflow-x-auto max-w-full min-w-0 rounded-lg bg-surface-50 p-3 text-xs">{renderSiweLiteral(previewMessage)}</pre>
        </details>
        <button onclick={() => { phase = 'review'; previewToken = ''; }}>Change abilities</button>
        <button disabled={busy || submitted} onclick={approve}>Approve</button>
      {:else}
        <button disabled={busy || submitted || selectedIds().length === 0} onclick={preview}>Preview signing message</button>
      {/if}
      <button disabled={busy || submitted} onclick={cancel}>Cancel</button>
    {/if}
    </div>
  {/if}
</Slip>
