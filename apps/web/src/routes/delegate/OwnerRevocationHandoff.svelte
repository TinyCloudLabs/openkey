<script lang="ts">
  import { onMount } from 'svelte';
  import { afterNavigate, replaceState } from '$app/navigation';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { formatLocalAccessEnd } from '$lib/access-end';
  import { getSessionToken } from '$lib/embed-passkey';
  import { ownerRevocationCopy as text } from '$lib/owner-revocation-copy';
  import { deliverOwnerRevocation } from '$lib/owner-revocation-response';
  import { fitsPreparedLinkBudget } from '$lib/prepared-link';
  import { ApprovalReplyError, compareWallets, readHandoffReply, releasedSigningCancellation, shortWallet, stopForApprovalError, stopKeyName } from '$lib/approval-stop';
  import { OwnerMessageError } from '$lib/delegate-failure-text';
  import { ServerReplyError } from '$lib/server-reply';
  import StopPage from '$lib/components/approval/stop-page.svelte';
  import { ownerRevocationAddress, parseOwnerRevocationRequest, renderSiweLiteral, type OwnerRevocationRequest } from '@openkey/capability-review';
  import Button from '$lib/components/ui/button.svelte';
  import CodeBox from '$lib/components/approval/code-box.svelte';
  import DonePage from '$lib/components/approval/done-page.svelte';
  import Icon from '$lib/components/approval/icon.svelte';
  import Loader from '$lib/components/approval/loader.svelte';
  import SignInCard from '$lib/components/approval/sign-in-card.svelte';
  import SignedInCard from '$lib/components/approval/signed-in-card.svelte';
  import Slip from '$lib/components/approval/slip.svelte';
  import { CODE, DONE, REVOKE_REVIEW, STOP_PARTS, STOPS, approvalStop, type StopView, codeDestinationWord, fill } from '@openkey/sdk/approval-copy';

  let { encoded, onClear }: { encoded: string; onClear: () => void } = $props();
  const session = authClient.useSession();
  const apiUrl = import.meta.env.VITE_API_URL || '';
  type Delivery = { handoffId: string; state: string; cancelSecret: string; callback?: string };
  type Claim = { transportVersion: 2; request: OwnerRevocationRequest; delivery: Delivery };
  let pending = $state<Claim | null>(null);
  let request = $state<OwnerRevocationRequest | null>(null);
  let delivery = $state<Delivery | null>(null);
  let ticket = $state('');
  let keys = $state<EthereumKey[]>([]);
  let key = $state<EthereumKey | null>(null);
  let contextToken = $state('');
  let siwe = $state('');
  let code = $state('');
  let delivered = $state(false);
  let error = $state('');
  let stop = $state<StopView | null>(null);
  let retry = $state<(() => Promise<void>) | undefined>();
  let cancelReleasedSigning = $state<(() => Promise<void>) | undefined>();
  let signedOut = $state(false);
  let retryClaimAfterSignIn = false;
  let wanted = $state('');
  let compared = $state<ReturnType<typeof compareWallets>>([]);

  function report(cause: unknown, action?: () => Promise<void>, claiming = false) {
    cancelReleasedSigning = undefined;
    const view = stopForApprovalError(cause, {
      phase: claiming ? 'claim' : 'approve',
      values: { email: $session.data?.user.email ?? '', keyName: key ? stopKeyName(key) : '' },
    });
    if (cause instanceof OwnerMessageError) {
      error = cause.message;
    } else if (view.placement === 'sign-in') {
      signedOut = true;
      retryClaimAfterSignIn = claiming;
    } else if (view.placement === 'inline' && (!claiming || !!request)) {
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

  function leaveRefusedSigning() {
    void cancelOnClose?.();
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
  let initialized = $state(false);
  let loaded = $state(false);
  let busy = $state(false);
  let submitted = $state(false);
  const cancelOnClose = $derived(stop?.id === 'S26' && !submitted ? cancelReleasedSigning : undefined);
  let signingIn = $state(false);
  let loginRequired = $state(false);
  let cancelled = $state(false);
  let pendingTimeout: ReturnType<typeof setTimeout> | undefined;
  let routerReady = false;
  let markerNeeded = false;
  afterNavigate(() => {
    routerReady = true;
    if (markerNeeded) {
      markerNeeded = false;
      replaceState(`${location.pathname}?transportVersion=2`, {});
    }
  });

  function clearPending() {
    if (pendingTimeout !== undefined) clearTimeout(pendingTimeout);
    try { sessionStorage.removeItem('openkey.delegate.tv2.pending'); } catch { /* Tab storage is optional after claim. */ }
    onClear();
    if (routerReady) replaceState(`${location.pathname}?transportVersion=2`, {});
    else markerNeeded = true;
  }

  function validDelivery(value: unknown): value is Delivery {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const item = value as Record<string, unknown>;
    const opaque = (part: unknown) => typeof part === 'string' && /^[A-Za-z0-9_-]{43}$/.test(part);
    return Object.keys(item).every(field => ['handoffId', 'state', 'cancelSecret', 'callback'].includes(field)) &&
      opaque(item.handoffId) && opaque(item.state) && opaque(item.cancelSecret) &&
      item.handoffId !== item.state && item.handoffId !== item.cancelSecret && item.state !== item.cancelSecret &&
      (item.callback === undefined || (typeof item.callback === 'string' &&
        /^http:\/\/(?:127\.0\.0\.1|\[::1\]):[0-9]{4,5}\/callback\/[A-Za-z0-9_-]{22}$/.test(item.callback) &&
        Number(new URL(item.callback).port) >= 1024));
  }

  onMount(() => {
    try {
      if (!encoded.startsWith('#tv2=') || !fitsPreparedLinkBudget(location, encoded)) throw new Error('Invalid prepared revocation link. Restart the CLI command.');
      const binary = atob(encoded.slice(5).replace(/-/g, '+').replace(/_/g, '/'));
      const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid prepared revocation request.');
      const claim = value as Record<string, unknown>;
      if (Object.keys(claim).sort().join(',') !== 'delivery,request,transportVersion' || claim.transportVersion !== 2 || !validDelivery(claim.delivery)) {
        throw new Error('Invalid prepared revocation envelope.');
      }
      const checked = parseOwnerRevocationRequest(claim.request);
      pending = { transportVersion: 2, request: claim.request as OwnerRevocationRequest, delivery: claim.delivery };
      pendingTimeout = setTimeout(() => {
        pending = null;
        clearPending();
        stop = approvalStop('S4');
        retry = undefined;
      }, Math.min(Date.parse(checked.expiresAt) - Date.now(), 300_000));
    } catch (cause) {
      clearPending();
      stop = approvalStop(encoded ? 'S1' : 'S3');
    } finally { initialized = true; }
    return () => {
      leaveRefusedSigning();
      if (pendingTimeout !== undefined) clearTimeout(pendingTimeout);
    };
  });

  async function post(path: string, body: unknown, valid?: (reply: Record<string, unknown>) => boolean, keepalive = false): Promise<Record<string, unknown>> {
    const token = getSessionToken();
    const response = await fetch(`${apiUrl}/api/delegate/${path}`, {
      method: 'POST', credentials: token ? 'omit' : 'include',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
      keepalive,
    });
    return readHandoffReply(response, valid);
  }

  async function load() {
    const input = pending;
    if (!input) return;
    busy = true;
    try {
      const availability = await fetch(`${apiUrl}/api/delegate/handoffs/available`, { credentials: 'include', cache: 'no-store' });
      if (!availability.ok) throw new ApprovalReplyError(availability.status);
      const feature = await availability.json().catch(() => null);
      if (!feature || typeof feature !== 'object') throw new ServerReplyError(availability.status);
      if (feature.transportVersion !== 2) {
        stop = approvalStop('S12');
        return;
      }
      const listed = await api.listKeys();
      if (pending !== input) return;
      const owner = ownerRevocationAddress(input.request);
      const choices = listed.keys.filter(item => item.address.toLowerCase() === owner.toLowerCase());
      if (!choices.length) {
        wanted = shortWallet(owner);
        compared = compareWallets(listed.keys);
        stop = approvalStop('S17', { values: {
          email: $session.data?.user.email ?? '', wanted: fill(STOP_PARTS.wantsWallet, { short: wanted }),
        } });
        return;
      }
      await post('handoffs/claim', input, (reply) => reply.ticket === input.delivery.handoffId && typeof reply.expiresAt === 'string');
      if (pending !== input) return;
      ticket = input.delivery.handoffId;
      request = input.request;
      delivery = input.delivery;
      keys = choices;
      pending = null;
      clearPending();
      if (choices.length === 1) await chooseKey(choices[0]!);
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
    if (!$session.data) loginRequired = true;
    else if (!loginRequired) { loaded = true; void load(); }
  });

  async function chooseKey(choice: EthereumKey) {
    if (!request || !ticket || contextToken) return;
    busy = true;
    error = '';
    try {
      const prepared = await post('owner-revocation/prepare', { ticket, keyId: choice.id },
        (reply) => typeof reply.siwe === 'string' && typeof reply.authorizationContextToken === 'string');
      key = choice;
      siwe = prepared.siwe as string;
      contextToken = prepared.authorizationContextToken as string;
    } catch (cause) {
      report(cause, () => chooseKey(choice));
    } finally { busy = false; }
  }

  async function revoke() {
    if (!key || !request || !delivery || !ticket || !contextToken || !siwe || busy || submitted) return;
    busy = true;
    error = '';
    try {
      let externalSignature: string | undefined;
      if (key.keyType === 'EXTERNAL') {
        const provider = (window as Window & { ethereum?: { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> } }).ethereum;
        if (!provider) throw new OwnerMessageError(STOPS.S32.lines.noWallet);
        const chain = await provider.request({ method: 'eth_chainId' });
        if (typeof chain !== 'string' || !/^0x[0-9a-fA-F]+$/.test(chain) ||
          BigInt(chain) !== BigInt(request.ownerDid.split(':')[3]!)) {
          throw new OwnerMessageError('The owner wallet is on a different chain.');
        }
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        if (!Array.isArray(accounts) || !accounts.every(value => typeof value === 'string')) throw new Error('Owner wallet returned invalid accounts.');
        const account = accounts.find(value => value.toLowerCase() === key!.address.toLowerCase());
        if (!account) throw new OwnerMessageError(fill(STOPS.S32.lines.walletLacks, { short: shortWallet(key.address) }));
        let signed: unknown;
        try {
          signed = await provider.request({ method: 'personal_sign', params: [siwe, account] });
        } catch {
          throw new OwnerMessageError(STOPS.S32.lines.walletDeclined);
        }
        if (typeof signed !== 'string') throw new OwnerMessageError(STOPS.S32.lines.walletDeclined);
        externalSignature = signed;
      }
      submitted = true;
      let signed: Record<string, unknown>;
      try {
        signed = await post('owner-revocation/sign', { ticket, keyId: key.id, authorizationContextToken: contextToken, ...(externalSignature ? { externalSignature } : {}) });
      } catch (cause) {
        // A refused or failed signing carries no signature and the server releases the handoff: Revoke and Cancel come back.
        if (!(cause instanceof ServerReplyError)) submitted = false;
        throw cause;
      }
      if (signed.siwe !== siwe || typeof signed.signature !== 'string' || signed.deliveryState !== delivery.state || signed.selectedKeyId !== key.id) {
        throw new Error('Signed response differs from the reviewed revocation.');
      }
      const result = await deliverOwnerRevocation({ state: delivery.state, siwe, signature: signed.signature, callback: delivery.callback });
      code = result.code;
      delivered = result.delivered;
    } catch (cause) {
      if (cause && typeof cause === 'object' && 'code' in cause && cause.code === 4001) error = STOPS.S32.lines.walletDeclined;
      else {
        report(cause, submitted ? undefined : revoke);
        cancelReleasedSigning = releasedSigningCancellation(cause,
          () => post('handoffs/cancel-claimed', { ticket }, undefined, true));
      }
    } finally { busy = false; }
  }

  async function cancel() {
    if (busy || submitted) return;
    if (!ticket) { pending = null; clearPending(); cancelled = true; return; }
    busy = true;
    try {
      const result = await post('handoffs/cancel-claimed', { ticket });
      if (result.cancelled !== true) throw new Error('The handoff was not cancelled.');
      request = null;
      delivery = null;
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
  const ended = $derived(initialized && !$session.isPending && (cancelled || (!!error && !request && !pending)));
  const loaderOn = $derived(
    !initialized || $session.isPending || (!ended && !signedOut && !!$session.data && !loginRequired && !code && !request),
  );
  const loaderLit = $derived(!initialized || $session.isPending ? 'session' : 'request');
  const cardOn = $derived(!loaderOn && !ended && (!$session.data || signedOut));
  const signedInOn = $derived(!loaderOn && !ended && !!$session.data && loginRequired && !signedOut);
  const slipAt = $derived(loaderOn ? 0 : cardOn || signedInOn ? 1 : cancelled ? 3 : code ? (delivered ? 4 : 3) : 2);
  const slipLast = $derived(code && !delivered && !cancelled ? 'code' : 'terminal');
  const expiresAt = $derived(siwe.match(/^Expiration Time: (.+)$/m)?.[1]);
  const keyName = (choice: EthereumKey) => choice.label ?? fill(REVOKE_REVIEW.keyFallback, { n: choice.keyIndex });
  const shortCid = (cid: string) => `${cid.slice(0, 10)}…${cid.slice(-6)}`;
</script>

<svelte:window onpagehide={leaveRefusedSigning} />

<Slip at={stop ? 2 : slipAt} last={slipLast} stopped={!!stop} email={stop && $session.data?.user.email}
  center={!stop && (loaderOn || cancelled || !!code)}>
  {#if stop}
    {#key stop}
      <StopPage {stop} wanted={stop.id === 'S17' ? wanted : ''} compared={stop.id === 'S17' ? compared : []}
        retry={retry ? retryStop : undefined} {switchAccount} {cancelOnClose}
        chooseKey={keys.length > 1 ? () => { stop = null; key = null; contextToken = ''; siwe = ''; } : undefined} />
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
      onCancel={cancel}
    />
  {:else if signedInOn}
    <SignedInCard onReview={() => { loginRequired = false; }} onCancel={cancel} />
  {:else if cancelled}
    <DonePage outcome="cancelled" />
  {:else if code && delivered && request}
    <DonePage outcome="signed" rows={[{ label: DONE.receipt.permission, value: shortCid(request.cid), mono: true }]} />
  {:else if code}
    <CodeBox
      fullCode={code}
      eyebrow={CODE.eyebrowRevoke}
      line={fill(delivery?.callback ? CODE.lineNotReached : CODE.lineRevoke, { destination: codeDestinationWord() })}
    />
  {:else if request}
    <p class="m-0 mb-2.5 text-[11.5px] font-semibold tracking-[0.09em] text-surface-500 uppercase">{REVOKE_REVIEW.eyebrow}</p>
    <h1 class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{REVOKE_REVIEW.heading}</h1>
    {#if error}
      <div class="mt-0.5 mb-3.5 grid grid-cols-[16px_1fr] gap-[9px] rounded-[11px] border border-red-line bg-red-wash px-3 py-[9px] text-[13.5px] leading-[1.45] text-[#7a1a12]">
        <Icon name="alert" class="mt-0.5 h-4 w-4" />
        <span role="alert">{error}</span>
      </div>
    {/if}
    {#if !key}
      <h2 class="m-0 mt-1 mb-2.5 text-[15px] font-semibold text-surface-950">{REVOKE_REVIEW.chooseKey}</h2>
      <div class="mb-4 grid gap-2">
        {#each keys as choice (choice.id)}
          <button
            type="button"
            class="grid w-full gap-0.5 rounded-[13px] border border-surface-300 bg-white px-[13px] py-[11px] text-left hover:border-surface-500 disabled:opacity-50"
            disabled={busy}
            onclick={() => chooseKey(choice)}
          >
            <span class="text-sm font-semibold text-surface-950">{keyName(choice)}</span>
            <span class="font-mono text-xs break-all text-surface-500">{choice.address}</span>
          </button>
        {/each}
      </div>
    {/if}
    <div class="mt-0.5 mb-3.5 grid grid-cols-[16px_1fr] gap-[9px] rounded-[11px] border border-red-line bg-red-wash px-3 py-[9px] text-[13.5px] leading-[1.45] text-[#7a1a12]">
      <Icon name="alert" class="mt-0.5 h-4 w-4" />
      <b class="font-semibold">{REVOKE_REVIEW.warning}</b>
    </div>
    <div class="rounded-xl border border-dashed border-surface-300 px-[13px] py-[11px]">
      <p class="m-0 mb-[5px] text-[11px] font-semibold tracking-[0.09em] text-surface-500 uppercase">{REVOKE_REVIEW.fullId}</p>
      <p class="m-0 font-mono text-[12.5px] leading-normal [overflow-wrap:anywhere] text-surface-950">{request.cid}</p>
    </div>
    <p class="m-0 mt-1.5 mb-3.5 text-[13px] leading-normal text-surface-500">{REVOKE_REVIEW.matchId}</p>
    <dl class="m-0 grid gap-2 text-[13.5px]">
      <div class="flex items-baseline justify-between gap-3.5">
        <dt class="flex-none text-surface-500">{REVOKE_REVIEW.rows.owner}</dt>
        <dd class="m-0 min-w-0 text-right font-mono text-[12.5px] [overflow-wrap:anywhere] text-surface-950">{ownerRevocationAddress(request)}</dd>
      </div>
      {#if key}
        <div class="flex items-baseline justify-between gap-3.5">
          <dt class="flex-none text-surface-500">{REVOKE_REVIEW.rows.signingWith}</dt>
          <dd class="m-0 min-w-0 text-right [overflow-wrap:anywhere] text-surface-950">{keyName(key)}</dd>
        </div>
      {/if}
      {#if expiresAt}
        <div class="flex items-baseline justify-between gap-3.5">
          <dt class="flex-none text-surface-500">{REVOKE_REVIEW.rows.expires}</dt>
          <dd class="m-0 min-w-0 text-right [overflow-wrap:anywhere] text-surface-950">{formatLocalAccessEnd(expiresAt)}</dd>
        </div>
      {/if}
    </dl>
    {#if key && siwe}
      <details open class="mt-3.5 text-[13px] text-surface-500">
        <summary class="cursor-pointer">{REVOKE_REVIEW.fold}</summary>
        <pre class="mt-2 whitespace-pre overflow-x-auto max-w-full min-w-0 rounded-lg bg-surface-50 p-3 text-xs text-surface-950">{renderSiweLiteral(siwe)}</pre>
      </details>
    {/if}
    <div class="mt-5 grid gap-2.5 {key ? 'grid-cols-2' : ''}">
      <Button variant="secondary" class="w-full" disabled={busy || submitted} onclick={cancel}>{REVOKE_REVIEW.cancel}</Button>
      {#if key}
        <Button class="w-full" disabled={busy || submitted} onclick={revoke}>{REVOKE_REVIEW.revoke}</Button>
      {/if}
    </div>
  {:else}
    <div class="space-y-5">
    <header><h1 class="text-xl font-semibold text-surface-900">{text.title}</h1></header>
    {#if error}<p role="alert" class="rounded-lg bg-red-50 p-3 text-red-800">{error}</p>{/if}
    {#if ended}<p>Start a new CLI revocation request.</p>
    {/if}
    </div>
  {/if}
</Slip>
