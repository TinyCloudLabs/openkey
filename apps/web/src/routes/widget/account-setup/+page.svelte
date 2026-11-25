<script lang="ts">
  // OpenKey's own account setup page. Unframeable (frame-policy.ts): it runs in its own window, opened by the app, by
  // an OpenKey hand-off (`?via=embed`) or on its own. The owner's tap on Set up asks the API for the record; the
  // owner confirms it with a passkey (or an email code when the account has no passkey that counts), and the API sets
  // up the account and publishes that record. The app gets only the outcome.
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Card from '$lib/components/ui/card.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import { confirmWithPasskey, type ApprovalPasskeyOffer } from '$lib/approval-passkey';
  import { isFromWidgetCounterparty, resolveWidgetOrigin } from '$lib/widget-transport';
  import {
    accountSetupFailure,
    accountSetupSuccess,
    readAccountSetupRequest,
    TINYCLOUD_ONE_SETUP_URL,
    type AccountSetupPrepared,
    type AccountSetupRequest,
    type AccountSetupResponse,
    type AccountSetupState,
  } from '$lib/account-setup';

  type Phase =
    | 'waiting' | 'ready' | 'preparing' | 'confirm' | 'approving' | 'working'
    | 'failed' | 'present' | 'done' | 'unavailable';

  const session = authClient.useSession();
  const relayed = $page.url.searchParams.get('via') === 'embed';
  // The one window this page talks to and its exact origin: the app's window, or the OpenKey window that relays.
  const origin = relayed
    ? resolveWidgetOrigin(typeof window === 'undefined' ? null : window.location.origin)
    : resolveWidgetOrigin($page.url.searchParams.get('origin'));
  const counterparty: Window | null = typeof window === 'undefined' ? null : window.opener;
  // Opened on its own (no opener): the page sets up the account's primary key and answers no one.
  const standalone = counterparty === null || origin === null;

  let request = $state<AccountSetupRequest | null>(null);
  let answered = false;
  let phase = $state<Phase>('waiting');
  let key = $state<EthereumKey | null>(null);
  let prepared = $state<Extract<AccountSetupPrepared, { state: 'ready' }> | null>(null);
  let email = $state<string | null>(null);
  let codeSent = $state(false);
  let code = $state('');
  let notice = $state<string | null>(null);
  let failure = $state<{ message: string; retry: boolean } | null>(null);
  let unavailableMessage = $state<string | null>(null);
  let unavailableKind = $state<'tinycloud-one' | 'passkey'>('tinycloud-one');
  let offer = $state<ApprovalPasskeyOffer | null>(null);
  let pollTimer: ReturnType<typeof setTimeout> | null = null;

  const requesterHost = $derived(request ? new URL(request.requester).host : null);
  const loginHref = $derived(`/auth/login?redirect=${encodeURIComponent(`${$page.url.pathname}${$page.url.search}`)}`);

  $effect(() => {
    if (standalone) return;
    window.addEventListener('message', onMessage);
    counterparty!.postMessage({ type: 'openkey:ready' }, origin!);
    return () => window.removeEventListener('message', onMessage);
  });

  $effect(() => () => {
    if (pollTimer) clearTimeout(pollTimer);
  });

  function onMessage(event: MessageEvent) {
    if (request) return;
    if (!isFromWidgetCounterparty(event, origin, counterparty)) return;
    request = readAccountSetupRequest(event, origin, counterparty, relayed);
  }

  // The key to set up: the one the app named, else the account's primary key.
  $effect(() => {
    if (!$session.data || key || (!standalone && !request)) return;
    const wanted = request?.keyId ?? null;
    api.listKeys().then(({ keys }) => {
      const live = keys.filter((candidate) => !candidate.archivedAt);
      const chosen = wanted
        ? live.find((candidate) => candidate.id === wanted)
        : live.find((candidate) => candidate.isPrimary) ?? live.find((candidate) => candidate.keyType === 'MANAGED');
      if (!chosen) {
        showFailure('This key is not one of your OpenKey keys. Sign in with the account the app uses.', false);
        return;
      }
      key = chosen;
      if (chosen.keyType !== 'MANAGED') {
        showUnavailable("OpenKey can't set this up for a wallet key. Finish setup in TinyCloud One.");
        return;
      }
      phase = 'ready';
    }, () => showFailure('OpenKey could not read your keys. Reload this window.', false));
  });

  function answer(response: AccountSetupResponse) {
    if (answered || standalone || !request) return;
    answered = true;
    counterparty!.postMessage(response, origin!);
  }

  /** `passkey`: the account can confirm neither by passkey nor by email; else the way is TinyCloud One. */
  function showUnavailable(message: string, kind: 'tinycloud-one' | 'passkey' = 'tinycloud-one') {
    unavailableMessage = message;
    unavailableKind = kind;
    phase = 'unavailable';
  }

  function unavailableFrom(error: unknown) {
    const reason = (error as { reason?: unknown } | null)?.reason;
    showUnavailable(errorMessage(error), reason === 'no_step_up' ? 'passkey' : 'tinycloud-one');
  }

  function showFailure(message: string, retry: boolean) {
    failure = { message, retry };
    phase = 'failed';
  }

  function errorMessage(error: unknown): string {
    return error instanceof Error && error.message ? error.message : "Setup didn't finish.";
  }

  function errorCode(error: unknown): string | undefined {
    const value = (error as { code?: unknown } | null)?.code;
    return typeof value === 'string' ? value : undefined;
  }

  async function setUp() {
    if (!key || phase === 'preparing') return;
    phase = 'preparing';
    notice = null;
    try {
      const result = await api.accountSetup.prepare(key.id, request?.requester ?? null);
      if (result.state === 'present') {
        phase = 'present';
        return;
      }
      prepared = result;
      codeSent = false;
      code = '';
      email = null;
      offer = null;
      await loadStepUp();
      phase = 'confirm';
    } catch (error) {
      if (errorCode(error) === 'ACCOUNT_SETUP_UNAVAILABLE') unavailableFrom(error);
      else showFailure(errorMessage(error), false);
    }
  }

  /**
   * The challenge for this request, fetched before the tap so Confirm opens the passkey prompt straight from it. With
   * no passkey that counts, the API names the masked email a code goes to; no code is sent until the owner asks.
   */
  async function loadStepUp() {
    if (!prepared) return;
    const next = await api.accountSetup.stepUp(prepared.id);
    if (next.stepUp === 'email') {
      email = next.email;
      offer = null;
    } else {
      offer = next;
    }
  }

  async function confirmPasskey() {
    if (!prepared || !offer || phase === 'approving') return;
    const current = offer;
    phase = 'approving';
    notice = null;
    let assertion;
    try {
      assertion = await confirmWithPasskey(current);
    } catch {
      notice = 'The passkey prompt closed. Tap Confirm with your passkey to open it.';
      phase = 'confirm';
      return;
    }
    // The challenge is spent either way.
    offer = null;
    try {
      settle(await api.accountSetup.approve(prepared.id, { passkeyAssertion: assertion }));
    } catch (error) {
      approvalFailed(error);
    }
  }

  async function sendCode() {
    if (!prepared) return;
    notice = null;
    try {
      const sent = await api.accountSetup.sendEmailCode(prepared.id);
      email = sent.email;
      codeSent = true;
      if (!sent.sent) notice = 'A code is on its way. Check your email.';
    } catch (error) {
      if (errorCode(error) === 'ACCOUNT_SETUP_UNAVAILABLE') showUnavailable(errorMessage(error));
      else notice = errorMessage(error);
    }
  }

  async function confirmCode() {
    if (!prepared || phase === 'approving' || !/^\d{6}$/.test(code.trim())) return;
    phase = 'approving';
    notice = null;
    try {
      settle(await api.accountSetup.approve(prepared.id, { emailCode: code.trim() }));
    } catch (error) {
      approvalFailed(error);
    }
  }

  function approvalFailed(error: unknown) {
    const codeName = errorCode(error);
    if (codeName === 'account_setup_code_invalid' || codeName === 'account_setup_code_ended' ||
        codeName === 'passkey_approval_invalid' || codeName === 'passkey_approval_not_step_up' ||
        codeName === 'passkey_approval_required') {
      notice = errorMessage(error);
      code = '';
      phase = 'confirm';
      if (prepared?.stepUp === 'passkey') loadStepUp().catch((reload) => { notice = errorMessage(reload); });
      return;
    }
    if (codeName === 'ACCOUNT_SETUP_UNAVAILABLE') {
      unavailableFrom(error);
      return;
    }
    // The request ended or was used: the owner starts over.
    prepared = null;
    showFailure(errorMessage(error), false);
  }

  function settle(state: AccountSetupState) {
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
    if (state.state === 'published') {
      phase = 'done';
      if (request) answer(accountSetupSuccess(request, 'published'));
      return;
    }
    if (state.state === 'present') {
      phase = 'present';
      return;
    }
    if (state.state === 'working') {
      phase = 'working';
      pollTimer = setTimeout(() => void finish(), 2000);
      return;
    }
    if (!state.retry) prepared = null;
    showFailure(state.error, state.retry);
  }

  async function finish() {
    if (!prepared) return;
    phase = 'working';
    try {
      settle(await api.accountSetup.finish(prepared.id));
    } catch (error) {
      prepared = null;
      showFailure(errorMessage(error), false);
    }
  }

  function continueSetUp() {
    if (request) answer(accountSetupSuccess(request, 'present'));
    window.close();
  }

  function cancel() {
    if (request) {
      answer(phase === 'unavailable'
        ? accountSetupFailure(request, 'ACCOUNT_SETUP_UNAVAILABLE', unavailableMessage ?? "Account setup isn't available here.")
        : accountSetupFailure(request, 'USER_CANCELLED', 'The owner closed account setup.'));
    }
    window.close();
  }

  function leaveForTinyCloudOne() {
    if (request) answer(accountSetupFailure(request, 'ACCOUNT_SETUP_UNAVAILABLE', unavailableMessage ?? 'Finish setup in TinyCloud One.'));
  }

  function prettyRecord(text: string): string {
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      return text;
    }
  }
</script>

<svelte:head>
  <title>Set up your TinyCloud account · OpenKey</title>
</svelte:head>

<div class="min-h-screen bg-[#fafafa] flex flex-col items-center justify-center px-4 py-8">
  <Card class="w-full max-w-[440px]" data-testid="account-setup-card" data-phase={phase}>
    {#if $session.isPending}
      <p class="text-sm text-surface-500">Loading…</p>
    {:else if !$session.data}
      <h1 class="text-lg font-semibold text-surface-900">Set up your TinyCloud account</h1>
      <p class="mt-3 text-sm text-surface-600">Sign in to OpenKey to set up your account.</p>
      <div class="mt-5 flex flex-col gap-3">
        <Button href={loginHref} class="w-full rounded-xl">Sign in</Button>
        <Button variant="secondary" onclick={cancel} class="w-full rounded-xl">Cancel</Button>
      </div>
    {:else if phase === 'waiting'}
      <p class="text-sm text-surface-500">Waiting for the app…</p>
    {:else if phase === 'ready' || phase === 'preparing'}
      <h1 class="text-lg font-semibold text-surface-900">Set up your TinyCloud account</h1>
      {#if requesterHost}
        <p class="mt-2 text-sm text-surface-600" data-testid="account-setup-requester">
          Requested by <span class="font-medium text-surface-900">{requesterHost}</span>
          ({relayed ? 'the site that asked OpenKey to open this window' : 'the site that opened this window'}).
        </p>
      {/if}
      {#if key}
        <p class="mt-2 text-sm text-surface-600" data-testid="account-setup-account">
          Account: <span class="break-all font-mono text-xs text-surface-900">{key.address}</span>
        </p>
      {/if}
      <p class="mt-3 text-sm text-surface-700">
        This creates your TinyCloud spaces and publishes a public record of where your data lives. After setup, apps you
        approve can store data in your TinyCloud account.
      </p>
      <p class="mt-3 text-sm text-surface-700">
        You set up your account once, for all your apps. Each app asks for your approval before it gets access.
      </p>
      <p class="mt-3 text-xs text-surface-500">
        Some apps need extra setup in
        <a class="underline" href={TINYCLOUD_ONE_SETUP_URL} target="_blank" rel="noopener">TinyCloud One</a>.
      </p>
      <div class="mt-5 flex flex-col gap-3">
        <Button onclick={setUp} disabled={phase === 'preparing'} class="w-full rounded-xl" data-testid="account-setup-set-up">
          {phase === 'preparing' ? 'Preparing…' : 'Set up'}
        </Button>
        <Button variant="secondary" onclick={cancel} class="w-full rounded-xl">Cancel</Button>
      </div>
      <details class="mt-4 text-xs text-surface-500">
        <summary class="cursor-pointer">More options</summary>
        <p class="mt-2">
          <a class="underline" href={TINYCLOUD_ONE_SETUP_URL} target="_blank" rel="noopener" onclick={leaveForTinyCloudOne}>
            Choose your own location in TinyCloud One
          </a>
        </p>
      </details>
    {:else if (phase === 'confirm' || phase === 'approving') && prepared}
      <h1 class="text-lg font-semibold text-surface-900">Confirm setup</h1>
      {#if !email}
        <p class="mt-3 text-sm text-surface-700">Confirm with your passkey to set up your account on TinyCloud hosting.</p>
        <div class="mt-5 flex flex-col gap-3">
          <Button onclick={confirmPasskey} disabled={phase === 'approving' || !offer} class="w-full rounded-xl" data-testid="account-setup-confirm">
            {phase === 'approving' ? 'Confirming…' : 'Confirm with your passkey'}
          </Button>
          <Button variant="secondary" onclick={cancel} class="w-full rounded-xl">Cancel</Button>
        </div>
      {:else if !codeSent}
        <p class="mt-3 text-sm text-surface-700">We'll email a code to {email ?? 'your email'} to confirm setup.</p>
        <div class="mt-5 flex flex-col gap-3">
          <Button onclick={sendCode} class="w-full rounded-xl" data-testid="account-setup-send-code">Send code</Button>
          <Button variant="secondary" onclick={cancel} class="w-full rounded-xl">Cancel</Button>
        </div>
      {:else}
        <p class="mt-3 text-sm text-surface-700">We sent a code to {email}.</p>
        <form class="mt-4 flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); void confirmCode(); }}>
          <label class="text-xs font-medium text-surface-600" for="account-setup-code">Code</label>
          <input
            id="account-setup-code"
            class="h-11 rounded-xl border border-surface-200 px-3 text-base tracking-widest"
            inputmode="numeric"
            autocomplete="one-time-code"
            maxlength="6"
            bind:value={code}
          />
          <Button type="submit" disabled={phase === 'approving' || !/^\d{6}$/.test(code.trim())} class="w-full rounded-xl">
            {phase === 'approving' ? 'Confirming…' : 'Confirm'}
          </Button>
          <Button variant="ghost" type="button" onclick={sendCode} class="w-full rounded-xl">Send a new code</Button>
        </form>
      {/if}
      {#if notice}
        <p class="mt-3 text-sm text-red-700" role="alert">{notice}</p>
      {/if}
      <details class="mt-4 text-xs text-surface-500" data-testid="account-setup-details">
        <summary class="cursor-pointer">Advanced details</summary>
        <p class="mt-2">Node: {prepared.nodeUrl}</p>
        <p class="mt-1">The location record you approve:</p>
        <pre class="mt-1 max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-surface-50 p-2 text-[11px]">{prettyRecord(prepared.record)}</pre>
      </details>
    {:else if phase === 'working'}
      <h1 class="text-lg font-semibold text-surface-900">Setting up your account</h1>
      <ol class="mt-4 space-y-2 text-sm text-surface-700">
        <li>Create your spaces</li>
        <li>Publish a public record of where your data lives</li>
      </ol>
    {:else if phase === 'failed' && failure}
      <h1 class="text-lg font-semibold text-surface-900">Setup didn't finish</h1>
      <p class="mt-3 text-sm text-surface-700" role="alert">{failure.message}</p>
      <div class="mt-5 flex flex-col gap-3">
        {#if failure.retry && prepared}
          <Button onclick={finish} class="w-full rounded-xl" data-testid="account-setup-retry">Retry</Button>
        {:else if key?.keyType === 'MANAGED'}
          <Button onclick={setUp} class="w-full rounded-xl" data-testid="account-setup-start-over">Start over</Button>
        {/if}
        <Button variant="secondary" onclick={cancel} class="w-full rounded-xl">Close</Button>
      </div>
    {:else if phase === 'present'}
      <h1 class="text-lg font-semibold text-surface-900">Your TinyCloud account is set up</h1>
      <div class="mt-5 flex flex-col gap-3">
        <Button onclick={continueSetUp} class="w-full rounded-xl" data-testid="account-setup-continue">Continue</Button>
      </div>
    {:else if phase === 'done'}
      <h1 class="text-lg font-semibold text-surface-900">Your TinyCloud account is set up</h1>
      <p class="mt-3 text-sm text-surface-700">Return to the app to continue.</p>
      <div class="mt-5 flex flex-col gap-3">
        <Button variant="secondary" onclick={() => window.close()} class="w-full rounded-xl">Close</Button>
      </div>
    {:else if phase === 'unavailable'}
      <h1 class="text-lg font-semibold text-surface-900">Set up your TinyCloud account</h1>
      <p class="mt-3 text-sm text-surface-700" role="alert">{unavailableMessage}</p>
      <div class="mt-5 flex flex-col gap-3">
        {#if unavailableKind === 'passkey'}
          <Button href="/dashboard/settings" target="_blank" rel="noopener" class="w-full rounded-xl">Open OpenKey settings</Button>
        {:else}
          <Button href={TINYCLOUD_ONE_SETUP_URL} target="_blank" rel="noopener" onclick={leaveForTinyCloudOne} class="w-full rounded-xl">
            Open TinyCloud One
          </Button>
        {/if}
        <Button variant="secondary" onclick={cancel} class="w-full rounded-xl">Close</Button>
      </div>
    {/if}
  </Card>
</div>
