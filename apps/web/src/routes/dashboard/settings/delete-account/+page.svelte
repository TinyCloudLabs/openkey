<script lang="ts">
  import { goto } from '$app/navigation';
  import { onDestroy, tick } from 'svelte';
  import { API_BASE, authClient } from '$lib/auth-client';
  import {
    CODE_LIFETIME_SECONDS,
    DELETE_CONFIRMATION,
    DELETE_ACCOUNT_PATH,
    DeletionError,
    PASSKEY_UNAVAILABLE,
    deleteAccount,
    loadDeletionSupport,
    relayForwardingMessage,
    requiredMethod,
    sendDeletionCode,
    verifyDeletionCode,
    verifyDeletionPasskey,
    type DeletionAccount,
  } from '$lib/account-deletion';
  import { isAppleRelayEmail } from '$lib/social-continuation';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  // Explain → typed confirmation → step-up → result. The step-up comes last
  // so the deletion runs straight after it, well inside its five minutes.
  type Step = 'loading' | 'unavailable' | 'explain' | 'confirm' | 'verify' | 'done';

  const session = authClient.useSession();

  let step = $state<Step>('loading');
  let account = $state<DeletionAccount | null>(null);
  let loadError = $state('');
  let error = $state('');
  let notice = $state('');
  let busy = $state(false);
  let typed = $state('');
  let codeSent = $state(false);
  let code = $state('');
  // While a code is live the API sends no other, so a resend waits it out.
  let resendIn = $state(0);
  let resendTimer: ReturnType<typeof setInterval> | undefined;
  let started = false;
  let heading = $state<HTMLHeadingElement | null>(null);

  $effect(() => {
    if ($session.isPending || step === 'done') return;
    if (!$session.data) {
      goto(`/auth/login?redirect=${encodeURIComponent(DELETE_ACCOUNT_PATH)}`);
    } else if (!started) {
      started = true;
      void load();
    }
  });

  async function load() {
    step = 'loading';
    loadError = '';
    try {
      const support = await loadDeletionSupport(API_BASE);
      if (!support.supported) {
        step = 'unavailable';
        return;
      }
      account = support.account;
      step = 'explain';
    } catch (cause) {
      loadError = cause instanceof Error ? cause.message : 'Could not load your account. Try again.';
    }
  }

  async function go(next: Step) {
    error = '';
    notice = '';
    step = next;
    await tick();
    heading?.focus();
  }

  const relay = $derived(account !== null && isAppleRelayEmail(account.email));
  const passkeyBlocked = $derived(account?.method === 'passkey' && !account.passkeyStepUpAvailable);

  // A typed 403 names the step-up this account needs now (a passkey enrolled,
  // or the last one removed, since the page loaded).
  function handle(cause: unknown) {
    const method = requiredMethod(cause);
    if (account && method && method !== account.method) {
      account = { ...account, method };
      codeSent = false;
      code = '';
    }
    if (cause instanceof DeletionError && cause.code === 'passkey_step_up_unavailable' && account) {
      // The blocked passkey section already says so.
      account = { ...account, passkeyStepUpAvailable: false };
      return;
    }
    error = cause instanceof Error ? cause.message : 'Something went wrong. Try again.';
  }

  function startResendCountdown() {
    clearInterval(resendTimer);
    const deadline = Date.now() + CODE_LIFETIME_SECONDS * 1000;
    resendIn = CODE_LIFETIME_SECONDS;
    resendTimer = setInterval(() => {
      resendIn = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      if (resendIn === 0) clearInterval(resendTimer);
    }, 250);
  }
  onDestroy(() => clearInterval(resendTimer));

  const countdown = $derived(`${Math.floor(resendIn / 60)}:${String(resendIn % 60).padStart(2, '0')}`);

  async function finish() {
    await deleteAccount(API_BASE);
    clearInterval(resendTimer);
    await go('done');
    // The server already removed every session; this clears the local copy.
    await authClient.signOut().catch(() => {});
  }

  async function sendCode() {
    busy = true;
    error = '';
    notice = '';
    try {
      await sendDeletionCode(API_BASE);
      codeSent = true;
      code = '';
      startResendCountdown();
      notice = relay
        ? `We sent a code to your Apple relay address, ${account!.email}. It lasts 5 minutes.`
        : `We sent a code to ${account!.email}. It lasts 5 minutes.`;
    } catch (cause) {
      handle(cause);
    } finally {
      busy = false;
    }
  }

  async function verifyCodeAndDelete() {
    if (code.length !== 6) return;
    busy = true;
    error = '';
    try {
      await verifyDeletionCode(API_BASE, code);
      await finish();
    } catch (cause) {
      if (requiredMethod(cause) === 'email') codeSent = false;
      code = '';
      handle(cause);
    } finally {
      busy = false;
    }
  }

  async function verifyPasskeyAndDelete() {
    busy = true;
    error = '';
    try {
      await verifyDeletionPasskey(API_BASE);
      await finish();
    } catch (cause) {
      handle(cause);
    } finally {
      busy = false;
    }
  }
</script>

<div class="mx-auto max-w-xl px-4 py-8">
  {#if step !== 'done'}
    <div class="mb-6">
      <a href="/dashboard/settings" class="text-sm text-surface-500 transition-colors hover:text-surface-700">
        &larr; Back to Settings
      </a>
    </div>
  {/if}

  <Card>
    {#if step === 'loading'}
      {#if loadError}
        <p class="text-sm text-red-700" role="alert">{loadError}</p>
        <Button class="mt-4" variant="secondary" onclick={load}>Try again</Button>
      {:else}
        <p class="py-8 text-center text-surface-400">Loading your account…</p>
      {/if}
    {:else if step === 'unavailable'}
      <h1 bind:this={heading} tabindex="-1" class="text-2xl font-bold text-surface-900 outline-none">Delete account</h1>
      <p class="mt-3 text-sm leading-6 text-surface-600">
        Account deletion isn't available yet. Try again later.
      </p>
    {:else if step === 'explain' && account}
      <h1 bind:this={heading} tabindex="-1" class="text-2xl font-bold text-surface-900 outline-none">Delete your OpenKey account</h1>
      <p class="mt-3 text-sm leading-6 text-surface-600">
        This permanently deletes the OpenKey account for <span class="font-semibold text-surface-900">{account.email}</span>.
      </p>
      <ul class="mt-4 flex list-disc flex-col gap-2 pl-5 text-sm leading-6 text-surface-700">
        <li>
          Every key on this account is destroyed, including archived keys and any Nostr identity. Nobody, including OpenKey,
          can recover them, so anything that only these keys can sign for or decrypt is lost.
        </li>
        <li>Your passkeys, sessions and linked sign-in methods are removed. If you used Sign in with Apple, OpenKey revokes its Apple tokens.</li>
        <li>Apps you connected with OpenKey lose access. Signatures and delegations already issued stay valid until they expire.</li>
        <li>OpenKey doesn't delete data that apps keep with other services, such as files in your TinyCloud spaces. To remove that data, delete it in those apps first.</li>
      </ul>
      <p class="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm font-semibold text-red-700">This can't be undone.</p>
      <div class="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
        <Button variant="secondary" href="/dashboard/settings">Keep my account</Button>
        <Button onclick={() => go('confirm')}>Continue</Button>
      </div>
    {:else if step === 'confirm' && account}
      <h1 bind:this={heading} tabindex="-1" class="text-2xl font-bold text-surface-900 outline-none">Confirm deletion</h1>
      <form class="mt-4" onsubmit={(event) => { event.preventDefault(); if (typed === DELETE_CONFIRMATION) go('verify'); }}>
        <label class="block text-sm font-medium text-surface-800" for="delete-confirmation">
          Type <span class="font-mono font-semibold">{DELETE_CONFIRMATION}</span> to confirm
        </label>
        <input
          id="delete-confirmation"
          bind:value={typed}
          autocomplete="off"
          autocapitalize="characters"
          spellcheck={false}
          class="mt-2 flex h-11 w-full rounded-xl border border-surface-200 bg-white px-3 py-2 font-mono text-sm text-surface-900 focus-visible:border-primary-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-200"
        />
        <div class="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
          <Button variant="secondary" type="button" onclick={() => go('explain')}>Back</Button>
          <Button type="submit" disabled={typed !== DELETE_CONFIRMATION}>Continue</Button>
        </div>
      </form>
    {:else if step === 'verify' && account}
      <h1 bind:this={heading} tabindex="-1" class="text-2xl font-bold text-surface-900 outline-none">Verify it's you</h1>
      <p class="mt-3 text-sm leading-6 text-surface-600">
        Your account is deleted as soon as you verify.
      </p>
      {#if error}<p class="mt-4 text-sm text-red-700" role="alert">{error}</p>{/if}
      {#if notice}<p class="mt-4 text-sm text-surface-600" role="status">{notice}</p>{/if}

      {#if account.method === 'passkey'}
        {#if passkeyBlocked}
          <p class="mt-4 text-sm text-surface-600" role="status">{PASSKEY_UNAVAILABLE}</p>
        {:else}
          <p class="mt-4 text-sm text-surface-600">Confirm with a passkey saved for this account.</p>
          <div class="mt-6 flex justify-end">
            <Button class="w-full border-red-700 bg-red-700 hover:border-red-800 hover:bg-red-800 sm:w-auto" onclick={verifyPasskeyAndDelete} disabled={busy}>
              {busy ? 'Deleting…' : 'Verify with passkey and delete'}
            </Button>
          </div>
        {/if}
      {:else}
        {#if account.emailUndeliverable}
          <p class="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm leading-6 text-amber-900" role="alert">
            {relayForwardingMessage(account.email)}
          </p>
        {/if}
        {#if !codeSent}
          <p class="mt-4 text-sm text-surface-600">
            We'll email a code to {relay ? `your Apple relay address, ${account.email}` : account.email}.
          </p>
          <div class="mt-6 flex justify-end">
            <Button class="w-full sm:w-auto" onclick={sendCode} disabled={busy}>
              {busy ? 'Sending…' : 'Send code'}
            </Button>
          </div>
        {:else}
          <form class="mt-4" onsubmit={(event) => { event.preventDefault(); verifyCodeAndDelete(); }}>
            <label class="block text-sm font-medium text-surface-800" for="delete-code">Code from the email</label>
            <input
              id="delete-code"
              bind:value={code}
              inputmode="numeric"
              autocomplete="one-time-code"
              maxlength="6"
              class="mt-2 flex h-11 w-full rounded-xl border border-surface-200 bg-white px-3 py-2 font-mono text-lg tracking-widest text-surface-900 focus-visible:border-primary-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-200"
            />
            <p class="mt-2 text-xs text-surface-500">
              No email? Check spam{relay ? ' and that Apple is forwarding to you' : ''}.
              {#if resendIn > 0}
                You can ask for another code in {countdown}.
              {:else}
                <button type="button" class="underline" onclick={sendCode} disabled={busy}>Send a new code</button>.
              {/if}
            </p>
            <div class="mt-6 flex justify-end">
              <Button type="submit" class="w-full border-red-700 bg-red-700 hover:border-red-800 hover:bg-red-800 sm:w-auto" disabled={busy || code.length !== 6}>
                {busy ? 'Deleting…' : 'Verify and delete account'}
              </Button>
            </div>
          </form>
        {/if}
      {/if}
      <div class="mt-4 flex justify-start">
        <Button variant="ghost" size="sm" href="/dashboard/settings">Cancel</Button>
      </div>
    {:else if step === 'done'}
      <h1 bind:this={heading} tabindex="-1" class="text-2xl font-bold text-surface-900 outline-none">Your account was deleted</h1>
      <p class="mt-3 text-sm leading-6 text-surface-600" role="status">
        Your OpenKey account is gone and its keys were destroyed. You've been signed out of OpenKey everywhere.
      </p>
      <p class="mt-3 text-sm leading-6 text-surface-600">You can close this page.</p>
      <div class="mt-6">
        <Button variant="secondary" href="/">Go to OpenKey</Button>
      </div>
    {/if}
  </Card>
</div>
