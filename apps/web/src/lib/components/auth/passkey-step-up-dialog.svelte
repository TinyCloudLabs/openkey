<script lang="ts">
  // TC-1198: confirms a passkey change with an email code or an existing
  // passkey, then hands back to the caller to retry the change.
  import { onMount } from 'svelte';
  import Button from '$lib/components/ui/button.svelte';
  import {
    sendPasskeyStepUpCode,
    verifyPasskeyStepUpCode,
    verifyWithExistingPasskey,
    type PasskeyStepUpMethod,
    type PasskeyStepUpPurpose,
  } from '$lib/passkey-step-up';

  interface Props {
    purpose: PasskeyStepUpPurpose;
    methods: PasskeyStepUpMethod[];
    onverified: () => void;
    oncancel: () => void;
  }

  let { purpose, methods, onverified, oncancel }: Props = $props();

  let dialog = $state<HTMLDivElement | null>(null);
  let codeSent = $state(false);
  let code = $state('');
  let busy = $state(false);
  let error = $state('');

  const adding = $derived(purpose === 'passkey_register');
  const offersPasskey = $derived(methods.includes('passkey'));
  const offersEmail = $derived(methods.includes('email'));

  onMount(() => dialog?.focus());

  async function run(action: () => Promise<void>) {
    busy = true;
    error = '';
    try {
      await action();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Verification failed. Try again.';
    } finally {
      busy = false;
    }
  }

  const usePasskey = () => run(async () => {
    await verifyWithExistingPasskey();
    onverified();
  });

  const sendCode = () => run(async () => {
    await sendPasskeyStepUpCode(purpose);
    codeSent = true;
    code = '';
  });

  const verifyCode = () => run(async () => {
    await verifyPasskeyStepUpCode(purpose, code);
    onverified();
  });
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-surface-900/40 p-4" role="presentation">
  <div bind:this={dialog} tabindex="-1" class="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl" role="dialog" aria-modal="true"
    aria-labelledby="passkey-step-up-title" aria-describedby="passkey-step-up-description"
    onkeydown={(event) => { if (event.key === 'Escape' && !busy) oncancel(); }}>
    <h2 id="passkey-step-up-title" class="text-xl font-semibold text-surface-900">
      {adding ? 'Confirm it’s you to add a passkey' : 'Confirm it’s you to remove this passkey'}
    </h2>
    <p id="passkey-step-up-description" class="mt-2 text-sm text-surface-600">
      {#if offersPasskey && offersEmail}
        Verify with one of your passkeys, or with a code sent to your OpenKey email.
      {:else if offersPasskey}
        Verify with one of your passkeys. An email code can’t confirm this change.
      {:else if offersEmail}
        We’ll send a code to your OpenKey email.
      {:else}
        Your OpenKey email can’t receive codes right now. If you use Hide My Email, turn forwarding back on in your Apple ID settings, then try again.
      {/if}
    </p>
    {#if error}<p class="mt-4 text-sm text-red-700" role="alert">{error}</p>{/if}

    {#if codeSent}
      <form class="mt-5 flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); void verifyCode(); }}>
        <label for="passkey-step-up-code" class="text-sm font-medium text-surface-700">Email verification code</label>
        <input id="passkey-step-up-code" class="w-full rounded-xl border border-surface-300 px-4 py-3" type="text"
          inputmode="numeric" autocomplete="one-time-code" maxlength="6" bind:value={code} disabled={busy} />
        <Button type="submit" disabled={busy || code.length !== 6}>{busy ? 'Verifying…' : 'Verify code'}</Button>
      </form>
    {:else}
      <div class="mt-5 flex flex-col gap-3">
        {#if offersPasskey}
          <Button onclick={usePasskey} disabled={busy}>{busy ? 'Verifying…' : 'Use an existing passkey'}</Button>
        {/if}
        {#if offersEmail}
          <Button variant={offersPasskey ? 'secondary' : 'default'} onclick={sendCode} disabled={busy}>
            {busy ? 'Sending…' : 'Email me a code'}
          </Button>
        {/if}
      </div>
    {/if}
    <div class="mt-3 flex justify-end">
      <Button variant="ghost" onclick={oncancel} disabled={busy}>Cancel</Button>
    </div>
  </div>
</div>
