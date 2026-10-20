<script lang="ts">
  import Button from '$lib/components/ui/button.svelte';
  import TurnstileWidget from './turnstile-widget.svelte';

  // TC-1114: shown after a verified code for an email with no account. Nothing
  // exists yet; only "Create a new account" makes one.
  interface Props {
    email: string;
    busy?: boolean;
    creating?: boolean;
    /** TC-1632: show the verification check before creating the account. */
    challenge?: boolean;
    oncreate: (turnstileToken: string | null) => void;
    ondifferentemail: () => void;
    /** Omitted where passkeys are unavailable. */
    onpasskey?: () => void;
    /** Omitted where no recovery page can be opened. */
    onrecover?: () => void;
  }

  let {
    email,
    busy = false,
    creating = false,
    challenge = false,
    oncreate,
    ondifferentemail,
    onpasskey,
    onrecover,
  }: Props = $props();

  let turnstileToken = $state<string | null>(null);
  let widget = $state<{ reset: () => void }>();

  const canCreate = $derived(!challenge || turnstileToken !== null);

  const alternatives = $derived(
    onpasskey && onrecover
      ? 'sign in with your passkey or recover your account'
      : onpasskey
        ? 'sign in with your passkey'
        : onrecover
          ? 'recover your account'
          : 'use the email on your existing account',
  );

  function create() {
    if (!canCreate) return;
    const token = challenge ? turnstileToken : null;
    // Tokens are single-use: a new check is needed for every attempt.
    turnstileToken = null;
    widget?.reset();
    oncreate(token);
  }
</script>

<div class="flex w-full flex-col gap-3 text-center" data-testid="new-account-confirmation">
  <h2 class="text-base font-semibold text-surface-900">
    No OpenKey account for <span class="block break-words">{email}</span>
  </h2>
  <p class="mb-2 text-sm text-surface-500">Create a new account, or {alternatives}?</p>
  {#if challenge}
    <TurnstileWidget bind:this={widget} onverify={(token) => (turnstileToken = token)} onexpire={() => (turnstileToken = null)} />
  {/if}
  <Button onclick={create} disabled={busy || !canCreate} aria-busy={creating} class="w-full rounded-xl">
    {creating ? 'Creating account…' : 'Create a new account'}
  </Button>
  {#if onpasskey}
    <Button variant="secondary" onclick={onpasskey} disabled={busy} class="w-full rounded-xl">
      Sign in with a passkey
    </Button>
  {/if}
  {#if onrecover}
    <Button variant="secondary" onclick={onrecover} disabled={busy} class="w-full rounded-xl">
      Recover your account
    </Button>
  {/if}
  <button
    type="button"
    onclick={ondifferentemail}
    disabled={busy}
    class="mt-1 text-sm font-medium text-surface-500 hover:text-surface-900 disabled:opacity-50"
  >
    Use a different email
  </button>
</div>
