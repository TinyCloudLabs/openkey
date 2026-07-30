<script lang="ts">
  import { onMount } from 'svelte';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import {
    embedSendEmailOtp,
    embedSignInPasskey,
    embedVerifyEmailOtp,
    isEmbedContext,
  } from '$lib/embed-passkey';
  import {
    loadConfiguredSocialProviders,
    signInWithSocialPopup,
    type SocialProviderId,
  } from '$lib/social-auth';
  import SocialButtons from './social-buttons.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import Input from '$lib/components/ui/input.svelte';

  interface Props {
    prompt: string;
    onauthenticated: () => void;
    hasEoa?: boolean;
    onuseexternalwallet?: () => void;
  }

  let {
    prompt,
    onauthenticated,
    hasEoa = false,
    onuseexternalwallet,
  }: Props = $props();

  type BusyAction = 'send-email' | 'verify-email' | 'passkey' | SocialProviderId;

  let step = $state<'choices' | 'email' | 'otp'>('choices');
  let email = $state('');
  let otp = $state('');
  let error = $state('');
  let busy = $state<BusyAction | null>(null);
  let providers = $state<SocialProviderId[]>([]);

  onMount(async () => {
    providers = await loadConfiguredSocialProviders().catch(() => []);
  });

  async function sendOtp() {
    busy = 'send-email';
    error = '';
    try {
      await embedSendEmailOtp(email);
      step = 'otp';
    } catch (cause: any) {
      error = cause.message || 'Failed to send code';
    } finally {
      busy = null;
    }
  }

  async function verifyOtp() {
    busy = 'verify-email';
    error = '';
    try {
      await embedVerifyEmailOtp(email, otp);
      onauthenticated();
    } catch (cause: any) {
      error = cause.message || 'Invalid code';
    } finally {
      busy = null;
    }
  }

  async function signInWithPasskey() {
    busy = 'passkey';
    error = '';
    try {
      if (isEmbedContext()) {
        await embedSignInPasskey();
      } else {
        const result = await authClient.signIn.passkey();
        if (result.error) {
          error = authErrorMessage(result.error, 'Passkey sign-in failed');
          return;
        }
      }
      onauthenticated();
    } catch (cause: any) {
      error = cause.message || 'Passkey sign-in failed';
    } finally {
      busy = null;
    }
  }

  async function signInWithSocial(provider: SocialProviderId) {
    busy = provider;
    error = '';
    try {
      await signInWithSocialPopup(provider);
      onauthenticated();
    } catch (cause: any) {
      error = cause.message || `${provider === 'google' ? 'Google' : 'Apple'} sign-in failed`;
    } finally {
      busy = null;
    }
  }

  function backToChoices() {
    step = 'choices';
    otp = '';
    error = '';
  }
</script>

<div class="flex flex-col items-center justify-center py-2 text-center">
  <p class="mb-4 text-sm text-surface-500">{prompt}</p>

  {#if error}
    <div class="mb-4 w-full rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
      {error}
    </div>
  {/if}

  {#if step === 'choices'}
    <Button onclick={() => { step = 'email'; error = ''; }} disabled={busy !== null} class="w-full rounded-xl">
      Continue with email
    </Button>

    {#if providers.length > 0}
      <div class="mt-3 w-full">
        <SocialButtons
          {providers}
          loadingProvider={busy === 'google' || busy === 'apple' ? busy : null}
          disabled={busy !== null}
          onsignin={signInWithSocial}
        />
      </div>
    {/if}

    <div class="my-4 flex w-full items-center gap-3 text-surface-400" aria-hidden="true">
      <div class="h-px flex-1 bg-surface-200"></div>
      <span class="text-xs">or</span>
      <div class="h-px flex-1 bg-surface-200"></div>
    </div>

    <Button
      onclick={signInWithPasskey}
      variant="secondary"
      disabled={busy !== null}
      aria-busy={busy === 'passkey'}
      class="w-full rounded-xl"
    >
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">
        <path d="M12 11a1 1 0 0 0-1 1c0 3.1-.8 6.1-2.4 8.7"/>
        <path d="M8.2 4.7A8 8 0 0 1 20 11.8c0 2.6-.4 5.1-1.3 7.5"/>
        <path d="M4.9 17.3c.7-1.7 1.1-3.5 1.1-5.3a6 6 0 0 1 .3-1.9"/>
        <path d="M7.8 21.4A20 20 0 0 0 10 12a2 2 0 1 1 4 0c0 3.4-.6 6.8-1.8 10"/>
        <path d="M14.9 4.6A8 8 0 0 0 4 12c0 .7-.1 1.4-.2 2.1"/>
        <path d="M16 12a4 4 0 0 0-7.8-1.2"/>
        <path d="M16 12c0 3-.4 5.9-1.3 8.8"/>
      </svg>
      {busy === 'passkey' ? 'Waiting for passkey…' : 'Passkey'}
    </Button>

    {#if hasEoa && onuseexternalwallet}
      <button
        onclick={onuseexternalwallet}
        disabled={busy !== null}
        class="mt-3 border-none bg-transparent text-xs text-surface-400 transition-colors hover:text-surface-600 disabled:opacity-50"
      >
        or use an external wallet
      </button>
    {/if}
  {:else if step === 'email'}
    <form onsubmit={(event) => { event.preventDefault(); sendOtp(); }} class="flex w-full flex-col gap-3">
      <label for="embed-email" class="text-left text-sm font-medium text-surface-700">Email address</label>
      <Input
        id="embed-email"
        type="email"
        bind:value={email}
        autocomplete="email"
        autocapitalize="none"
        spellcheck={false}
        placeholder="you@example.com"
        required
        disabled={busy !== null}
        autofocus
      />
      <Button type="submit" disabled={busy !== null} aria-busy={busy === 'send-email'} class="w-full rounded-xl">
        {busy === 'send-email' ? 'Sending code…' : 'Send code'}
      </Button>
    </form>
    <button
      type="button"
      onclick={backToChoices}
      disabled={busy !== null}
      class="mt-3 text-sm font-medium text-surface-500 hover:text-surface-900 disabled:opacity-50"
    >
      Back
    </button>
  {:else}
    <p class="mb-3 text-sm text-surface-500">
      Enter the 6-digit code sent to <span class="font-medium text-surface-900">{email}</span>
    </p>
    <form onsubmit={(event) => { event.preventDefault(); verifyOtp(); }} class="flex w-full flex-col gap-3">
      <label for="embed-otp" class="sr-only">Verification code</label>
      <Input
        id="embed-otp"
        type="text"
        bind:value={otp}
        inputmode="numeric"
        autocomplete="one-time-code"
        maxlength={6}
        placeholder="000000"
        required
        disabled={busy !== null}
        autofocus
        class="text-center font-mono text-xl tracking-widest"
      />
      <Button type="submit" disabled={busy !== null} aria-busy={busy === 'verify-email'} class="w-full rounded-xl">
        {busy === 'verify-email' ? 'Verifying…' : 'Verify and continue'}
      </Button>
    </form>
    <button
      type="button"
      onclick={() => { step = 'email'; otp = ''; error = ''; }}
      disabled={busy !== null}
      class="mt-3 text-sm font-medium text-surface-500 hover:text-surface-900 disabled:opacity-50"
    >
      Use a different email
    </button>
  {/if}
</div>
