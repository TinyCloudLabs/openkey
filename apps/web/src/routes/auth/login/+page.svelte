<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient, API_BASE, authErrorMessage } from '$lib/auth-client';
  import { consoleOrigin } from '$lib/console-host';
  import { normalizeAuthReturnTo, safeOAuthAuthorizeQuery } from '$lib/auth-flow';
  import {
    loadConfiguredSocialProviders,
    signInWithSocialPopup,
    type SocialProviderId,
  } from '$lib/social-auth';
  import { api } from '$lib/api';
  import SocialButtons from '$lib/components/auth/social-buttons.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  type Step = 'email' | 'otp' | 'passkey';

  let email = $state('');
  let otp = $state('');
  let step = $state<Step>('email');
  let loading = $state(false);
  let error = $state('');
  let providers = $state<SocialProviderId[]>([]);
  let loadingProvider = $state<SocialProviderId | null>(null);

  function getOAuthQuery(): string | undefined {
    return safeOAuthAuthorizeQuery($page.url.searchParams);
  }

  function handlePostSignIn() {
    const oauthQuery = getOAuthQuery();
    const redirect = normalizeAuthReturnTo(
      $page.url.searchParams.get('redirect'),
      $page.url.origin,
      undefined,
      { consoleOrigin: consoleOrigin() || undefined },
    );
    if (oauthQuery) {
      window.location.href = API_BASE + '/api/auth/oauth2/authorize?' + oauthQuery;
    } else if (redirect) {
      if (new URL(redirect, $page.url.origin).origin === $page.url.origin) {
        goto(redirect);
      } else {
        window.location.assign(redirect);
      }
    } else {
      goto('/dashboard');
    }
  }

  onMount(async () => {
    providers = await loadConfiguredSocialProviders().catch(() => []);
  });

  async function sendOTP() {
    loading = true;
    error = '';
    try {
      const result = await authClient.emailOtp.sendVerificationOtp({ email, type: 'sign-in' });
      if (result.error) {
        error = authErrorMessage(result.error, 'Failed to send code');
      } else {
        step = 'otp';
      }
    } catch (e: any) {
      error = e.message || 'Failed to send code';
    } finally {
      loading = false;
    }
  }

  async function verifyOTP() {
    loading = true;
    error = '';
    try {
      const result = await authClient.signIn.emailOtp({
        email,
        otp,
        oauth_query: getOAuthQuery(),
      });
      if (result.error) {
        error = authErrorMessage(result.error, 'Invalid code');
        return;
      }

      // Email OTP is also the default account-creation path. The API normally
      // provisions a key in its user hook; this keeps the user moving if that
      // non-critical hook needs to be retried.
      try {
        const { keys } = await api.listKeys();
        if (keys.length === 0) await api.generateKey();
      } catch (keyError) {
        console.error('[Login] Failed to ensure key exists:', keyError);
      }

      // Encourage passkey setup for accounts that do not have one, but never
      // make it a condition of continuing. Passkey discovery is best-effort:
      // any failure (network, API unavailable) falls through to handlePostSignIn()
      // so that OTP sign-in works independently of passkey availability.
      try {
        const passkeys = await authClient.passkey.listUserPasskeys();
        if (!passkeys.error && Array.isArray(passkeys.data) && passkeys.data.length === 0) {
          step = 'passkey';
          return;
        }
      } catch (passkeyError) {
        console.error('[Login] Failed to check passkeys, continuing without prompt:', passkeyError);
      }
      handlePostSignIn();
    } catch (e: any) {
      error = e.message || 'Invalid code';
    } finally {
      loading = false;
    }
  }

  async function signInWithPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) {
        error = authErrorMessage(result.error, 'Passkey sign-in failed');
      } else {
        handlePostSignIn();
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
    } finally {
      loading = false;
    }
  }

  async function signInWithSocial(provider: SocialProviderId) {
    loading = true;
    loadingProvider = provider;
    error = '';
    try {
      await signInWithSocialPopup(provider);
      handlePostSignIn();
    } catch (e: any) {
      error = e.message || `${provider === 'google' ? 'Google' : 'Apple'} sign-in failed`;
    } finally {
      loading = false;
      loadingProvider = null;
    }
  }

  async function registerPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.passkey.addPasskey();
      if (result?.error) {
        error = authErrorMessage(result.error, 'Failed to create passkey');
      } else {
        handlePostSignIn();
      }
    } catch (e: any) {
      error = e.message || 'Failed to create passkey';
    } finally {
      loading = false;
    }
  }

  function useDifferentEmail() {
    step = 'email';
    otp = '';
    error = '';
  }
</script>

<div class="flex min-h-screen items-center justify-center bg-surface-50 px-4 py-12">
  <div class="w-full max-w-md">
    <div class="mb-8 flex justify-center">
      <div class="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-900">
        <svg class="h-6 w-6 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
        </svg>
      </div>
    </div>

    <Card class="w-full p-8 sm:p-10">
      {#if step === 'email'}
        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">Welcome to OpenKey</h1>
        <p class="mb-7 text-center text-sm text-surface-500">Sign in or create an account with your email</p>

        {#if error}
          <div class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
            {error}
          </div>
        {/if}

        <form onsubmit={(event) => { event.preventDefault(); sendOTP(); }} class="flex flex-col gap-4">
          <div>
            <label for="email" class="mb-2 block text-sm font-medium text-surface-700">Email address</label>
            <Input
              id="email"
              type="email"
              bind:value={email}
              placeholder="you@example.com"
              autocomplete="email"
              autocapitalize="none"
              spellcheck={false}
              required
              disabled={loading}
              autofocus
            />
          </div>
          <Button type="submit" disabled={loading} class="w-full">
            {loading ? 'Sending code…' : 'Continue with email'}
          </Button>
        </form>

        {#if providers.length > 0}
          <div class="mt-4">
            <SocialButtons
              {providers}
              {loadingProvider}
              disabled={loading}
              onsignin={signInWithSocial}
            />
          </div>
        {/if}

        <div class="my-6 flex items-center gap-4 text-surface-400" aria-hidden="true">
          <div class="h-px flex-1 bg-surface-200"></div>
          <span class="text-sm">or</span>
          <div class="h-px flex-1 bg-surface-200"></div>
        </div>

        <Button variant="secondary" onclick={signInWithPasskey} disabled={loading} class="w-full">
          <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" />
            <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
          </svg>
          {loading ? 'Waiting for passkey…' : 'Use a passkey instead'}
        </Button>
      {:else if step === 'otp'}
        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">Check your email</h1>
        <p class="mb-7 text-center text-sm text-surface-500">
          Enter the 6-digit code sent to <span class="font-medium text-surface-900">{email}</span>
        </p>

        {#if error}
          <div class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
            {error}
          </div>
        {/if}

        <form onsubmit={(event) => { event.preventDefault(); verifyOTP(); }} class="flex flex-col gap-4">
          <div>
            <label for="otp" class="sr-only">Verification code</label>
            <Input
              id="otp"
              type="text"
              bind:value={otp}
              placeholder="000000"
              maxlength={6}
              inputmode="numeric"
              autocomplete="one-time-code"
              required
              disabled={loading}
              autofocus
              class="text-center font-mono text-2xl tracking-widest"
            />
          </div>
          <Button type="submit" disabled={loading} class="w-full">
            {loading ? 'Verifying…' : 'Verify and continue'}
          </Button>
        </form>
        <button
          type="button"
          onclick={useDifferentEmail}
          disabled={loading}
          class="mt-4 w-full text-center text-sm font-medium text-surface-600 transition-colors hover:text-surface-900 disabled:opacity-50"
        >
          Use a different email
        </button>
      {:else}
        <div class="mb-5 flex justify-center">
          <div class="inline-flex h-12 w-12 items-center justify-center rounded-full bg-primary-50 text-primary-700 ring-1 ring-primary-200">
            <svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" />
              <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
            </svg>
          </div>
        </div>
        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">Secure your account</h1>
        <p class="mb-7 text-center text-sm text-surface-500">
          Create a passkey for faster, phishing-resistant sign-in. You can skip this and keep using email codes.
        </p>

        {#if error}
          <div class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-3">
          <Button onclick={registerPasskey} disabled={loading} class="w-full">
            {loading ? 'Creating passkey…' : 'Create a passkey'}
          </Button>
          <Button variant="ghost" onclick={handlePostSignIn} disabled={loading} class="w-full">
            Skip for now
          </Button>
        </div>
      {/if}
    </Card>

    <div class="mt-6 flex items-center justify-center gap-2 text-xs text-surface-500">
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
      Protected by TEE hardware security
    </div>
  </div>
</div>
