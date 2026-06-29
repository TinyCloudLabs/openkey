<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authClient, API_BASE, authErrorMessage } from '$lib/auth-client';
  import { api } from '$lib/api';
  import { setSessionToken } from '$lib/embed-passkey';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  let { data } = $props();

  let email = $state('');
  let otp = $state('');
  let step = $state<'email' | 'otp' | 'passkey' | 'success'>(getInitialStep());
  const initialReturnTo = getInitialReturnTo();
  let loading = $state(false);
  let error = $state('');
  let registeredSessionToken = $state<string | null>(null);

  // Detect if opened as a popup from the embed SDK flow
  const isEmbedPopup = $derived(typeof window !== 'undefined' && !!window.opener && data.isEmbed);

  function getInitialStep() {
    return data.initialStep;
  }

  function getInitialReturnTo() {
    return data.returnTo;
  }

  // Persist OAuth params in sessionStorage so the OAuth authorization can be
  // resumed after passkey registration (mirrors the login page logic)
  const OAUTH_STORAGE_KEY = 'openkey:pending_oauth';
  const RETURN_TO_STORAGE_KEY = 'openkey:pending_register_return';
  if (typeof window !== 'undefined' && $page.url.searchParams.has('client_id')) {
    const oauthParams = new URLSearchParams($page.url.searchParams);
    oauthParams.delete('sig');
    oauthParams.delete('exp');
    oauthParams.delete('prompt');
    sessionStorage.setItem(OAUTH_STORAGE_KEY, oauthParams.toString());
  }
  if (typeof window !== 'undefined' && initialReturnTo) {
    sessionStorage.setItem(RETURN_TO_STORAGE_KEY, initialReturnTo);
    sessionStorage.removeItem(OAUTH_STORAGE_KEY);
  }

  function takeReturnTo() {
    const returnTo = sessionStorage.getItem(RETURN_TO_STORAGE_KEY) || initialReturnTo;
    if (returnTo) {
      sessionStorage.removeItem(RETURN_TO_STORAGE_KEY);
    }
    return returnTo;
  }

  async function readSessionToken() {
    const sessionRes = await fetch(`${API_BASE}/api/auth/get-session`, {
      method: 'GET',
      credentials: 'include',
      headers: { 'Accept': 'application/json' },
    });
    const sessionBody = await sessionRes.json().catch(() => null);
    const sessionToken =
      sessionRes.headers.get('set-auth-token') ||
      sessionBody?.session?.token ||
      sessionBody?.token;
    if (!sessionToken) {
      throw new Error('Passkey registered, but no session token was returned.');
    }
    return sessionToken;
  }

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
      const result = await authClient.signIn.emailOtp({ email, otp });
      if (result.error) {
        error = authErrorMessage(result.error, 'Invalid code');
      } else {
        step = 'passkey';
      }
    } catch (e: any) {
      error = e.message || 'Invalid code';
    } finally {
      loading = false;
    }
  }

  // Ensure the user has at least one Ethereum key (the databaseHook auto-generates
  // one on user creation, but if it failed we create one here so the user isn't
  // stuck on an empty dashboard or sent back to an app with no key).
  async function ensureKeyExists() {
    try {
      const { keys } = await api.listKeys();
      if (keys.length === 0) {
        await api.generateKey();
      }
    } catch (e) {
      // Non-blocking — key can be created later from the dashboard
      console.error('[Register] Failed to ensure key exists:', e);
    }
  }

  async function registerPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.passkey.addPasskey();
      if (result?.error) {
        error = authErrorMessage(result.error, 'Failed to register passkey');
      } else {
        // Ensure the user has a key before proceeding
        await ensureKeyExists();
        if (data.isEmbed) {
          try {
            registeredSessionToken = await readSessionToken();
          } catch (e: any) {
            error = e.message || 'Passkey registered, but we could not prepare the embedded session.';
          }
        } else {
          registeredSessionToken = null;
        }
        step = 'success';
      }
    } catch (e: any) {
      error = e.message || 'Failed to register passkey';
    } finally {
      loading = false;
    }
  }

  async function continueAfterRegistration() {
    loading = true;
    error = '';
    try {
      if (data.isEmbed) {
        const sessionToken = registeredSessionToken || await readSessionToken();
        registeredSessionToken = sessionToken;

        if (isEmbedPopup) {
          window.opener.postMessage(
            { type: 'openkey:register:complete', sessionToken },
            window.location.origin
          );
          window.close();
        } else {
          setSessionToken(sessionToken);
          await goto(takeReturnTo() || '/widget/embed/connect');
        }
        return;
      }

      const returnTo = takeReturnTo();
      if (returnTo) {
        await goto(returnTo);
        return;
      }

      // Resume pending OAuth authorization flow if the user came from an OAuth client
      const pendingOAuth = sessionStorage.getItem(OAUTH_STORAGE_KEY);
      if (pendingOAuth) {
        sessionStorage.removeItem(OAUTH_STORAGE_KEY);
        window.location.href = API_BASE + '/api/auth/oauth2/authorize?' + pendingOAuth;
      } else {
        await goto('/dashboard');
      }
    } catch (e: any) {
      error = e.message || 'Failed to continue';
    } finally {
      loading = false;
    }
  }

  async function returnToEmbedSignIn() {
    const returnTo = takeReturnTo() || '/widget/embed/connect';
    if (isEmbedPopup) {
      window.close();
    } else {
      await goto(returnTo);
    }
  }

  function registrationCallbackParams() {
    const params = new URLSearchParams({ step: 'passkey' });
    if (data.isEmbed) params.set('embed', 'true');
    const returnTo = takeReturnTo();
    if (returnTo) params.set('returnTo', returnTo);
    return params.toString();
  }

  async function googleSignIn() {
    await authClient.signIn.social({ provider: 'google', callbackURL: `${window.location.origin}/auth/register?${registrationCallbackParams()}` });
  }
</script>

<div class="flex min-h-screen items-center justify-center bg-surface-50 px-4 py-12">
  <div class="w-full max-w-md">
    <!-- Logo mark -->
    <div class="mb-8 flex justify-center">
      <div class="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-900">
        <svg class="h-6 w-6 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
        </svg>
      </div>
    </div>

    <Card class="w-full">
      {#if step === 'email'}
        <h1 class="text-2xl font-bold text-surface-900 text-center mb-2">Create an account</h1>
        <p class="text-surface-500 text-center mb-6">Get started with OpenKey</p>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-4">
          <form onsubmit={(e) => { e.preventDefault(); sendOTP(); }} class="flex flex-col gap-4">
            <div>
              <label for="email" class="sr-only">Email address</label>
              <Input
                id="email"
                type="email"
                bind:value={email}
                placeholder="Email address"
                required
                disabled={loading}
              />
            </div>
            <Button type="submit" disabled={loading} class="w-full">
              {loading ? 'Sending...' : 'Continue with Email'}
            </Button>
          </form>

          <div class="flex items-center gap-4 text-surface-400">
            <div class="flex-1 h-px bg-surface-200"></div>
            <span class="text-sm">or</span>
            <div class="flex-1 h-px bg-surface-200"></div>
          </div>

          <Button variant="secondary" onclick={googleSignIn} disabled={loading} class="w-full">
            Continue with Google
          </Button>

          {#if data.isEmbed}
            <p class="text-center text-sm text-surface-500 mt-2">
              Already have an account?
              <button
                type="button"
                onclick={returnToEmbedSignIn}
                class="text-surface-900 font-medium hover:underline bg-transparent border-none p-0 cursor-pointer"
              >
                Back to sign in
              </button>
            </p>
          {:else}
            <p class="text-center text-sm text-surface-500 mt-2">
              Already have an account? <a href="/auth/login" class="text-surface-900 font-medium hover:underline">Sign in</a>
            </p>
          {/if}
        </div>
      {/if}

      {#if step === 'otp'}
        <h1 class="text-2xl font-bold text-surface-900 text-center mb-2">Check your email</h1>
        <p class="text-surface-500 text-center mb-6">
          Enter the 6-digit code sent to <span class="text-surface-900 font-medium">{email}</span>
        </p>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <form onsubmit={(e) => { e.preventDefault(); verifyOTP(); }} class="flex flex-col gap-4">
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
              class="text-center text-2xl tracking-widest font-mono"
            />
          </div>
          <Button type="submit" disabled={loading} class="w-full">
            {loading ? 'Verifying...' : 'Verify'}
          </Button>
        </form>
        <Button variant="ghost" onclick={() => { step = 'email'; error = ''; }} class="w-full mt-2">
          Back
        </Button>
      {/if}

      {#if step === 'passkey'}
        <h1 class="text-2xl font-bold text-surface-900 text-center mb-2">Set up your passkey</h1>
        <p class="text-surface-500 text-center mb-6">
          Passkeys are the most secure way to sign in. You'll use this instead of a password.
        </p>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-4">
          <Button onclick={registerPasskey} disabled={loading} class="w-full">
            {loading ? 'Registering...' : 'Register Passkey'}
          </Button>
        </div>
      {/if}

      {#if step === 'success'}
        <div class="flex flex-col items-center text-center">
          <div class="mb-5 inline-flex h-12 w-12 items-center justify-center rounded-full bg-green-50 text-green-700 ring-1 ring-green-200">
            <svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M20 6 9 17l-5-5" />
            </svg>
          </div>
          <h1 class="text-2xl font-bold text-surface-900 mb-2">Passkey registered</h1>
          <p class="text-surface-500 mb-6 max-w-sm">
            Your account is secured. Continue to finish signing in with OpenKey.
          </p>

          {#if error}
            <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
              {error}
            </div>
          {/if}

          <Button onclick={continueAfterRegistration} disabled={loading} class="w-full">
            {loading ? 'Continuing...' : 'Continue'}
          </Button>
        </div>
      {/if}
    </Card>
  </div>
</div>
