<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient, API_BASE } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  let { data } = $props();

  let email = $state('');
  let otp = $state('');
  let step = $state<'email' | 'otp' | 'passkey'>(data.initialStep);
  let loading = $state(false);
  let error = $state('');

  // Detect if opened as a popup from the embed SDK flow
  const isEmbedPopup = typeof window !== 'undefined' && !!window.opener && data.isEmbed;

  const OAUTH_STORAGE_KEY = 'openkey:pending_oauth';

  async function sendOTP() {
    loading = true;
    error = '';
    try {
      const result = await authClient.emailOtp.sendVerificationOtp({ email, type: 'sign-in' });
      if (result.error) {
        error = result.error.message || 'Failed to send code';
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
        error = result.error.message || 'Invalid code';
      } else {
        step = 'passkey';
      }
    } catch (e: any) {
      error = e.message || 'Invalid code';
    } finally {
      loading = false;
    }
  }

  async function registerPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.passkey.addPasskey();
      if (result?.error) {
        error = result.error.message || 'Failed to register passkey';
      } else if (isEmbedPopup) {
        // Opened from embed SDK — get a bearer token from the session and
        // post it back to the parent SDK so the embed iframe can authenticate.
        // The bearer() plugin returns the token via the set-auth-token header.
        const sessionRes = await fetch('/api/auth/get-session', {
          method: 'GET',
          credentials: 'include',
          headers: { 'Accept': 'application/json' },
        });
        const sessionToken = sessionRes.headers.get('set-auth-token');
        window.opener.postMessage({ type: 'openkey:register:complete', sessionToken }, '*');
      } else {
        // Resume pending OAuth authorization flow if the user came from an OAuth client
        const pendingOAuth = sessionStorage.getItem(OAUTH_STORAGE_KEY);
        if (pendingOAuth) {
          sessionStorage.removeItem(OAUTH_STORAGE_KEY);
          window.location.href = API_BASE + '/api/auth/oauth2/authorize?' + pendingOAuth;
        } else {
          goto('/dashboard');
        }
      }
    } catch (e: any) {
      error = e.message || 'Failed to register passkey';
    } finally {
      loading = false;
    }
  }

  async function googleSignIn() {
    const callbackParams = isEmbedPopup ? 'step=passkey&embed=true' : 'step=passkey';
    await authClient.signIn.social({ provider: 'google', callbackURL: `${window.location.origin}/auth/register?${callbackParams}` });
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

          <p class="text-center text-sm text-surface-500 mt-2">
            Already have an account? <a href="/auth/login" class="text-surface-900 font-medium hover:underline">Sign in</a>
          </p>
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
    </Card>
  </div>
</div>
