<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authClient, API_BASE } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  let loading = $state(false);
  let error = $state('');
  let showDevMode = $state(import.meta.env.DEV);

  // Persist OAuth params in sessionStorage so the register flow can resume the OAuth
  // authorization after passkey creation (params survive the Google OAuth round-trip)
  const OAUTH_STORAGE_KEY = 'openkey:pending_oauth';
  if (typeof window !== 'undefined' && $page.url.searchParams.has('client_id')) {
    const oauthParams = new URLSearchParams($page.url.searchParams);
    oauthParams.delete('sig');
    oauthParams.delete('exp');
    oauthParams.delete('prompt');
    sessionStorage.setItem(OAUTH_STORAGE_KEY, oauthParams.toString());
  }

  // Dev-only email OTP state
  let devEmail = $state('');
  let devOtp = $state('');
  let devStep = $state<'email' | 'otp'>('email');

  function handlePostSignIn() {
    const clientId = $page.url.searchParams.get('client_id');
    const redirect = $page.url.searchParams.get('redirect');
    if (clientId) {
      const cleanParams = new URLSearchParams($page.url.searchParams);
      cleanParams.delete('sig');
      cleanParams.delete('exp');
      cleanParams.delete('prompt');
      window.location.href = API_BASE + '/api/auth/oauth2/authorize?' + cleanParams.toString();
    } else if (redirect) {
      goto(redirect);
    } else {
      goto('/dashboard');
    }
  }

  async function signInWithPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) {
        error = result.error.message || 'Passkey sign-in failed';
      } else {
        handlePostSignIn();
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
    } finally {
      loading = false;
    }
  }

  async function devSendOTP() {
    loading = true;
    error = '';
    try {
      const result = await authClient.emailOtp.sendVerificationOtp({ email: devEmail, type: 'sign-in' });
      if (result.error) {
        error = result.error.message || 'Failed to send code';
      } else {
        devStep = 'otp';
      }
    } catch (e: any) {
      error = e.message || 'Failed to send code';
    } finally {
      loading = false;
    }
  }

  async function devVerifyOTP() {
    loading = true;
    error = '';
    try {
      const result = await authClient.signIn.emailOtp({ email: devEmail, otp: devOtp });
      if (result.error) {
        error = result.error.message || 'Invalid code';
      } else {
        handlePostSignIn();
      }
    } catch (e: any) {
      error = e.message || 'Invalid code';
    } finally {
      loading = false;
    }
  }
</script>

<div class="min-h-screen bg-surface-50 flex flex-col items-center justify-center px-4">
  <!-- Logo mark -->
  <div class="mb-8 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-surface-800 to-surface-950 shadow-md">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-6 w-6">
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  </div>

  <!-- Main card -->
  <Card class="w-full max-w-md p-10">
    <h1 class="text-[22px] font-semibold text-surface-900 text-center mb-2">Welcome back</h1>
    <p class="text-sm text-surface-500 text-center mb-8">Sign in with your passkey to continue</p>

    {#if error}
      <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
        {error}
      </div>
    {/if}

    <div class="flex flex-col gap-4">
      <Button onclick={signInWithPasskey} disabled={loading} class="w-full rounded-xl">
        {#if loading}
          Signing in...
        {:else}
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mr-2 h-4 w-4">
            <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" />
            <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
          </svg>
          Sign in with Passkey
        {/if}
      </Button>
    </div>

    <!-- Bottom links -->
    <div class="mt-8 flex items-center justify-center gap-3 text-sm">
      <a href="/auth/register" class="text-surface-500 hover:text-surface-700 transition-colors">
        Register
      </a>
      <span class="text-surface-300">|</span>
      <a href="/auth/recover" class="text-surface-500 hover:text-surface-700 transition-colors">
        Recover account
      </a>
    </div>

    <!-- Dev mode section -->
    {#if import.meta.env.DEV}
      <div class="mt-6 pt-6 border-t border-surface-100">
        <button
          type="button"
          onclick={() => { showDevMode = !showDevMode; }}
          class="w-full text-xs text-surface-400 hover:text-surface-500 transition-colors text-center"
        >
          {showDevMode ? 'Hide' : 'Show'} Dev mode
        </button>

        {#if showDevMode}
          <div class="mt-4 flex flex-col gap-3">
            {#if devStep === 'email'}
              <form onsubmit={(e) => { e.preventDefault(); devSendOTP(); }} class="flex flex-col gap-3">
                <div>
                  <label for="dev-email" class="sr-only">Email address</label>
                  <Input
                    id="dev-email"
                    type="email"
                    bind:value={devEmail}
                    placeholder="Email address"
                    required
                    disabled={loading}
                  />
                </div>
                <Button type="submit" variant="secondary" disabled={loading} class="w-full rounded-xl">
                  {loading ? 'Sending...' : 'Sign in with Email OTP'}
                </Button>
              </form>
            {:else}
              <div class="flex flex-col gap-3">
                <p class="text-surface-500 text-center text-sm">
                  Enter the code sent to <span class="text-surface-900 font-medium">{devEmail}</span>
                </p>
                <form onsubmit={(e) => { e.preventDefault(); devVerifyOTP(); }} class="flex flex-col gap-3">
                  <div>
                    <label for="dev-otp" class="sr-only">Verification code</label>
                    <Input
                      id="dev-otp"
                      type="text"
                      bind:value={devOtp}
                      placeholder="000000"
                      maxlength={6}
                      inputmode="numeric"
                      autocomplete="one-time-code"
                      required
                      disabled={loading}
                      class="text-center text-2xl tracking-widest font-mono"
                    />
                  </div>
                  <Button type="submit" variant="secondary" disabled={loading} class="w-full rounded-xl">
                    {loading ? 'Verifying...' : 'Verify Code'}
                  </Button>
                </form>
                <button
                  type="button"
                  onclick={() => { devStep = 'email'; devOtp = ''; error = ''; }}
                  class="text-surface-500 hover:text-surface-700 text-sm text-center transition-colors"
                >
                  Use a different email
                </button>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  </Card>

  <!-- Trust badge -->
  <div class="mt-6 flex items-center gap-2 text-xs text-surface-400">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
    Protected by TEE hardware security
  </div>
</div>
