<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authClient, API_BASE } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  let loading = $state(false);
  let error = $state('');

  // Dev-only email OTP state
  let devEmail = $state('');
  let devOtp = $state('');
  let devStep = $state<'email' | 'otp'>('email');

  function handlePostSignIn() {
    const clientId = $page.url.searchParams.get('client_id');
    if (clientId) {
      const cleanParams = new URLSearchParams($page.url.searchParams);
      cleanParams.delete('sig');
      cleanParams.delete('exp');
      cleanParams.delete('prompt');
      window.location.href = API_BASE + '/api/auth/oauth2/authorize?' + cleanParams.toString();
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

<div class="min-h-screen bg-surface-950 flex items-center justify-center px-4">
  <Card class="w-full max-w-md">
    <h1 class="text-2xl font-bold text-surface-50 text-center mb-2">Welcome back</h1>
    <p class="text-surface-400 text-center mb-6">Sign in with your passkey</p>

    {#if error}
      <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-6" role="alert">
        {error}
      </div>
    {/if}

    <div class="flex flex-col gap-4">
      <Button onclick={signInWithPasskey} disabled={loading} class="w-full">
        {loading ? 'Signing in...' : 'Sign in with Passkey'}
      </Button>

      {#if import.meta.env.DEV}
        <div class="flex items-center gap-4 text-surface-500 my-2">
          <div class="flex-1 h-px bg-surface-700"></div>
          <span class="text-sm text-yellow-500">dev only</span>
          <div class="flex-1 h-px bg-surface-700"></div>
        </div>

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
            <Button type="submit" variant="secondary" disabled={loading} class="w-full">
              {loading ? 'Sending...' : 'Sign in with Email OTP'}
            </Button>
          </form>
        {:else}
          <div class="flex flex-col gap-3">
            <p class="text-surface-400 text-center text-sm">
              Enter the code sent to <span class="text-surface-200">{devEmail}</span>
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
              <Button type="submit" variant="secondary" disabled={loading} class="w-full">
                {loading ? 'Verifying...' : 'Verify Code'}
              </Button>
            </form>
            <button
              type="button"
              onclick={() => { devStep = 'email'; devOtp = ''; error = ''; }}
              class="text-surface-400 hover:text-surface-300 text-sm text-center"
            >
              Use a different email
            </button>
          </div>
        {/if}
      {/if}

      <div class="flex items-center gap-4 text-surface-500 my-2">
        <div class="flex-1 h-px bg-surface-700"></div>
        <span class="text-sm">or</span>
        <div class="flex-1 h-px bg-surface-700"></div>
      </div>

      <div class="flex flex-col gap-3 text-center">
        <a href="/auth/register" class="text-primary-400 hover:text-primary-300 text-sm">
          Create an account
        </a>
        <a href="/auth/recover" class="text-surface-400 hover:text-surface-300 text-sm">
          Can't sign in? Recover account
        </a>
      </div>
    </div>
  </Card>
</div>
