<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  let email = $state('');
  let otp = $state('');
  let step = $state<'email' | 'otp' | 'passkey'>('email');
  let loading = $state(false);
  let error = $state('');

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

  async function registerPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.passkey.addPasskey();
      if (result?.error) {
        error = authErrorMessage(result.error, 'Failed to register passkey');
      } else {
        goto('/dashboard');
      }
    } catch (e: any) {
      error = e.message || 'Failed to register passkey';
    } finally {
      loading = false;
    }
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
        <h1 class="text-2xl font-bold text-surface-900 text-center mb-2">Recover your account</h1>
        <p class="text-surface-500 text-center mb-6">
          We'll send a code to verify your identity and set up a new passkey
        </p>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
            {error}
          </div>
        {/if}

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
            {loading ? 'Sending...' : 'Send recovery code'}
          </Button>
        </form>

        <p class="text-center text-sm text-surface-500 mt-4">
          <a href="/auth/login" class="text-surface-900 font-medium hover:underline">Back to sign in</a>
        </p>
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
        <h1 class="text-2xl font-bold text-surface-900 text-center mb-2">Set up a new passkey</h1>
        <p class="text-surface-500 text-center mb-6">
          Your identity has been verified. Register a new passkey to regain access to your account.
        </p>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-4">
          <Button onclick={registerPasskey} disabled={loading} class="w-full">
            {loading ? 'Registering...' : 'Register New Passkey'}
          </Button>
        </div>
      {/if}
    </Card>
  </div>
</div>
