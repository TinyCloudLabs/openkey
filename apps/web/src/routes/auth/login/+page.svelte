<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  let email = $state('');
  let otp = $state('');
  let step = $state<'email' | 'otp' | 'passkey'>('email');
  let loading = $state(false);
  let error = $state('');

  // Check for existing passkey
  async function tryPasskeyLogin() {
    loading = true;
    error = '';
    try {
      await authClient.passkey.signIn();
      goto('/dashboard');
    } catch (e: any) {
      // No passkey available, continue with email flow
      error = e.message || 'Passkey login failed';
    } finally {
      loading = false;
    }
  }

  async function sendOTP() {
    loading = true;
    error = '';
    try {
      await authClient.emailOtp.sendVerificationOtp({ email, type: 'sign-in' });
      step = 'otp';
    } catch (e: any) {
      error = e.message || 'Failed to send OTP';
    } finally {
      loading = false;
    }
  }

  async function verifyOTP() {
    loading = true;
    error = '';
    try {
      await authClient.emailOtp.verifyEmail({ email, otp });
      // After verifying, prompt to register a passkey
      step = 'passkey';
    } catch (e: any) {
      error = e.message || 'Invalid OTP';
    } finally {
      loading = false;
    }
  }

  async function registerPasskey() {
    loading = true;
    error = '';
    try {
      await authClient.passkey.addPasskey();
      goto('/dashboard');
    } catch (e: any) {
      error = e.message || 'Failed to register passkey';
    } finally {
      loading = false;
    }
  }

  async function skipPasskey() {
    goto('/dashboard');
  }

  async function googleLogin() {
    await authClient.signIn.social({ provider: 'google' });
  }
</script>

<div class="min-h-screen bg-surface-950 flex items-center justify-center px-4">
  <Card class="w-full max-w-md">
    <h1 class="text-2xl font-bold text-surface-50 text-center mb-6">Sign In</h1>

    {#if error}
      <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-6" role="alert">
        {error}
      </div>
    {/if}

    {#if step === 'email'}
      <div class="flex flex-col gap-4">
        <Button variant="secondary" onclick={tryPasskeyLogin} disabled={loading} class="w-full">
          Sign in with Passkey
        </Button>

        <div class="flex items-center gap-4 text-surface-500">
          <div class="flex-1 h-px bg-surface-700"></div>
          <span class="text-sm">or</span>
          <div class="flex-1 h-px bg-surface-700"></div>
        </div>

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

        <div class="flex items-center gap-4 text-surface-500">
          <div class="flex-1 h-px bg-surface-700"></div>
          <span class="text-sm">or</span>
          <div class="flex-1 h-px bg-surface-700"></div>
        </div>

        <Button variant="secondary" onclick={googleLogin} disabled={loading} class="w-full">
          Continue with Google
        </Button>
      </div>
    {/if}

    {#if step === 'otp'}
      <div class="flex flex-col gap-4">
        <p class="text-surface-300 text-center">
          Enter the 6-digit code sent to <span class="text-surface-50 font-medium">{email}</span>
        </p>
        <form onsubmit={(e) => { e.preventDefault(); verifyOTP(); }} class="flex flex-col gap-4">
          <div>
            <label for="otp" class="sr-only">Verification code</label>
            <Input
              id="otp"
              type="text"
              bind:value={otp}
              placeholder="000000"
              maxlength={6}
              pattern="[0-9]{6}"
              required
              disabled={loading}
              class="text-center text-2xl tracking-widest font-mono"
            />
          </div>
          <Button type="submit" disabled={loading} class="w-full">
            {loading ? 'Verifying...' : 'Verify'}
          </Button>
        </form>
        <Button variant="ghost" onclick={() => step = 'email'} class="w-full">
          Back
        </Button>
      </div>
    {/if}

    {#if step === 'passkey'}
      <div class="flex flex-col gap-4 text-center">
        <div class="space-y-2">
          <h2 class="text-xl font-semibold text-surface-50">Add a Passkey</h2>
          <p class="text-surface-400">
            Secure your account with a passkey for faster, passwordless sign-in.
          </p>
        </div>
        <Button onclick={registerPasskey} disabled={loading} class="w-full">
          {loading ? 'Registering...' : 'Register Passkey'}
        </Button>
        <Button variant="ghost" onclick={skipPasskey} class="w-full">
          Skip for now
        </Button>
      </div>
    {/if}
  </Card>
</div>
