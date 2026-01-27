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
      } else {
        goto('/dashboard');
      }
    } catch (e: any) {
      error = e.message || 'Failed to register passkey';
    } finally {
      loading = false;
    }
  }

  async function googleSignIn() {
    await authClient.signIn.social({ provider: 'google', callbackURL: '/auth/register?step=passkey' });
  }

  // Handle callback from Google OAuth
  import { page } from '$app/stores';
  import { onMount } from 'svelte';

  onMount(() => {
    const urlStep = $page.url.searchParams.get('step');
    if (urlStep === 'passkey') {
      step = 'passkey';
    }
  });
</script>

<div class="min-h-screen bg-surface-950 flex items-center justify-center px-4">
  <Card class="w-full max-w-md">
    {#if step === 'email'}
      <h1 class="text-2xl font-bold text-surface-50 text-center mb-2">Create an account</h1>
      <p class="text-surface-400 text-center mb-6">Get started with OpenKey</p>

      {#if error}
        <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-6" role="alert">
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

        <div class="flex items-center gap-4 text-surface-500">
          <div class="flex-1 h-px bg-surface-700"></div>
          <span class="text-sm">or</span>
          <div class="flex-1 h-px bg-surface-700"></div>
        </div>

        <Button variant="secondary" onclick={googleSignIn} disabled={loading} class="w-full">
          Continue with Google
        </Button>

        <p class="text-center text-sm text-surface-400 mt-2">
          Already have an account? <a href="/auth/login" class="text-primary-400 hover:text-primary-300">Sign in</a>
        </p>
      </div>
    {/if}

    {#if step === 'otp'}
      <h1 class="text-2xl font-bold text-surface-50 text-center mb-2">Check your email</h1>
      <p class="text-surface-400 text-center mb-6">
        Enter the 6-digit code sent to <span class="text-surface-200">{email}</span>
      </p>

      {#if error}
        <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-6" role="alert">
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
      <h1 class="text-2xl font-bold text-surface-50 text-center mb-2">Set up your passkey</h1>
      <p class="text-surface-400 text-center mb-6">
        Passkeys are the most secure way to sign in. You'll use this instead of a password.
      </p>

      {#if error}
        <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-6" role="alert">
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
