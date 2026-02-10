<script lang="ts">
  import { authClient } from '$lib/auth-client';
  import { goto } from '$app/navigation';

  let email = $state('');
  let otp = $state('');
  let step = $state<'email' | 'otp'>('email');
  let loading = $state(false);
  let error = $state('');

  async function sendOTP() {
    loading = true;
    error = '';

    try {
      const result = await authClient.emailOtp.sendVerificationOtp({
        email,
        type: 'sign-in',
      });

      if (result.error) {
        error = result.error.message || 'Failed to send verification code';
        return;
      }

      step = 'otp';
    } catch (e) {
      error = 'Failed to send verification code. Please try again.';
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
      });

      if (result.error) {
        error = result.error.message || 'Invalid verification code';
        return;
      }

      // Redirect to dashboard on success
      goto('/');
    } catch (e) {
      error = 'Verification failed. Please try again.';
    } finally {
      loading = false;
    }
  }

  function goBack() {
    step = 'email';
    otp = '';
    error = '';
  }
</script>

<svelte:head>
  <title>Sign In - OpenKey Admin</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-surface-50 px-4">
  <div class="w-full max-w-sm">
    <div class="text-center mb-8">
      <h1 class="text-3xl font-bold text-surface-900">OpenKey Admin</h1>
      <p class="text-surface-500 mt-2">Sign in to your developer account</p>
    </div>

    <div class="bg-white border border-surface-200 rounded-lg p-6">
      {#if step === 'email'}
        <form onsubmit={(e) => { e.preventDefault(); sendOTP(); }}>
          <label for="email" class="block text-sm font-medium text-surface-700 mb-1">
            Email address
          </label>
          <input
            id="email"
            type="email"
            bind:value={email}
            placeholder="you@example.com"
            required
            class="w-full px-3 py-2 border border-surface-300 rounded-md text-surface-900 placeholder-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          />

          {#if error}
            <p class="mt-2 text-sm text-red-600">{error}</p>
          {/if}

          <button
            type="submit"
            disabled={loading || !email}
            class="mt-4 w-full py-2 px-4 bg-primary-600 text-white rounded-md font-medium hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Sending...' : 'Send Verification Code'}
          </button>
        </form>
      {:else}
        <form onsubmit={(e) => { e.preventDefault(); verifyOTP(); }}>
          <p class="text-sm text-surface-600 mb-4">
            We sent a verification code to <span class="font-medium text-surface-900">{email}</span>
          </p>

          <label for="otp" class="block text-sm font-medium text-surface-700 mb-1">
            Verification code
          </label>
          <input
            id="otp"
            type="text"
            bind:value={otp}
            placeholder="000000"
            required
            maxlength={6}
            autocomplete="one-time-code"
            class="w-full px-3 py-2 border border-surface-300 rounded-md text-surface-900 placeholder-surface-400 text-center text-lg tracking-widest font-mono focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          />

          {#if error}
            <p class="mt-2 text-sm text-red-600">{error}</p>
          {/if}

          <button
            type="submit"
            disabled={loading || otp.length < 6}
            class="mt-4 w-full py-2 px-4 bg-primary-600 text-white rounded-md font-medium hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading ? 'Verifying...' : 'Verify & Sign In'}
          </button>

          <button
            type="button"
            onclick={goBack}
            class="mt-2 w-full py-2 px-4 text-surface-600 text-sm hover:text-surface-900 transition-colors"
          >
            Use a different email
          </button>
        </form>
      {/if}
    </div>
  </div>
</div>
