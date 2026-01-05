<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';

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

<div class="auth-container">
  <h1>Sign In</h1>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if step === 'email'}
    <div class="auth-form">
      <button class="button passkey" onclick={tryPasskeyLogin} disabled={loading}>
        Sign in with Passkey
      </button>

      <div class="divider">
        <span>or</span>
      </div>

      <form onsubmit={(e) => { e.preventDefault(); sendOTP(); }}>
        <input
          type="email"
          bind:value={email}
          placeholder="Email address"
          required
          disabled={loading}
        />
        <button type="submit" class="button primary" disabled={loading}>
          {loading ? 'Sending...' : 'Continue with Email'}
        </button>
      </form>

      <div class="divider">
        <span>or</span>
      </div>

      <button class="button google" onclick={googleLogin} disabled={loading}>
        Continue with Google
      </button>
    </div>
  {/if}

  {#if step === 'otp'}
    <div class="auth-form">
      <p>Enter the 6-digit code sent to {email}</p>
      <form onsubmit={(e) => { e.preventDefault(); verifyOTP(); }}>
        <input
          type="text"
          bind:value={otp}
          placeholder="000000"
          maxlength="6"
          pattern="[0-9]{6}"
          required
          disabled={loading}
          class="otp-input"
        />
        <button type="submit" class="button primary" disabled={loading}>
          {loading ? 'Verifying...' : 'Verify'}
        </button>
      </form>
      <button class="button link" onclick={() => step = 'email'}>
        Back
      </button>
    </div>
  {/if}

  {#if step === 'passkey'}
    <div class="auth-form">
      <h2>Add a Passkey</h2>
      <p>Secure your account with a passkey for faster, passwordless sign-in.</p>
      <button class="button primary" onclick={registerPasskey} disabled={loading}>
        {loading ? 'Registering...' : 'Register Passkey'}
      </button>
      <button class="button link" onclick={skipPasskey}>
        Skip for now
      </button>
    </div>
  {/if}
</div>

<style>
  .auth-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
  }

  h1 {
    text-align: center;
    margin-bottom: 2rem;
  }

  .auth-form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  input {
    padding: 1rem;
    border: 1px solid #333;
    border-radius: 8px;
    background: #1a1a1a;
    color: #fafafa;
    font-size: 1rem;
  }

  input:focus {
    outline: none;
    border-color: #667eea;
  }

  .otp-input {
    text-align: center;
    font-size: 2rem;
    letter-spacing: 0.5rem;
    font-family: monospace;
  }

  .button {
    padding: 1rem;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }

  .button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .button.primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }

  .button.passkey {
    background: #1a1a1a;
    border: 1px solid #333;
    color: #fafafa;
  }

  .button.google {
    background: #1a1a1a;
    border: 1px solid #333;
    color: #fafafa;
  }

  .button.link {
    background: transparent;
    color: #888;
    padding: 0.5rem;
  }

  .button.link:hover {
    color: #fafafa;
  }

  .divider {
    display: flex;
    align-items: center;
    gap: 1rem;
    color: #666;
  }

  .divider::before,
  .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: #333;
  }

  .error {
    background: #ff4444;
    color: white;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
  }
</style>
