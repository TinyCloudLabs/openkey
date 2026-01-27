<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  let loading = $state(false);
  let error = $state('');

  async function signInWithPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) {
        error = result.error.message || 'Passkey sign-in failed';
      } else {
        goto('/dashboard');
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
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
