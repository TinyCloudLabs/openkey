<script lang="ts">
  import { onMount } from 'svelte';
  import { authClient, API_BASE, authErrorMessage } from '$lib/auth-client';
  import { loadConfiguredSocialProviders, signInWithSocialPopup } from '$lib/social-auth';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  type GoogleAccount = { id: string; providerId: string; accountId: string };
  let accounts = $state<GoogleAccount[]>([]);
  let googleAvailable = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');
  let action = $state<'link' | 'unlink' | null>(null);
  let step = $state<'code' | 'verified' | null>(null);
  let code = $state('');

  async function refreshAccounts() {
    const result = await authClient.listAccounts();
    if (result.error) throw new Error(authErrorMessage(result.error, 'Could not load linked accounts.'));
    accounts = (result.data ?? []).filter((account) => account.providerId === 'google') as GoogleAccount[];
  }

  onMount(() => {
    void refreshAccounts().catch((cause) => {
      error = cause instanceof Error ? cause.message : 'Could not load linked accounts.';
    }).finally(() => { loading = false; });
    void loadConfiguredSocialProviders().then((providers) => {
      googleAvailable = providers.includes('google');
    }).catch(() => {});
  });

  async function requestCode(next: 'link' | 'unlink') {
    busy = true;
    error = '';
    notice = '';
    try {
      const response = await fetch(`${API_BASE}/api/account/step-up/email-otp/send`, {
        method: 'POST', credentials: 'include',
      });
      if (!response.ok) throw new Error('Could not send an account verification code. Try again.');
      action = next;
      step = 'code';
      code = '';
      notice = 'Check your OpenKey email for a code to change linked sign-in methods.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not send a code.';
    } finally {
      busy = false;
    }
  }

  async function verifyCode() {
    if (!action || code.length !== 6) return;
    busy = true;
    error = '';
    try {
      const response = await fetch(`${API_BASE}/api/account/step-up/email-otp/verify`, {
        method: 'POST', credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      if (!response.ok) throw new Error('Incorrect or expired code. Check the email and try again.');
      code = '';
      if (action === 'link') {
        step = 'verified';
        notice = 'Email verified. Continue to Google within five minutes.';
      } else {
        const account = accounts[0];
        if (!account) throw new Error('Google is no longer linked to this account.');
        const unlink = await fetch(`${API_BASE}/api/account/social/unlink`, {
          method: 'POST', credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ providerId: 'google', accountId: account.accountId }),
        });
        if (!unlink.ok) throw new Error('Could not unlink Google. Verify a new code or add a passkey first.');
        await refreshAccounts();
        action = null;
        step = null;
        notice = 'Google was unlinked. You can still sign in with your email or passkey.';
      }
    } catch (cause) {
      if (action === 'unlink' && code === '') {
        action = null;
        step = null;
      }
      error = cause instanceof Error ? cause.message : 'Could not update your account.';
    } finally {
      busy = false;
    }
  }

  async function linkGoogle() {
    busy = true;
    error = '';
    try {
      // The popup is opened synchronously by signInWithSocialPopup on this click.
      await signInWithSocialPopup('google', undefined, 'link');
      await refreshAccounts();
      action = null;
      step = null;
      notice = 'Google is linked to this OpenKey account.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not link Google.';
    } finally {
      busy = false;
    }
  }
</script>

<Card class="mt-6">
  <div class="mb-5">
    <h2 class="text-xl font-semibold text-surface-900">Linked sign-in methods</h2>
    <p class="mt-1 text-sm text-surface-500">Verify an email code before adding or removing Google.</p>
  </div>
  {#if error}<p class="mb-4 text-sm text-red-700" role="alert">{error}</p>{/if}
  {#if notice}<p class="mb-4 text-sm text-surface-600" role="status">{notice}</p>{/if}
  {#if step === 'code'}
    <form class="flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); verifyCode(); }}>
      <label for="link-code" class="text-sm font-medium text-surface-700">Email verification code</label>
      <input id="link-code" class="w-full rounded-xl border border-surface-300 px-4 py-3" type="text"
        inputmode="numeric" autocomplete="one-time-code" maxlength="6" bind:value={code} disabled={busy} />
      <div class="flex gap-3">
        <Button type="submit" disabled={busy || code.length !== 6}>{busy ? 'Verifying…' : 'Verify code'}</Button>
        <Button type="button" variant="secondary" onclick={() => { action = null; step = null; error = ''; }}>Cancel</Button>
      </div>
    </form>
  {:else if step === 'verified'}
    <Button onclick={linkGoogle} disabled={busy}>{busy ? 'Connecting…' : 'Continue to Google'}</Button>
  {:else if loading}
    <p class="text-sm text-surface-500">Loading linked accounts…</p>
  {:else if accounts.length > 0}
    <div class="flex items-center justify-between gap-3 rounded-xl border border-surface-200 bg-surface-50 p-4">
      <span class="font-medium text-surface-900">Google</span>
      <Button variant="secondary" onclick={() => requestCode('unlink')} disabled={busy}>Unlink Google</Button>
    </div>
  {:else if googleAvailable}
    <Button onclick={() => requestCode('link')} disabled={busy}>Link Google</Button>
  {:else}
    <p class="text-sm text-surface-500">No social sign-in method linked.</p>
  {/if}
</Card>
