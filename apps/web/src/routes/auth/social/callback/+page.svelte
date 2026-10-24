<script lang="ts">
  import { onMount } from 'svelte';
  import { authClient, API_BASE } from '$lib/auth-client';
  import NewAccountConfirmation from '$lib/components/auth/new-account-confirmation.svelte';
  import {
    safeSocialAuthorizationUrl,
    type SocialProviderId,
  } from '$lib/social-auth';

  let status = $state('Completing sign-in…');
  let error = $state('');
  let continuation = $state<string | null>(null);
  let confirmation = $state<{ outcome: 'new_account' | 'account_exists'; email: string } | null>(null);
  let creating = $state(false);

  function finish(sessionToken: string) {
    window.opener.postMessage({ type: 'openkey:social:complete', sessionToken }, window.location.origin);
    status = 'Sign-in complete. You can close this window.';
    window.setTimeout(() => window.close(), 100);
  }

  function returnToSignIn(message: string) {
    window.opener.postMessage({ type: 'openkey:social:error', message }, window.location.origin);
    window.close();
  }

  async function createGoogleAccount() {
    if (!continuation || creating) return;
    creating = true;
    error = '';
    try {
      const response = await fetch(`${API_BASE}/api/auth/social/confirm`, {
        method: 'POST', credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ continuation }),
      });
      const result = await response.json();
      if (!response.ok || !result.token) throw new Error(result.message || 'Could not create your account. Start Google sign-in again.');
      authClient.$store.notify('$sessionSignal');
      finish(result.token);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not create your account.';
    } finally {
      creating = false;
    }
  }

  onMount(async () => {
    if (!window.opener) {
      error = 'This sign-in window is no longer connected to OpenKey. Close it and try again.';
      return;
    }

    try {
      const currentURL = new URL(window.location.href);
      const providerParam = currentURL.searchParams.get('provider');
      const provider: SocialProviderId | null =
        providerParam === 'google' || providerParam === 'apple'
          ? providerParam
          : null;

      if (provider) {
        const providerName = provider === 'google' ? 'Google' : 'Apple';
        status = `Connecting to ${providerName}…`;
        const callbackURL = new URL('/auth/social/callback', window.location.origin).href;
        const input = {
          provider, callbackURL, errorCallbackURL: callbackURL, disableRedirect: true,
        } as const;
        const result = currentURL.searchParams.get('action') === 'link'
          ? await authClient.linkSocial(input)
          : await authClient.signIn.social(input);
        if (result.error) {
          throw new Error(result.error.message || `${providerName} sign-in failed.`);
        }
        const authorizationURL = safeSocialAuthorizationUrl(result.data?.url, provider);
        if (!authorizationURL) {
          throw new Error(`${providerName} returned an invalid authorization URL.`);
        }
        window.location.replace(authorizationURL);
        return;
      }

      const socialError = currentURL.searchParams.get('error');
      const socialContinuation = currentURL.searchParams.get('continuation');
      if (socialContinuation && (socialError === 'new_account' || socialError === 'account_exists')) {
        const response = await fetch(
          `${API_BASE}/api/auth/social/continuation?continuation=${encodeURIComponent(socialContinuation)}`,
          { credentials: 'include', headers: { Accept: 'application/json' } },
        );
        if (!response.ok) throw new Error('This Google confirmation expired. Start sign-in again.');
        const details = await response.json();
        if (details.outcome !== socialError || typeof details.email !== 'string') {
          throw new Error('Invalid Google confirmation. Start sign-in again.');
        }
        continuation = socialContinuation;
        confirmation = { outcome: details.outcome, email: details.email };
        return;
      }
      if (socialError) {
        throw new Error(socialError === 'account_not_linked'
          ? 'An OpenKey account already uses this email. Sign in to it and link Google in Settings.'
          : 'Google could not complete sign-in. Please try again.');
      }
      const response = await fetch(`${API_BASE}/api/auth/get-session`, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      const body = await response.json().catch(() => null);
      const sessionToken =
        response.headers.get('set-auth-token')
        || body?.session?.token
        || body?.token;
      if (!response.ok || !sessionToken) {
        throw new Error('OpenKey could not read the completed session. Please try again.');
      }

      finish(sessionToken);
    } catch (cause: any) {
      error = cause.message || 'Social sign-in failed.';
      window.opener.postMessage(
        { type: 'openkey:social:error', message: error },
        window.location.origin,
      );
    }
  });
</script>

<svelte:head>
  <meta name="referrer" content="no-referrer" />
  <title>Completing sign-in · OpenKey</title>
</svelte:head>

<div class="flex min-h-screen items-center justify-center bg-surface-50 px-4">
  <div class="w-full max-w-sm rounded-2xl border border-surface-200 bg-white p-8 text-center shadow-sm">
    <div class="mx-auto mb-5 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-900 text-white">
      <svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
      </svg>
    </div>
    {#if confirmation?.outcome === 'new_account'}
      {#if error}<p class="mb-3 text-sm text-red-700" role="alert">{error}</p>{/if}
      <NewAccountConfirmation
        email={confirmation.email}
        busy={creating}
        {creating}
        oncreate={createGoogleAccount}
        ondifferentemail={() => returnToSignIn('Use a different sign-in method to continue.')}
        onpasskey={() => returnToSignIn('Sign in with your passkey instead.')}
        onrecover={() => returnToSignIn('Recover your existing OpenKey account instead.')}
      />
    {:else if confirmation?.outcome === 'account_exists'}
      <h1 class="mb-3 text-lg font-semibold text-surface-900">Account already exists</h1>
      <p class="mb-5 text-sm text-surface-600">
        An OpenKey account already uses {confirmation.email}. Sign in to it, then verify with an email code to add Google in Settings.
      </p>
      <button
        class="w-full rounded-xl bg-surface-900 px-4 py-3 text-sm font-medium text-white"
        onclick={() => returnToSignIn('Sign in to your existing account, then link Google in Settings.')}
      >Return to sign-in</button>
    {:else if error}
      <h1 class="mb-2 text-lg font-semibold text-surface-900">Sign-in failed</h1>
      <p class="text-sm text-red-700" role="alert">{error}</p>
    {:else}
      <h1 class="mb-2 text-lg font-semibold text-surface-900">OpenKey</h1>
      <p class="text-sm text-surface-500" role="status">{status}</p>
    {/if}
  </div>
</div>
