<script lang="ts">
  import { onMount } from 'svelte';
  import { authClient, API_BASE } from '$lib/auth-client';
  import NewAccountConfirmation from '$lib/components/auth/new-account-confirmation.svelte';
  import { safeSocialAuthorizationUrl } from '$lib/social-auth';
  import {
    accountExistsMessage,
    confirmSocialContinuation,
    loadSocialContinuation,
    parseSocialCallback,
    relayNotice,
    socialErrorMessage,
    socialPopupReturnUrl,
    socialProviderName,
    type SocialContinuation,
  } from '$lib/social-continuation';

  // This page runs in the first-party popup the opener (login, register, the
  // embedded widget or Settings) opened. It starts the provider, shows any
  // choice the API asks for, and hands the session back through the single
  // `openkey:social:complete` message (social-auth.ts). Create runs here, never
  // in an embedded iframe, where the continuation cookie is partitioned.
  let status = $state('Completing sign-in…');
  let error = $state('');
  let confirmation = $state<SocialContinuation | null>(null);
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

  async function createAccount() {
    if (!confirmation || creating) return;
    creating = true;
    error = '';
    try {
      const token = await confirmSocialContinuation({ token: confirmation.token, provider: confirmation.provider });
      authClient.$store.notify('$sessionSignal');
      finish(token);
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

    const currentURL = new URL(window.location.href);
    const callback = parseSocialCallback(currentURL);
    try {
      if (callback.kind === 'start') {
        const providerName = socialProviderName(callback.provider);
        status = `Connecting to ${providerName}…`;
        const callbackURL = socialPopupReturnUrl(window.location.origin, callback.provider, callback.action);
        const input = {
          provider: callback.provider, callbackURL, errorCallbackURL: callbackURL, disableRedirect: true,
        } as const;
        const result = callback.action === 'link'
          ? await authClient.linkSocial(input)
          : await authClient.signIn.social(input);
        if (result.error) {
          throw new Error(result.error.message || `${providerName} sign-in failed.`);
        }
        const authorizationURL = safeSocialAuthorizationUrl(result.data?.url, callback.provider);
        if (!authorizationURL) {
          throw new Error(`${providerName} returned an invalid authorization URL.`);
        }
        window.location.replace(authorizationURL);
        return;
      }

      if (callback.kind === 'continuation') {
        const loaded = await loadSocialContinuation(callback);
        // /auth/register is explicit sign-up intent, but a relay address still
        // asks first: it can never be the user's existing account (R4).
        if (loaded.outcome === 'new_account' && callback.signupIntent && !relayNotice(loaded)) {
          status = 'Creating your account…';
          confirmation = null;
          const token = await confirmSocialContinuation({ token: loaded.token, provider: loaded.provider });
          authClient.$store.notify('$sessionSignal');
          finish(token);
          return;
        }
        confirmation = loaded;
        return;
      }
      if (callback.kind === 'error') {
        throw new Error(socialErrorMessage(callback.provider, callback.code));
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
        notice={relayNotice(confirmation)}
        busy={creating}
        {creating}
        differentEmailLabel="Use email instead"
        oncreate={createAccount}
        ondifferentemail={() => returnToSignIn('Continue with your email instead.')}
        onpasskey={() => returnToSignIn('Sign in with your passkey instead.')}
        onrecover={() => returnToSignIn('Recover your existing OpenKey account instead.')}
      />
    {:else if confirmation?.outcome === 'account_exists'}
      <div data-testid="social-account-exists">
        <h1 class="mb-3 text-lg font-semibold text-surface-900">Account already exists</h1>
        <p class="mb-5 break-words text-sm text-surface-600">{accountExistsMessage(confirmation.provider, confirmation.email)}</p>
        <button
          class="w-full rounded-xl bg-surface-900 px-4 py-3 text-sm font-medium text-white"
          onclick={() => returnToSignIn(`Sign in to your existing account, then add ${socialProviderName(confirmation!.provider)} in Settings.`)}
        >Return to sign-in</button>
      </div>
    {:else if error}
      <h1 class="mb-2 text-lg font-semibold text-surface-900">Sign-in failed</h1>
      <p class="text-sm text-red-700" role="alert">{error}</p>
    {:else}
      <h1 class="mb-2 text-lg font-semibold text-surface-900">OpenKey</h1>
      <p class="text-sm text-surface-500" role="status">{status}</p>
    {/if}
  </div>
</div>
