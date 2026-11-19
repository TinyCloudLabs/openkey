<script lang="ts">
  import { onMount } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import Icon from '$lib/components/approval/icon.svelte';
  import Slip from '$lib/components/approval/slip.svelte';
  import { focusHeading } from '$lib/components/approval/focus-heading';
  import { readSignedSessionToken } from '$lib/embed-passkey';
  import NewAccountConfirmation from '$lib/components/auth/new-account-confirmation.svelte';
  import Button from '$lib/components/ui/button.svelte';
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
    type SocialProviderId,
  } from '$lib/social-continuation';
  import { POPUP_WINDOW, fill } from '@openkey/sdk/approval-copy';

  // This page runs in the first-party popup the opener (login, register, the
  // embedded widget or Settings) opened. It starts the provider, shows any
  // choice the API asks for, and hands the session back through the single
  // `openkey:social:complete` message (social-auth.ts). Create runs here, never
  // in an embedded iframe, where the continuation cookie is partitioned.
  // While it works, `status` is the heading; `done`, `lost` and `error` are its three ends.
  let status = $state<string>(POPUP_WINDOW.working.completing);
  let error = $state('');
  let done = $state(false);
  // The window has no opener left to answer to.
  let lost = $state(false);
  let provider = $state<SocialProviderId | null>(null);
  let confirmation = $state<SocialContinuation | null>(null);
  let creating = $state(false);

  function finish(sessionToken: string) {
    window.opener.postMessage({ type: 'openkey:social:complete', sessionToken }, window.location.origin);
    done = true;
    window.setTimeout(() => window.close(), 100);
  }

  function returnToSignIn(message: string) {
    window.opener.postMessage({ type: 'openkey:social:error', message }, window.location.origin);
    window.close();
  }

  function openedByRegister(): boolean {
    try {
      // Reading a cross-origin opener's location throws.
      return window.opener.location.origin === window.location.origin
        && window.opener.location.pathname === '/auth/register';
    } catch {
      return false;
    }
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
      lost = true;
      return;
    }

    const currentURL = new URL(window.location.href);
    const callback = parseSocialCallback(currentURL);
    provider = callback.provider;
    try {
      if (callback.kind === 'start') {
        const providerName = socialProviderName(callback.provider);
        status = fill(POPUP_WINDOW.working.connecting, { provider: providerName });
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
        // asks first: it can never be the user's existing account (R4). The
        // intent is only a URL parameter, so it counts only when this popup's
        // opener is OpenKey's own register page; any other opener (another
        // site calling window.open) gets the confirmation (R5).
        if (loaded.outcome === 'new_account' && callback.signupIntent && openedByRegister() && !relayNotice(loaded)) {
          status = POPUP_WINDOW.working.creating;
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
      const sessionToken = await readSignedSessionToken();
      if (!sessionToken) {
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

  const stopHeading = $derived(
    lost ? POPUP_WINDOW.lost.heading
      : provider ? fill(POPUP_WINDOW.failed.heading, { provider: socialProviderName(provider) })
        : POPUP_WINDOW.failed.headingNoProvider,
  );
</script>

<svelte:head>
  <meta name="referrer" content="no-referrer" />
  <title>Completing sign-in · OpenKey</title>
</svelte:head>

<Slip steps={false} center>
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
    <div class="w-full" data-testid="social-account-exists">
      <h1 class="mb-3 text-lg font-semibold text-surface-900">Account already exists</h1>
      <p class="mb-5 break-words text-sm text-surface-600">{accountExistsMessage(confirmation.provider, confirmation.email)}</p>
      <button
        class="w-full rounded-xl bg-surface-900 px-4 py-3 text-sm font-medium text-white"
        onclick={() => returnToSignIn(`Sign in to your existing account, then add ${socialProviderName(confirmation!.provider)} in Settings.`)}
      >Return to sign-in</button>
    </div>
  {:else if lost || error}
    <div class="mt-1 mb-[18px] grid h-[52px] w-[52px] place-items-center rounded-full border border-red-line bg-red-wash text-[#b42318]">
      <Icon name="x" class="h-[26px] w-[26px]" />
    </div>
    <h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{stopHeading}</h1>
    <p class="m-0 text-pretty break-words">{lost ? POPUP_WINDOW.lost.line : error}</p>
    <Button class="mt-5 w-full" onclick={() => window.close()}>{POPUP_WINDOW.close}</Button>
  {:else if done}
    <div class="mt-1 mb-[18px] grid h-[52px] w-[52px] place-items-center rounded-full border border-green-line bg-green-wash text-[#157f3c]">
      <Icon name="check" class="h-[26px] w-[26px]" />
    </div>
    <h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{POPUP_WINDOW.done.heading}</h1>
    <p class="m-0 text-pretty">{POPUP_WINDOW.done.line}</p>
  {:else}
    <div class="relative my-[26px] mb-[22px] grid h-16 w-16 place-items-center" aria-hidden="true">
      <span class="absolute inset-0 animate-spin rounded-full border-2 border-surface-200 border-t-surface-950"></span>
      <span class="grid h-10 w-10 place-items-center rounded-xl bg-linear-to-br from-surface-800 to-surface-950 text-white">
        <Icon name="key" class="h-[22px] w-[22px]" />
      </span>
    </div>
    <h1 class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{status}</h1>
    <p class="m-0 text-pretty" role="status">{POPUP_WINDOW.working.line}</p>
  {/if}
</Slip>
