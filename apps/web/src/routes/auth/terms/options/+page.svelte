<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import { loadTermsStatus, oauthClientName, signedOAuthQuery } from '$lib/terms';
  import { declineEffect, declineHere, disconnectHref, originOfTermsPage, termsPageFrom } from '$lib/terms-leave';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import TermsSignedOut from '$lib/components/auth/terms-signed-out.svelte';
  import DeleteAccountSection from '../DeleteAccountSection.svelte';

  // TC-3232, page 2 of the ways out, from the Terms screen's "Other options": sign out without agreeing
  // (the request that brought the account to the Terms is turned down, renewals stop), or delete the
  // account. Disconnecting apps is page 3.
  const terms = termsPageFrom($page.url.searchParams.get('returnTo'));
  const origin = originOfTermsPage(terms);
  const termsUrl = new URL(terms, $page.url.origin);
  const oauthQuery = signedOAuthQuery(termsUrl.search);
  const termsReturnTo = termsUrl.searchParams.get('returnTo');
  const signInHref = oauthQuery
    ? `/auth/login?${oauthQuery}`
    : termsReturnTo ? `/auth/login?redirect=${encodeURIComponent(termsReturnTo)}` : '/auth/login';

  let ready = $state(false);
  let appName = $state<string | null>(null);
  let busy = $state(false);
  let error = $state('');
  let signedOut = $state(false);

  onMount(async () => {
    const session = await authClient.getSession().catch(() => null);
    if (!session?.data) {
      window.location.assign(signInHref);
      return;
    }
    const status = await loadTermsStatus().catch(() => null);
    if (status && !status.requiresAcceptance) {
      await goto('/dashboard/settings');
      return;
    }
    if (origin.kind === 'oauth') {
      const clientId = new URLSearchParams(origin.oauthQuery).get('client_id');
      if (clientId) appName = await oauthClientName(clientId);
    }
    ready = true;
  });

  async function signOut() {
    busy = true;
    error = '';
    try {
      const { redirect } = await declineHere(origin);
      if (redirect) {
        window.location.href = redirect;
        return;
      }
      signedOut = true;
    } catch {
      error = 'Couldn’t sign you out. Try again.';
    } finally {
      busy = false;
    }
  }
</script>

<svelte:head>
  <title>Other options · OpenKey</title>
  <meta name="robots" content="noindex" />
</svelte:head>

{#if signedOut}
  <TermsSignedOut {signInHref} />
{:else}
  <div class="flex min-h-screen items-center justify-center bg-surface-50 px-4 py-12">
    <div class="w-full max-w-md">
      <Card class="w-full p-8 sm:p-10" data-testid="terms-options">
        <a href={terms} class="mb-5 block text-sm text-surface-500 transition-colors hover:text-surface-700">&larr; Back to the Terms</a>
        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">Other options</h1>
        <p class="mb-6 text-center text-sm text-surface-500">You don’t need to agree to the Terms to sign out, disconnect apps or delete your account.</p>

        {#if ready}
          <section aria-labelledby="terms-sign-out-heading">
            <h2 id="terms-sign-out-heading" class="text-sm font-semibold text-surface-900">Sign out without agreeing</h2>
            <p class="mt-1 text-sm text-surface-500" data-testid="terms-decline-note">{declineEffect(origin, appName)}</p>
            {#if error}
              <div class="mt-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{error}</div>
            {/if}
            <Button variant="secondary" onclick={signOut} disabled={busy} aria-busy={busy} class="mt-3 w-full">
              {busy ? 'Signing out…' : 'Sign out'}
            </Button>
          </section>

          <DeleteAccountSection />

          <div class="mt-6 border-t border-surface-200 pt-5 text-center">
            <a href={disconnectHref(terms)} class="text-sm font-semibold text-surface-900 underline underline-offset-2">Disconnect apps or stop renewals</a>
          </div>
        {/if}
      </Card>
    </div>
  </div>
{/if}
