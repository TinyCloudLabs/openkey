<script lang="ts">
  import { page } from '$app/stores';
  import TermsAccept from '$lib/components/auth/terms-accept.svelte';
  import TermsSignedOut from '$lib/components/auth/terms-signed-out.svelte';
  import { TermsVersionMismatch, acceptTerms, loadTermsStatus, type TermsStatus } from '$lib/terms';
  import { declineEffect, declineHere, optionsHref, termsOrigin, termsPageFor } from '$lib/terms-leave';

  // TC-3232: the required Terms step, wherever it is shown (its own page, or inline in sign-in and sign-up
  // so it comes before the passkey offer). Agree records the acceptance, then hands back to the caller.
  // On the web the ways out are on their own pages, reached from the "Other options" box. The native
  // sheet keeps Don't agree here: it says no to the request that brought the account here and signs it
  // out; nothing is deleted.
  interface Props {
    status: TermsStatus;
    surface: 'web' | 'native';
    email: string;
    /** The native sheet's OAuth client: branding, and the surface recorded with the acceptance. */
    clientId?: string | null;
    appName?: string | null;
    /** The page the account was on its way to, if any: an approval link or device sign-in is declined too. */
    returnTo?: string | null;
    /** Runs once the acceptance is recorded; the screen stays busy until it navigates away. */
    onaccepted: () => void | Promise<void>;
    /** Where "Sign in" goes after Don't agree; `onsignin` instead when the caller is the sign-in page. */
    signInHref?: string;
    onsignin?: () => void;
  }

  let { status, surface, email, clientId = null, appName = null, returnTo = null, onaccepted, signInHref = '/auth/login', onsignin }: Props = $props();

  const origin = $derived(termsOrigin($page.url.search, returnTo));
  const otherOptions = $derived(surface === 'web' ? optionsHref(termsPageFor($page.url.search, returnTo)) : null);

  // svelte-ignore state_referenced_locally
  let release = $state(status);
  let busy = $state<'accept' | 'decline' | null>(null);
  let error = $state<string | null>(null);
  let signedOut = $state(false);

  async function accept() {
    busy = 'accept';
    error = null;
    try {
      await acceptTerms(release.version ?? '', surface === 'native' ? clientId : null);
    } catch (cause) {
      busy = null;
      if (!(cause instanceof TermsVersionMismatch)) {
        error = 'Couldn’t save your answer. Check your connection and try again.';
        return;
      }
      // A new version went live while the screen was open: show it, and ask again.
      const latest = await loadTermsStatus().catch(() => null);
      if (latest && !latest.requiresAcceptance) {
        busy = 'accept';
        await onaccepted();
        return;
      }
      if (latest) release = latest;
      error = 'The Terms changed while this page was open. Read them again, then agree.';
      return;
    }
    try {
      await onaccepted();
    } catch {
      busy = null;
      error = 'Couldn’t continue. Try again.';
    }
  }

  async function decline() {
    busy = 'decline';
    error = null;
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
      busy = null;
    }
  }
</script>

{#if signedOut}
  <TermsSignedOut {signInHref} {onsignin} />
{:else}
  <TermsAccept
    kind={release.previouslyAccepted ? 'updated' : 'first'}
    {surface}
    {release}
    {email}
    {clientId}
    {appName}
    {busy}
    {error}
    {otherOptions}
    declineNote={`We’ll sign you out. ${declineEffect(origin, appName)}`}
    onaccept={accept}
    ondecline={decline}
  />
{/if}
