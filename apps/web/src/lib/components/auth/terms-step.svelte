<script lang="ts">
  import { page } from '$app/stores';
  import TermsAccept from '$lib/components/auth/terms-accept.svelte';
  import TermsSignedOut from '$lib/components/auth/terms-signed-out.svelte';
  import { revokeEmbeddedSession } from '$lib/embed-passkey';
  import { TermsSignInAgain, TermsVersionMismatch, acceptTerms, loadTermsStatus, type TermsStatus } from '$lib/terms';
  import { declineEffect, declineHere, optionsHref, termsOrigin, termsPageFor } from '$lib/terms-leave';

  // TC-3232: the required Terms step, wherever it is shown (its own page, inline in sign-in and sign-up so it
  // comes before the passkey offer, in place of a page, or in the embedded frame's card). Agree records the
  // acceptance, then hands back to the caller. On the web the ways out are on their own pages, reached from the
  // "Other options" box. The native sheet keeps Don't agree here: it says no to the request that brought the
  // account here and signs it out; nothing is deleted. The embedded frame offers Sign out, which ends the
  // frame's session and returns it to its sign-in.
  interface Props {
    status: TermsStatus;
    surface: 'web' | 'native' | 'embed';
    email?: string | null;
    /** The native sheet's OAuth client: branding, and the surface recorded with the acceptance. */
    clientId?: string | null;
    appName?: string | null;
    /** The page the account was on its way to, if any: an approval link or device sign-in is declined too. */
    returnTo?: string | null;
    /** Embedded frame: the host has acknowledged the frame's layout (v2 sign). */
    layoutReady?: boolean;
    /** Runs once the acceptance is recorded; the screen stays busy until it navigates away. */
    onaccepted: () => void | Promise<void>;
    /**
     * Embedded frame: the frame's session ended (Sign out), or its sign-in is too old to agree with (`again`); the
     * frame signs in afresh.
     */
    onsignedout?: (again: boolean) => void;
    /** Where "Sign in" goes after Don't agree; `onsignin` instead when the caller is the sign-in page. */
    signInHref?: string;
    onsignin?: () => void;
  }

  let {
    status, surface, email = null, clientId = null, appName = null, returnTo = null, layoutReady = true,
    onaccepted, onsignedout, signInHref = '/auth/login', onsignin,
  }: Props = $props();

  const origin = $derived(termsOrigin($page.url.search, returnTo));
  const otherOptions = $derived(surface === 'web' ? optionsHref(termsPageFor($page.url.search, returnTo)) : null);

  // svelte-ignore state_referenced_locally
  let release = $state(status);
  let busy = $state<'accept' | 'decline' | null>(null);
  let error = $state<string | null>(null);
  let signedOut = $state(false);

  async function proceed() {
    try {
      await onaccepted();
    } catch {
      busy = null;
      error = 'Couldn’t continue. Try again.';
    }
  }

  async function accept() {
    busy = 'accept';
    error = null;
    try {
      await acceptTerms(release.version ?? '', surface === 'native' ? clientId : null);
    } catch (cause) {
      busy = null;
      if (cause instanceof TermsSignInAgain) {
        // The frame's sign-in is too old to agree with: end that session, and sign in again here.
        await revokeEmbeddedSession();
        onsignedout?.(true);
        return;
      }
      if (!(cause instanceof TermsVersionMismatch)) {
        error = 'Couldn’t save your answer. Check your connection and try again.';
        return;
      }
      // A new version went live while the screen was open: show it, and ask again.
      const latest = await loadTermsStatus().catch(() => null);
      if (latest && !latest.requiresAcceptance) {
        busy = 'accept';
        await proceed();
        return;
      }
      if (latest) release = latest;
      error = 'The Terms changed while this page was open. Read them again, then agree.';
      return;
    }
    await proceed();
  }

  async function decline() {
    busy = 'decline';
    error = null;
    if (surface === 'embed') {
      await revokeEmbeddedSession();
      busy = null;
      onsignedout?.(false);
      return;
    }
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
    {layoutReady}
    declineNote={declineEffect(origin, appName, 'native')}
    onaccept={accept}
    ondecline={decline}
  />
{/if}
