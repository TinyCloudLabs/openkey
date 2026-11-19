<script lang="ts">
  import { authClient } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import TermsAccept from '$lib/components/auth/terms-accept.svelte';
  import { TermsVersionMismatch, acceptTerms, loadTermsStatus, type TermsStatus } from '$lib/terms';

  // TC-3232: the required Terms step, wherever it is shown (its own page, or inline in sign-in and sign-up
  // so it comes before the passkey offer). Agree records the acceptance, then hands back to the caller;
  // Don't agree is a plain sign-out: nothing is deleted.
  interface Props {
    status: TermsStatus;
    surface: 'web' | 'native';
    email: string;
    /** The native sheet's OAuth client: branding, and the surface recorded with the acceptance. */
    clientId?: string | null;
    appName?: string | null;
    /** Runs once the acceptance is recorded; the screen stays busy until it navigates away. */
    onaccepted: () => void | Promise<void>;
    /** Where "Sign in" goes after Don't agree; `onsignin` instead when the caller is the sign-in page. */
    signInHref?: string;
    onsignin?: () => void;
  }

  let { status, surface, email, clientId = null, appName = null, onaccepted, signInHref = '/auth/login', onsignin }: Props = $props();

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
      const result = await authClient.signOut();
      if (result?.error) throw new Error('sign-out failed');
      signedOut = true;
    } catch {
      error = 'Couldn’t sign you out. Try again.';
    } finally {
      busy = null;
    }
  }
</script>

{#if signedOut}
  <div class="flex min-h-screen items-center justify-center bg-surface-50 px-4 py-12">
    <Card class="w-full max-w-md p-8 text-center sm:p-10" data-testid="terms-result">
      <h1 class="mb-2 text-2xl font-bold text-surface-900">You’re signed out</h1>
      <p class="mb-7 text-sm text-surface-500">To use OpenKey again, sign in and agree to the Terms of Service.</p>
      {#if onsignin}
        <Button onclick={onsignin} class="w-full">Sign in</Button>
      {:else}
        <Button href={signInHref} class="w-full">Sign in</Button>
      {/if}
    </Card>
  </div>
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
    onaccept={accept}
    ondecline={decline}
  />
{/if}
