<script lang="ts">
  import type { Snippet } from 'svelte';
  import TermsCheckFailed from '$lib/components/auth/terms-check-failed.svelte';
  import TermsStep from '$lib/components/auth/terms-step.svelte';
  import { termsGate } from '$lib/terms-gate';

  // The Terms step as a gate in front of a page (window, pop-up, native sheet) or inside the embedded frame's card,
  // following `termsGate`: when the Terms are owed, the Terms in place of the page; when the status can't be read, Try
  // again. While the status is read a page stays as it is: it loads as it would (its own loaders, focus and state, a
  // sign-in made on it), and the API refuses its account calls until the account has agreed. The frame's card, which
  // has no page behind it, shows a spinner.
  interface Props {
    surface: 'web' | 'native' | 'embed';
    email?: string | null;
    clientId?: string | null;
    appName?: string | null;
    returnTo?: string | null;
    layoutReady?: boolean;
    /** Embedded frame: its session ended (`again`: its sign-in was too old to agree with). */
    onsignedout?: (again: boolean) => void;
    /** The page behind the gate; replaced while the Terms are owed or the status can't be read. */
    children?: Snippet;
  }

  let { surface, email = null, clientId = null, appName = null, returnTo = null, layoutReady = true, onsignedout, children }: Props = $props();

  const phase = $derived($termsGate.phase);
</script>

{#snippet spinner()}
  <svg class="h-6 w-6 animate-spin text-surface-400" fill="none" viewBox="0 0 24 24" aria-hidden="true">
    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
  </svg>
{/snippet}

{#if phase === 'required' && $termsGate.status}
  <TermsStep
    status={$termsGate.status}
    {surface}
    {email}
    {clientId}
    {appName}
    {returnTo}
    {layoutReady}
    onaccepted={() => termsGate.agreed()}
    {onsignedout}
  />
{:else if phase === 'failed'}
  <TermsCheckFailed compact={surface === 'embed'} onretry={() => termsGate.recheck()} />
{:else if children}
  {@render children()}
{:else}
  <div class="flex justify-center py-6" role="status" aria-busy="true" data-testid="terms-checking">
    {@render spinner()}
  </div>
{/if}
