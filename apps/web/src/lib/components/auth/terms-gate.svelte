<script lang="ts">
  import type { Snippet } from 'svelte';
  import TermsCheckFailed from '$lib/components/auth/terms-check-failed.svelte';
  import TermsStep from '$lib/components/auth/terms-step.svelte';
  import { termsGate } from '$lib/terms-gate';
  import { termsCheckedFirst } from '$lib/terms-release';
  import { SESSION_CHECK_TIMEOUT_MS } from '$lib/terms';

  // The Terms step as a gate in front of a page (window, pop-up, native sheet) or inside the embedded frame's card,
  // following `termsGate`: when the Terms are owed, the Terms in place of the page; when the status can't be read, Try
  // again. In a build with a Terms release, a page is not shown until the account's status is known: the gate shows a
  // spinner while the session is read and while the status is read, so the page makes no account call before the read
  // resolves. A session that does not answer within `SESSION_CHECK_TIMEOUT_MS` shows Try again, never the page; Try
  // again reads the session again, and a late answer continues the normal flow. A status read that finds the
  // credential signed out releases the page: that account is signed out, and the API refuses its account calls. The
  // first time the page is shown releases it for good: a later check (a refused call) keeps it mounted, with its own
  // loaders, focus and state. A sign-in made on the page waits for the status only on widget/connect, which loads its
  // keys when the gate is open; widget/sign and widget/sign-typed-data list keys as soon as the session exists, and the
  // API refuses those calls until the account has agreed. A build with no release holds nothing. The frame's card,
  // which has no page behind it, shows a spinner.
  interface Props {
    surface: 'web' | 'native' | 'embed';
    email?: string | null;
    clientId?: string | null;
    appName?: string | null;
    returnTo?: string | null;
    layoutReady?: boolean;
    /** The root layout is still reading whether anyone is signed in. */
    sessionPending?: boolean;
    /** Someone is signed in (the layout's session has an account). */
    signedIn?: boolean;
    /** Reads the session again (Try again after the session did not answer within `SESSION_CHECK_TIMEOUT_MS`). */
    onretrysession?: () => void;
    /** Embedded frame: its session ended (`again`: its sign-in was too old to agree with). */
    onsignedout?: (again: boolean) => void;
    /** The page behind the gate; replaced while the Terms are owed or the status can't be read. */
    children?: Snippet;
  }

  let {
    surface, email = null, clientId = null, appName = null, returnTo = null, layoutReady = true, sessionPending = false, signedIn = false,
    onretrysession, onsignedout, children,
  }: Props = $props();

  const phase = $derived($termsGate.phase);
  // Once the gate has left `idle`, `idle` is a status read that found the credential signed out, not a check yet to start.
  let read = $state(false);
  $effect.pre(() => {
    if (phase !== 'idle') read = true;
  });
  // The page waits while the session or the status is read: a signed-in account whose check has not started yet waits too.
  const waiting = $derived(termsCheckedFirst() && (sessionPending || phase === 'checking' || (signedIn && phase === 'idle' && !read)));
  let released = $state(false);
  $effect.pre(() => {
    if (!waiting) released = true;
  });

  // A session that does not answer within the bound is a failed check (Try again), never the page. Try again asks the
  // layout to read the session again and restarts the bound; a late answer ends the failed state by itself.
  // A store update can leave the session pending. Restart the timer only when the pending flag changes or Try again is clicked.
  const pending = $derived(sessionPending);
  let sessionWaitedOut = $state(false);
  let sessionAttempt = $state(0);
  $effect(() => {
    void sessionAttempt;
    if (!termsCheckedFirst() || !pending || released) {
      sessionWaitedOut = false;
      return;
    }
    const timer = setTimeout(() => { sessionWaitedOut = true; }, SESSION_CHECK_TIMEOUT_MS);
    return () => clearTimeout(timer);
  });
  const sessionFailed = $derived(sessionWaitedOut && sessionPending && !released);
  function retry() {
    if (!sessionFailed) {
      termsGate.recheck();
      return;
    }
    sessionWaitedOut = false;
    sessionAttempt++;
    onretrysession?.();
  }
</script>

{#snippet spinner()}
  <svg class="h-6 w-6 animate-spin text-surface-400" fill="none" viewBox="0 0 24 24" aria-hidden="true">
    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
  </svg>
  <span class="text-sm text-surface-500">Loading</span>
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
{:else if phase === 'failed' || sessionFailed}
  <TermsCheckFailed compact={surface === 'embed'} onretry={retry} />
{:else if children && (released || !waiting)}
  {@render children()}
{:else}
  <div class="flex items-center justify-center gap-3 py-6" role="status" aria-busy="true" data-testid="terms-checking">
    {@render spinner()}
  </div>
{/if}
