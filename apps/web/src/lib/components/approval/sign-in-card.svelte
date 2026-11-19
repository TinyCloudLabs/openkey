<script lang="ts">
  // The sign-in card every approval page shows when nobody is signed in: email, Google, Apple and passkey,
  // and the small window states of Google and Apple. It owns the social sign-in; the page owns the passkey call.
  import { onMount } from 'svelte';
  import Icon from '$lib/components/approval/icon.svelte';
  import { focusHeading } from '$lib/components/approval/focus-heading';
  import SocialButtons from '$lib/components/auth/social-buttons.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import {
    SocialPopupClosedError,
    loadConfiguredSocialProviders,
    signInWithSocialPopup,
    type SocialPopupHandle,
    type SocialProviderId,
  } from '$lib/social-auth';
  import { socialProviderName } from '$lib/social-continuation';
  import { SIGN_IN, fill } from '@openkey/sdk/approval-copy';

  interface Props {
    emailHref: string;
    registerHref: string;
    recoverHref?: string;
    /** A failure from the page's own sign-in (the passkey). A Google or Apple failure shown here takes its place. */
    error?: string;
    /** The passkey sign-in is running. */
    signingIn?: boolean;
    /** The session ended part-way: the heading and line say so instead of the first-visit words. */
    signedOut?: boolean;
    onPasskey: () => void | Promise<void>;
    /** Any sign-in is starting; the page clears its own error. */
    onBegin?: () => void;
    /** When set, "Cancel this request" shows under the links. */
    onCancel?: () => void;
    /** Google or Apple finished signing in. */
    onSignedIn?: () => void;
  }

  let {
    emailHref,
    registerHref,
    recoverHref = '/auth/recover',
    error = '',
    signingIn = false,
    signedOut = false,
    onPasskey,
    onBegin,
    onCancel,
    onSignedIn,
  }: Props = $props();

  let providers = $state<SocialProviderId[]>([]);
  let provider = $state<SocialProviderId | null>(null);
  // The small window, once it is open. While it is, the card shows the waiting state.
  let waiting = $state<{ provider: SocialProviderId; window: SocialPopupHandle } | null>(null);
  let socialError = $state('');
  // Each Google or Apple attempt gets a number, so a window the person dismissed cannot report back later.
  let attempt = 0;
  let dismissed = -1;

  onMount(async () => {
    providers = await loadConfiguredSocialProviders().catch(() => []);
  });

  const busy = $derived(signingIn || provider !== null);
  const shownError = $derived(socialError || error);

  // Google and Apple sign in through a popup, so the page and anything after the # in its link stay in place.
  async function signInWithSocial(chosen: SocialProviderId) {
    const mine = ++attempt;
    const name = socialProviderName(chosen);
    provider = chosen;
    socialError = '';
    onBegin?.();
    try {
      await signInWithSocialPopup(chosen, undefined, undefined, (popup) => {
        if (mine === attempt) waiting = { provider: chosen, window: popup };
      });
      onSignedIn?.();
    } catch (cause) {
      if (dismissed === mine) return;
      socialError = cause instanceof SocialPopupClosedError
        ? fill(SIGN_IN.popupCancelled, { provider: name })
        : cause instanceof Error && cause.message ? cause.message : `${name} sign-in failed`;
    } finally {
      if (mine === attempt) {
        provider = null;
        waiting = null;
      }
    }
  }

  function signInAnotherWay() {
    dismissed = attempt;
    waiting?.window.close();
    waiting = null;
    provider = null;
    socialError = '';
  }

  async function signInWithPasskey() {
    socialError = '';
    onBegin?.();
    await onPasskey();
  }
</script>

{#if waiting}
  {@const name = socialProviderName(waiting.provider)}
  <p class="m-0 mb-2.5 text-[11.5px] font-semibold tracking-[0.09em] text-surface-500 uppercase">{SIGN_IN.eyebrow}</p>
  <h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{fill(SIGN_IN.popupOpen.heading, { provider: name })}</h1>
  <p class="m-0 mb-3.5 text-pretty">{fill(SIGN_IN.popupOpen.line, { provider: name })}</p>
  <div role="status" class="flex items-center gap-3 rounded-[13px] border border-surface-300 bg-white px-[13px] py-[11px]">
    <span class="h-4 w-4 flex-none animate-spin rounded-full border-2 border-surface-300 border-t-surface-950" aria-hidden="true"></span>
    <span class="text-sm text-surface-950">{fill(SIGN_IN.popupOpen.status, { provider: name })}</span>
  </div>
  <div class="mt-5 grid gap-2.5">
    <Button variant="secondary" class="w-full" onclick={() => waiting?.window.focus()}>{fill(SIGN_IN.popupOpen.show, { provider: name })}</Button>
    <Button variant="ghost" class="w-full" onclick={signInAnotherWay}>{SIGN_IN.popupOpen.other}</Button>
  </div>
{:else}
  <p class="m-0 mb-2.5 text-[11.5px] font-semibold tracking-[0.09em] text-surface-500 uppercase">{SIGN_IN.eyebrow}</p>
  <h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{signedOut ? SIGN_IN.signedOutPartway.heading : SIGN_IN.heading}</h1>
  {#if shownError}
    <div role="alert" class="mt-0.5 mb-3.5 grid grid-cols-[16px_1fr] gap-[9px] rounded-[11px] border border-red-line bg-red-wash px-3 py-[9px] text-[13.5px] leading-[1.45] text-[#7a1a12]">
      <Icon name="alert" class="mt-0.5 h-4 w-4" />
      <span>{shownError}</span>
    </div>
  {:else}
    <p class="m-0 mb-3.5 text-pretty">{signedOut ? SIGN_IN.signedOutPartway.line : SIGN_IN.line}</p>
  {/if}

  <div class="mt-1.5 grid gap-2.5">
    <Button onclick={() => { window.location.href = emailHref; }} disabled={busy} class="w-full">{SIGN_IN.email}</Button>
    {#if providers.length > 0}
      <SocialButtons {providers} loadingProvider={provider} disabled={busy} onsignin={signInWithSocial} />
    {/if}
    <Button variant="secondary" onclick={signInWithPasskey} disabled={busy} class="w-full">
      {signingIn ? SIGN_IN.passkeyBusy : SIGN_IN.passkey}
    </Button>
  </div>
  <p class="m-0 mt-4 text-center text-[13px] leading-normal text-surface-500">
    {SIGN_IN.newToOpenKey}
    <a href={registerHref} class="font-medium text-surface-700 underline underline-offset-2">{SIGN_IN.createAccount}</a>
    ·
    <a href={recoverHref} class="font-medium text-surface-700 underline underline-offset-2">{SIGN_IN.recover}</a>
  </p>
  {#if onCancel}
    <div class="mt-5 grid">
      <Button variant="ghost" class="w-full" onclick={onCancel}>{SIGN_IN.cancel}</Button>
    </div>
  {/if}
{/if}
