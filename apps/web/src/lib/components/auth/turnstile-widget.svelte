<script lang="ts">
  import { onMount } from 'svelte';
  import { loadTurnstile, turnstileSiteKey, TURNSTILE_ACTION, type TurnstileApi } from '$lib/turnstile';

  // TC-1632: Cloudflare Turnstile check shown only on the new-account step.
  // Each token is single-use: the parent calls reset() after every attempt.
  // Without a site key or script, the check is unavailable and the parent's
  // create button stays disabled (fail closed).
  interface Props {
    onverify: (token: string) => void;
    onexpire: () => void;
    /** Challenge failed or timed out; the parent offers a retry on the same screen. */
    onerror: () => void;
  }

  let { onverify, onexpire, onerror }: Props = $props();

  const siteKey = turnstileSiteKey();
  let container = $state<HTMLDivElement>();
  let unavailable = $state(!siteKey);
  let api: TurnstileApi | null = null;
  let widgetId: string | null = null;

  onMount(() => {
    if (!siteKey) return;
    let active = true;
    loadTurnstile()
      .then((turnstile) => {
        if (!active || !container) return;
        api = turnstile;
        widgetId = turnstile.render(container, {
          sitekey: siteKey,
          action: TURNSTILE_ACTION,
          appearance: 'interaction-only',
          callback: onverify,
          'expired-callback': onexpire,
          'error-callback': onerror,
          'timeout-callback': onerror,
        });
      })
      .catch(() => {
        unavailable = true;
      });
    return () => {
      active = false;
      if (api && widgetId) api.remove(widgetId);
      api = null;
      widgetId = null;
    };
  });

  export function reset() {
    if (api && widgetId) api.reset(widgetId);
  }
</script>

<div class="flex w-full justify-center" data-testid="turnstile-widget">
  {#if unavailable}
    <p class="text-sm text-red-600" role="alert">Verification is unavailable right now. Try again shortly.</p>
  {:else}
    <div bind:this={container}></div>
  {/if}
</div>
