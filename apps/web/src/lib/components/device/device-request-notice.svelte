<script lang="ts">
  import { formatDeviceLifetime } from '$lib/device-authorization';

  interface Props {
    nodeOrigin: string;
    shareOrigin: string;
    /** The `/delegate` `expiry` parameter the device page sets, e.g. `2592000s`. */
    expiry: string;
  }

  let { nodeOrigin, shareOrigin, expiry }: Props = $props();

  const lifetime = $derived.by(() => {
    const seconds = /^(\d+)s$/.exec(expiry)?.[1];
    return seconds ? formatDeviceLifetime(Number(seconds)) : expiry || 'Not specified';
  });
</script>

<section class="flex flex-col gap-3" aria-label="Device request">
  <dl class="grid gap-2 rounded-xl border border-surface-200 bg-surface-50 p-3 text-xs">
    <div class="flex justify-between gap-3">
      <dt class="text-surface-400">Lifetime</dt>
      <dd class="font-medium text-surface-900">{lifetime}</dd>
    </div>
    <div class="flex justify-between gap-3">
      <dt class="shrink-0 text-surface-400">Node</dt>
      <dd class="break-all text-right font-mono text-surface-900">{nodeOrigin}</dd>
    </div>
    <div class="flex justify-between gap-3">
      <dt class="shrink-0 text-surface-400">Share</dt>
      <dd class="break-all text-right font-mono text-surface-900">{shareOrigin}</dd>
    </div>
  </dl>
  <p class="text-xs leading-relaxed text-surface-500">
    Every requested capability is listed below. Uncheck any optional one you do not want to grant; the CLI receives exactly what you approve.
    Capabilities marked required cannot be unchecked.
  </p>
</section>
