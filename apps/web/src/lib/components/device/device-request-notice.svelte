<script lang="ts">
  import { formatDeviceLifetime } from '$lib/device-authorization';

  interface Props {
    nodeOrigin: string;
    shareOrigin: string;
    /** The `/delegate` `expiry` parameter the device page sets, e.g. `2592000s`. */
    expiry: string;
    /** The owner confirmed they started this request; required to approve. */
    acknowledged?: boolean;
  }

  let { nodeOrigin, shareOrigin, expiry, acknowledged = $bindable(false) }: Props = $props();

  const lifetime = $derived.by(() => {
    const seconds = /^(\d+)s$/.exec(expiry)?.[1];
    return seconds ? formatDeviceLifetime(Number(seconds)) : expiry || 'Not specified';
  });
</script>

<section class="flex flex-col gap-3" aria-label="Device request">
  <div class="rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900" role="note">
    <p class="font-semibold">Only approve if you started this on your own device.</p>
    <p class="mt-1 leading-relaxed">
      Approving hands this access to the terminal that showed you the code. If someone else sent you the code or this link, stop here.
    </p>
    <label class="mt-3 flex items-start gap-2 font-medium">
      <input type="checkbox" class="mt-0.5 h-4 w-4" bind:checked={acknowledged} />
      <span>I started this request myself, on a device I control.</span>
    </label>
  </div>
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
