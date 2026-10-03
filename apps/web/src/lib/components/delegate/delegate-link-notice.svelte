<script lang="ts">
  interface Props {
    /** The TinyCloud node the delegation is activated on. */
    host: string;
    /** False when the node is neither a known TinyCloud node nor on this device. */
    hostRecognized: boolean;
    /** Validated callback URL, or null when the page shows a paste code. */
    callback: string | null;
    /** SIWE Expiration Time of the delegation being reviewed. */
    expiresAt: string;
    /** The owner confirmed they trust an unrecognized node; required to approve. */
    acknowledged?: boolean;
  }

  let { host, hostRecognized, callback, expiresAt, acknowledged = $bindable(false) }: Props = $props();

  const returnsTo = $derived(callback ? new URL(callback).origin : 'This page, as a code to paste');
  const expires = $derived.by(() => {
    const time = Date.parse(expiresAt);
    if (Number.isNaN(time)) return 'Not specified';
    const days = Math.round((time - Date.now()) / (24 * 60 * 60 * 1000));
    const relative = days >= 1 ? ` (in ${days} day${days === 1 ? '' : 's'})` : '';
    return `${new Date(time).toLocaleString()}${relative}`;
  });
</script>

<section class="flex flex-col gap-3" aria-label="Delegation destination">
  {#if !hostRecognized}
    <div class="rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900" role="alert">
      <p class="font-semibold">Unrecognized TinyCloud node</p>
      <p class="mt-1 leading-relaxed">
        This delegation goes to <code class="break-all font-mono text-xs">{host}</code>, which is not a TinyCloud node OpenKey knows.
        That node can use the access you grant until it expires. If someone sent you this link, stop here.
      </p>
      <label class="mt-3 flex items-start gap-2 font-medium">
        <input type="checkbox" class="mt-0.5 h-4 w-4" bind:checked={acknowledged} />
        <span>I run or trust this node.</span>
      </label>
    </div>
  {/if}
  <dl class="grid gap-2 rounded-xl border border-surface-200 bg-surface-50 p-3 text-xs">
    <div class="flex justify-between gap-3">
      <dt class="shrink-0 text-surface-400">Node</dt>
      <dd class="break-all text-right font-mono font-medium text-surface-900">{host}</dd>
    </div>
    <div class="flex justify-between gap-3">
      <dt class="shrink-0 text-surface-400">Returned to</dt>
      <dd class="break-all text-right font-mono text-surface-900">{returnsTo}</dd>
    </div>
    <div class="flex justify-between gap-3">
      <dt class="shrink-0 text-surface-400">Expires</dt>
      <dd class="text-right font-medium text-surface-900">{expires}</dd>
    </div>
  </dl>
</section>
