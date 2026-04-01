<script lang="ts">
  import { parseSIWE, groupCapabilities, timeUntilExpiry, type ParsedSIWE, type GroupedCapability } from '$lib/siwe-parser';

  interface Props {
    /** The raw message string to parse. */
    message: string;
    /** Optional: override light/dark style. Defaults to 'light'. */
    theme?: 'light' | 'dark';
  }

  let { message, theme = 'light' }: Props = $props();

  let showRaw = $state(false);
  let copied = $state(false);

  let parsed = $derived<ParsedSIWE | null>(parseSIWE(message));
  let grouped = $derived<GroupedCapability[]>(
    parsed?.recap ? groupCapabilities(parsed.recap) : []
  );
  let isSiwe = $derived(parsed !== null);
  let expiry = $derived(parsed?.message.expirationTime ? timeUntilExpiry(parsed.message.expirationTime) : null);

  async function copyMessage() {
    await navigator.clipboard.writeText(message);
    copied = true;
    setTimeout(() => { copied = false; }, 2000);
  }

  function formatDate(iso?: string): string {
    if (!iso) return '';
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  // Theme-aware classes
  let bg = $derived(theme === 'dark' ? 'bg-surface-800' : 'bg-surface-50');
  let border = $derived(theme === 'dark' ? 'border-surface-700' : 'border-surface-200');
  let textPrimary = $derived(theme === 'dark' ? 'text-surface-50' : 'text-surface-900');
  let textSecondary = $derived(theme === 'dark' ? 'text-surface-400' : 'text-surface-500');
  let textMuted = $derived(theme === 'dark' ? 'text-surface-500' : 'text-surface-400');
  let badgeBg = $derived(theme === 'dark' ? 'bg-surface-700' : 'bg-surface-100');
  let rawBg = $derived(theme === 'dark' ? 'bg-surface-900' : 'bg-white');
</script>

{#if isSiwe && parsed}
  <div class="flex flex-col gap-3">
    <!-- Capabilities / permissions -->
    {#if grouped.length > 0}
      <div>
        <div class="text-xs {textMuted} mb-2">Permissions requested</div>
        <div class="flex flex-col gap-2">
          {#each grouped as cap}
            <div class="flex items-start gap-2.5 p-2.5 {bg} border {border} rounded-lg">
              <svg class="w-4 h-4 {textMuted} mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div>
                <div class="text-sm font-medium {textPrimary}">{cap.label}</div>
                {#if cap.resourcePath}
                  <div class="text-xs {textMuted} font-mono mt-0.5">{cap.resourcePath}</div>
                {/if}
                <div class="flex flex-wrap gap-1 mt-1">
                  {#each cap.actions as action}
                    <span class="text-xs px-1.5 py-0.5 rounded {badgeBg} {textSecondary}">{action}</span>
                  {/each}
                </div>
              </div>
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <!-- Expiry -->
    {#if parsed.message.expirationTime}
      <div class="p-3 {bg} border {border} rounded-xl">
        <div class="text-xs {textMuted} mb-1">Expires</div>
        <span class="text-sm {textPrimary}">{formatDate(parsed.message.expirationTime)}</span>
        {#if expiry}
          <div class="text-xs mt-0.5 {expiry.expired ? 'text-amber-500' : textMuted}">{expiry.text}</div>
        {/if}
      </div>
    {/if}

    <!-- Raw message toggle -->
    <div>
      <button
        class="flex items-center gap-1.5 text-xs {textMuted} hover:opacity-80 transition-opacity bg-transparent border-none cursor-pointer p-0"
        onclick={() => showRaw = !showRaw}
      >
        <svg class="w-3.5 h-3.5 transition-transform" class:rotate-90={showRaw} fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
        </svg>
        {showRaw ? 'Hide' : 'View'} raw message
      </button>

      {#if showRaw}
        <div class="mt-2 relative">
          <pre class="p-3 {rawBg} border {border} rounded-xl text-xs font-mono {textSecondary} whitespace-pre-wrap break-all max-h-[200px] overflow-y-auto m-0">{message}</pre>
          <button
            class="absolute top-2 right-2 p-1.5 {bg} border {border} rounded-lg cursor-pointer hover:opacity-80 transition-opacity"
            onclick={copyMessage}
            title="Copy raw message"
          >
            {#if copied}
              <svg class="w-3.5 h-3.5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
              </svg>
            {:else}
              <svg class="w-3.5 h-3.5 {textMuted}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9.75a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
              </svg>
            {/if}
          </button>
        </div>
      {/if}
    </div>
  </div>
{:else}
  <!-- Not a SIWE message - show as plain text with copy -->
  <div class="relative">
    <pre class="p-3 {bg} border {border} rounded-xl text-sm font-mono {textSecondary} whitespace-pre-wrap break-all max-h-[200px] overflow-y-auto m-0">{message}</pre>
    <button
      class="absolute top-2 right-2 p-1.5 {rawBg} border {border} rounded-lg cursor-pointer hover:opacity-80 transition-opacity"
      onclick={copyMessage}
      title="Copy message"
    >
      {#if copied}
        <svg class="w-3.5 h-3.5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
        </svg>
      {:else}
        <svg class="w-3.5 h-3.5 {textMuted}" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9.75a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
        </svg>
      {/if}
    </button>
  </div>
{/if}
