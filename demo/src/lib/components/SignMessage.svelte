<script lang="ts">
  import { openkey, type OpenKeyError } from '$lib/openkey';
  import { cn } from '$lib/utils';

  let message = $state('Hello from OpenKey Demo!');
  let signature = $state<string | null>(null);
  let address = $state<string | null>(null);
  let loading = $state(false);
  let error = $state('');

  async function sign() {
    if (!message.trim()) {
      error = 'Please enter a message to sign';
      return;
    }

    loading = true;
    error = '';
    signature = null;
    address = null;

    try {
      const result = await openkey.signMessage(message);
      signature = result.signature;
      address = result.address;
    } catch (e: unknown) {
      const err = e as OpenKeyError;
      if (err.code === 'POPUP_BLOCKED') {
        error = 'Popup was blocked. Please allow popups for this site and try again.';
      } else if (err.code === 'USER_CANCELLED') {
        error = 'Signing cancelled.';
      } else {
        error = err.message || 'An error occurred while signing';
      }
    } finally {
      loading = false;
    }
  }

  function formatAddress(addr: string): string {
    if (addr.length <= 13) return addr;
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
  }

  function reset() {
    signature = null;
    address = null;
    error = '';
  }
</script>

<div class="bg-surface-900 border border-surface-800 rounded-xl p-6">
  <h2 class="text-xl font-semibold text-surface-50 mb-4">Sign Message</h2>

  <div class="space-y-4">
    <!-- Message Input -->
    <div>
      <label for="message" class="block text-sm font-medium text-surface-400 mb-2">
        Message to sign
      </label>
      <textarea
        id="message"
        bind:value={message}
        rows={4}
        disabled={loading}
        class={cn(
          'w-full rounded-lg border border-surface-700 bg-surface-900 px-3 py-2 text-sm',
          'text-surface-50 placeholder:text-surface-500',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:border-primary-500',
          'disabled:cursor-not-allowed disabled:opacity-50',
          'resize-none'
        )}
        placeholder="Enter a message to sign..."
      ></textarea>
    </div>

    <!-- Sign Button -->
    <button
      onclick={sign}
      disabled={loading || !message.trim()}
      class={cn(
        'w-full inline-flex items-center justify-center rounded-lg font-medium transition-colors',
        'h-11 px-6 text-base',
        'bg-primary-600 text-white hover:bg-primary-700',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-950',
        'disabled:pointer-events-none disabled:opacity-50'
      )}
    >
      {#if loading}
        <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Signing...
      {:else}
        Sign with OpenKey
      {/if}
    </button>

    <!-- Error Display -->
    {#if error}
      <div class="bg-red-500/10 border border-red-500/50 rounded-lg p-4">
        <div class="flex items-start gap-3">
          <svg class="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <p class="text-sm text-red-400">{error}</p>
          </div>
        </div>
      </div>
    {/if}

    <!-- Success Result -->
    {#if signature && address}
      <div class="bg-green-500/10 border border-green-500/50 rounded-lg p-4 space-y-4">
        <div class="flex items-center gap-2">
          <svg class="h-5 w-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
          <span class="text-sm font-medium text-green-400">Message signed successfully</span>
        </div>

        <div>
          <span class="block text-xs uppercase text-surface-400 mb-1">Signed by</span>
          <code class="font-mono text-sm bg-surface-800 px-3 py-2 rounded block text-surface-50">
            {address}
          </code>
        </div>

        <div>
          <span class="block text-xs uppercase text-surface-400 mb-1">Signature</span>
          <code class="font-mono text-sm bg-surface-800 p-3 rounded block break-all text-surface-50 max-h-32 overflow-y-auto">
            {signature}
          </code>
        </div>

        <button
          onclick={reset}
          class={cn(
            'w-full inline-flex items-center justify-center rounded-lg font-medium transition-colors',
            'h-10 px-4',
            'bg-surface-800 text-surface-50 hover:bg-surface-700 border border-surface-700',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500'
          )}
        >
          Sign Another Message
        </button>
      </div>
    {/if}
  </div>
</div>
