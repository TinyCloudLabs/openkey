<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const session = authClient.useSession();

  let key = $state<EthereumKey | null>(null);
  let loading = $state(true);
  let error = $state('');

  // Signing state
  let message = $state('');
  let signature = $state('');
  let signing = $state(false);

  // Label editing
  let editingLabel = $state(false);
  let newLabel = $state('');
  let savingLabel = $state(false);

  // Load key when session is ready
  $effect(() => {
    if (!$session.isPending) {
      if (!$session.data) {
        goto('/auth/login');
      } else if (!key && loading) {
        loadKey();
      }
    }
  });

  async function loadKey() {
    loading = true;
    error = '';
    try {
      const result = await api.getKey($page.params.id);
      key = result.key;
      newLabel = key.label || '';
    } catch (e: any) {
      error = e.message || 'Failed to load key';
    } finally {
      loading = false;
    }
  }

  async function signMessage() {
    if (!key || !message.trim()) return;
    signing = true;
    error = '';
    signature = '';
    try {
      const result = await api.signMessage(key.id, message);
      signature = result.signature;
    } catch (e: any) {
      error = e.message || 'Failed to sign message';
    } finally {
      signing = false;
    }
  }

  async function saveLabel() {
    if (!key) return;
    savingLabel = true;
    error = '';
    try {
      await api.updateKey(key.id, newLabel);
      key.label = newLabel;
      editingLabel = false;
    } catch (e: any) {
      error = e.message || 'Failed to update label';
    } finally {
      savingLabel = false;
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
  }
</script>

<div class="mx-auto max-w-3xl px-4 py-8">
  <div class="mb-6">
    <a href="/dashboard" class="text-sm text-surface-400 hover:text-surface-200">
      &larr; Back to Dashboard
    </a>
  </div>

  {#if error}
    <div class="mb-6 rounded-lg border border-red-500/50 bg-red-500/10 p-4 text-red-400">
      {error}
    </div>
  {/if}

  {#if loading}
    <Card>
      <div class="py-12 text-center text-surface-400">
        <p>Loading key...</p>
      </div>
    </Card>
  {:else if key}
    <Card class="mb-6">
      <div class="mb-6">
        {#if editingLabel}
          <div class="flex items-center gap-2">
            <Input
              bind:value={newLabel}
              placeholder="Key label"
              class="flex-1"
            />
            <Button onclick={saveLabel} disabled={savingLabel}>
              {savingLabel ? 'Saving...' : 'Save'}
            </Button>
            <Button variant="secondary" onclick={() => { editingLabel = false; newLabel = key?.label || ''; }}>
              Cancel
            </Button>
          </div>
        {:else}
          <div class="flex items-center justify-between">
            <h1 class="text-2xl font-bold text-surface-50">
              {key.label || `Key ${key.keyIndex}`}
            </h1>
            <Button variant="secondary" onclick={() => editingLabel = true}>
              Edit Label
            </Button>
          </div>
        {/if}
      </div>

      <div class="space-y-4">
        <div>
          <label class="mb-1 block text-sm text-surface-400">Address</label>
          <div class="flex items-center gap-2">
            <code class="flex-1 rounded-lg bg-surface-950 p-3 font-mono text-sm text-surface-200">
              {key.address}
            </code>
            <Button variant="secondary" onclick={() => copyToClipboard(key!.address)}>
              Copy
            </Button>
          </div>
        </div>

        <div>
          <label class="mb-1 block text-sm text-surface-400">Public Key</label>
          <div class="flex items-center gap-2">
            <code class="flex-1 truncate rounded-lg bg-surface-950 p-3 font-mono text-sm text-surface-200">
              {key.publicKey}
            </code>
            <Button variant="secondary" onclick={() => copyToClipboard(key!.publicKey)}>
              Copy
            </Button>
          </div>
        </div>

        <div>
          <label class="mb-1 block text-sm text-surface-400">Created</label>
          <p class="text-surface-200">
            {new Date(key.createdAt).toLocaleDateString(undefined, {
              year: 'numeric',
              month: 'long',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit'
            })}
          </p>
        </div>
      </div>
    </Card>

    <Card>
      <h2 class="mb-4 text-xl font-semibold text-surface-50">Sign Message</h2>

      <div class="space-y-4">
        <div>
          <label for="message" class="mb-1 block text-sm text-surface-400">Message</label>
          <textarea
            id="message"
            bind:value={message}
            placeholder="Enter message to sign..."
            rows={3}
            class="w-full rounded-lg border border-surface-700 bg-surface-900 px-3 py-2 text-sm text-surface-50 placeholder:text-surface-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500"
          ></textarea>
        </div>

        <Button onclick={signMessage} disabled={signing || !message.trim()}>
          {signing ? 'Signing...' : 'Sign Message'}
        </Button>

        {#if signature}
          <div>
            <label class="mb-1 block text-sm text-surface-400">Signature</label>
            <div class="flex items-start gap-2">
              <code class="flex-1 break-all rounded-lg bg-surface-950 p-3 font-mono text-xs text-surface-200">
                {signature}
              </code>
              <Button variant="secondary" onclick={() => copyToClipboard(signature)}>
                Copy
              </Button>
            </div>
          </div>
        {/if}
      </div>
    </Card>
  {:else}
    <Card>
      <div class="py-12 text-center text-surface-400">
        <p>Key not found</p>
      </div>
    </Card>
  {/if}
</div>
