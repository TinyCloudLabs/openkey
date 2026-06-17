<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { copyText } from '$lib/clipboard';
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
  let archiving = $state(false);

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
      const keyId = $page.params.id;
      if (!keyId) {
        error = 'Key not found';
        return;
      }
      const result = await api.getKey(keyId);
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

  async function archiveKey() {
    if (!key) return;

    const confirmed = window.confirm('Archive this key? It will no longer appear during sign-in.');
    if (!confirmed) return;

    archiving = true;
    error = '';
    try {
      await api.archiveKey(key.id);
      goto('/dashboard');
    } catch (e: any) {
      error = e.message || 'Failed to archive key';
    } finally {
      archiving = false;
    }
  }

  async function copyToClipboard(text: string) {
    if (!(await copyText(text))) {
      error = 'Failed to copy value. Select the value and copy it manually.';
      return;
    }

    error = '';
  }
</script>

<div class="mx-auto max-w-3xl px-4 py-8">
  <div class="mb-6">
    <a href="/dashboard" class="text-sm text-surface-500 hover:text-surface-700 transition-colors">
      &larr; Back to Dashboard
    </a>
  </div>

  {#if error}
    <div class="mb-6 rounded-xl border border-red-200 bg-red-50 p-4 text-red-600 text-sm">
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
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h1 class="text-2xl font-bold text-surface-900">
              {key.label || `Key ${key.keyIndex}`}
            </h1>
            <div class="flex flex-wrap items-center gap-2">
              <Button variant="secondary" onclick={() => editingLabel = true}>
                Edit Label
              </Button>
              <Button
                variant="secondary"
                onclick={archiveKey}
                disabled={archiving}
                class="border-red-200 text-red-600 hover:bg-red-50 hover:text-red-700"
              >
                {archiving ? 'Archiving...' : 'Archive Key'}
              </Button>
            </div>
          </div>
        {/if}
      </div>

      <div class="space-y-4">
        <div>
          <p class="mb-1 block text-sm text-surface-500">Address</p>
          <div class="flex items-center gap-2">
            <code class="flex-1 rounded-xl bg-surface-50 border border-surface-200 p-3 font-mono text-sm text-surface-900">
              {key.address}
            </code>
            <Button variant="secondary" onclick={() => copyToClipboard(key!.address)}>
              Copy
            </Button>
          </div>
        </div>

        <div>
          <p class="mb-1 block text-sm text-surface-500">Public Key</p>
          <div class="flex items-center gap-2">
            <code class="flex-1 truncate rounded-xl bg-surface-50 border border-surface-200 p-3 font-mono text-sm text-surface-900">
              {key.publicKey}
            </code>
            <Button variant="secondary" onclick={() => copyToClipboard(key!.publicKey)}>
              Copy
            </Button>
          </div>
        </div>

        <div>
          <p class="mb-1 block text-sm text-surface-500">Created</p>
          <p class="text-surface-900">
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
      <h2 class="mb-4 text-xl font-semibold text-surface-900">Sign Message</h2>

      <div class="space-y-4">
        <div>
          <label for="message" class="mb-1 block text-sm text-surface-500">Message</label>
          <textarea
            id="message"
            bind:value={message}
            placeholder="Enter message to sign..."
            rows={3}
            class="w-full rounded-xl border border-surface-200 bg-white px-3 py-2 text-sm text-surface-900 placeholder:text-surface-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-surface-300 focus-visible:border-surface-400"
          ></textarea>
        </div>

        <Button onclick={signMessage} disabled={signing || !message.trim()}>
          {signing ? 'Signing...' : 'Sign Message'}
        </Button>

        {#if signature}
          <div>
            <p class="mb-1 block text-sm text-surface-500">Signature</p>
            <div class="flex items-start gap-2">
              <code class="flex-1 break-all rounded-xl bg-surface-50 border border-surface-200 p-3 font-mono text-xs text-surface-900">
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
