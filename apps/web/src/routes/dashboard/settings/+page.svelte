<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const session = authClient.useSession();

  interface Passkey {
    id: string;
    name: string | null;
    createdAt: Date;
    deviceType: string;
  }

  let passkeys = $state<Passkey[]>([]);
  let loading = $state(true);
  let error = $state('');
  let addingPasskey = $state(false);

  // Edit state
  let editingId = $state<string | null>(null);
  let editName = $state('');
  let saving = $state(false);

  // Delete state
  let deletingId = $state<string | null>(null);

  // Redirect if not logged in, load passkeys when session is ready
  $effect(() => {
    if (!$session.isPending) {
      if (!$session.data) {
        goto('/auth/login');
      } else if (passkeys.length === 0 && loading) {
        loadPasskeys();
      }
    }
  });

  async function loadPasskeys() {
    loading = true;
    error = '';
    try {
      const result = await authClient.passkey.listUserPasskeys();
      if (result.error) {
        error = result.error.message || 'Failed to load passkeys';
      } else {
        passkeys = result.data || [];
      }
    } catch (e: any) {
      error = e.message || 'Failed to load passkeys';
    } finally {
      loading = false;
    }
  }

  async function addPasskey() {
    addingPasskey = true;
    error = '';
    try {
      const result = await authClient.passkey.addPasskey();
      if (result?.error) {
        error = result.error.message || 'Failed to add passkey';
      } else {
        await loadPasskeys();
      }
    } catch (e: any) {
      error = e.message || 'Failed to add passkey';
    } finally {
      addingPasskey = false;
    }
  }

  function startEdit(passkey: Passkey) {
    editingId = passkey.id;
    editName = passkey.name || '';
  }

  function cancelEdit() {
    editingId = null;
    editName = '';
  }

  async function saveEdit() {
    if (!editingId) return;
    saving = true;
    error = '';
    try {
      const result = await authClient.passkey.updatePasskey({
        id: editingId,
        name: editName || 'Unnamed Passkey',
      });
      if (result.error) {
        error = result.error.message || 'Failed to update passkey';
      } else {
        await loadPasskeys();
        cancelEdit();
      }
    } catch (e: any) {
      error = e.message || 'Failed to update passkey';
    } finally {
      saving = false;
    }
  }

  async function deletePasskey(id: string) {
    if (passkeys.length === 1) {
      error = 'Cannot delete your only passkey. Add another one first.';
      deletingId = null;
      return;
    }

    deletingId = id;
    error = '';
    try {
      const result = await authClient.passkey.deletePasskey({ id });
      if (result.error) {
        error = result.error.message || 'Failed to delete passkey';
      } else {
        await loadPasskeys();
      }
    } catch (e: any) {
      error = e.message || 'Failed to delete passkey';
    } finally {
      deletingId = null;
    }
  }

  function formatDate(date: Date | string): string {
    return new Date(date).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }

  function getDeviceIcon(deviceType: string): string {
    return deviceType === 'multiDevice' ? '☁️' : '🔐';
  }

  function getDeviceLabel(deviceType: string): string {
    return deviceType === 'multiDevice' ? 'Synced' : 'Device-bound';
  }
</script>

<div class="mx-auto max-w-3xl px-4 py-8">
  <div class="mb-6">
    <a href="/dashboard" class="text-sm text-surface-500 hover:text-surface-700 transition-colors">
      &larr; Back to Dashboard
    </a>
  </div>

  <header class="mb-8">
    <h1 class="text-3xl font-bold text-surface-900">Settings</h1>
    <p class="mt-1 text-surface-500">Manage your account and security</p>
  </header>

  {#if error}
    <div class="mb-6 rounded-xl border border-red-200 bg-red-50 p-4 text-red-600 text-sm">
      {error}
      <button onclick={() => error = ''} class="ml-2 text-red-400 hover:text-red-600">×</button>
    </div>
  {/if}

  <Card>
    <div class="mb-6 flex items-center justify-between">
      <div>
        <h2 class="text-xl font-semibold text-surface-900">Passkeys</h2>
        <p class="text-sm text-surface-500 mt-1">
          Passkeys let you sign in securely without a password
        </p>
      </div>
      <Button onclick={addPasskey} disabled={addingPasskey}>
        {addingPasskey ? 'Adding...' : '+ Add Passkey'}
      </Button>
    </div>

    {#if loading}
      <div class="py-12 text-center text-surface-400">
        <p>Loading passkeys...</p>
      </div>
    {:else if passkeys.length === 0}
      <div class="py-12 text-center text-surface-400">
        <p>No passkeys enrolled. Add one to secure your account.</p>
      </div>
    {:else}
      <div class="flex flex-col gap-3">
        {#each passkeys as passkey}
          <div class="flex items-center justify-between rounded-xl border border-surface-200 bg-surface-50 p-4">
            <div class="flex-1">
              {#if editingId === passkey.id}
                <div class="flex items-center gap-2">
                  <Input
                    bind:value={editName}
                    placeholder="Passkey name"
                    class="flex-1"
                  />
                  <Button onclick={saveEdit} disabled={saving}>
                    {saving ? 'Saving...' : 'Save'}
                  </Button>
                  <Button variant="secondary" onclick={cancelEdit}>
                    Cancel
                  </Button>
                </div>
              {:else}
                <div class="flex items-center gap-2">
                  <span class="text-lg" title={getDeviceLabel(passkey.deviceType)}>
                    {getDeviceIcon(passkey.deviceType)}
                  </span>
                  <div>
                    <div class="font-semibold text-surface-900">
                      {passkey.name || 'Unnamed Passkey'}
                    </div>
                    <div class="text-sm text-surface-500">
                      Added {formatDate(passkey.createdAt)} · {getDeviceLabel(passkey.deviceType)}
                    </div>
                  </div>
                </div>
              {/if}
            </div>

            {#if editingId !== passkey.id}
              <div class="flex items-center gap-2">
                <button
                  onclick={() => startEdit(passkey)}
                  class="rounded-lg border border-surface-200 bg-white px-3 py-1.5 text-sm text-surface-500 transition-colors hover:border-surface-300 hover:text-surface-700"
                >
                  Rename
                </button>
                <button
                  onclick={() => deletePasskey(passkey.id)}
                  disabled={deletingId === passkey.id}
                  class="rounded-lg border border-red-200 px-3 py-1.5 text-sm text-red-500 transition-colors hover:border-red-300 hover:bg-red-50 disabled:opacity-50"
                >
                  {deletingId === passkey.id ? 'Deleting...' : 'Delete'}
                </button>
              </div>
            {/if}
          </div>
        {/each}
      </div>

      {#if passkeys.length === 1}
        <p class="mt-4 text-sm text-surface-500">
          Tip: Add multiple passkeys on different devices so you always have a backup way to sign in.
        </p>
      {/if}
    {/if}
  </Card>

  <Card class="mt-6">
    <h2 class="text-xl font-semibold text-surface-900 mb-4">Account</h2>
    <div class="flex items-center justify-between">
      <div>
        <div class="text-surface-900">{$session.data?.user.email}</div>
        <div class="text-sm text-surface-500">Email address</div>
      </div>
    </div>
  </Card>
</div>
