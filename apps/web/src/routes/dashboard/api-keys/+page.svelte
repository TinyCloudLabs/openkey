<script lang="ts">
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { secretsApi, type Secret, type Variable } from '$lib/secrets-api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const session = authClient.useSession();

  type PageState = 'loading' | 'not_enabled' | 'enabling' | 'ready' | 'error';
  type Tab = 'secrets' | 'variables';

  let pageState = $state<PageState>('loading');
  let activeTab = $state<Tab>('secrets');
  let error = $state('');

  // Data
  let secrets = $state<Secret[]>([]);
  let variables = $state<Variable[]>([]);

  // Add form state
  let showAddForm = $state(false);
  let addName = $state('');
  let addValue = $state('');
  let adding = $state(false);

  // Edit state
  let editingName = $state<string | null>(null);
  let editValue = $state('');
  let saving = $state(false);

  // Delete state
  let deletingName = $state<string | null>(null);

  $effect(() => {
    if (!$session.isPending) {
      if (!$session.data) {
        goto('/auth/login');
      } else if (pageState === 'loading') {
        loadStatus();
      }
    }
  });

  async function loadStatus() {
    pageState = 'loading';
    error = '';
    try {
      const status = await secretsApi.getStatus();
      if (status.enabled) {
        await loadData();
        pageState = 'ready';
      } else {
        pageState = 'not_enabled';
      }
    } catch (e: any) {
      error = e.message || 'Failed to load status';
      pageState = 'error';
    }
  }

  async function enable() {
    pageState = 'enabling';
    error = '';
    try {
      await secretsApi.enable();
      await loadData();
      pageState = 'ready';
    } catch (e: any) {
      error = e.message || 'Failed to enable API keys';
      pageState = 'error';
    }
  }

  async function loadData() {
    const [secretsResult, variablesResult] = await Promise.all([
      secretsApi.listSecrets(),
      secretsApi.listVariables(),
    ]);
    secrets = secretsResult.secrets;
    variables = variablesResult.variables;
  }

  function resetAddForm() {
    showAddForm = false;
    addName = '';
    addValue = '';
  }

  async function addItem() {
    if (!addName.trim() || !addValue.trim()) return;
    adding = true;
    error = '';
    try {
      if (activeTab === 'secrets') {
        await secretsApi.createSecret(addName.trim(), addValue.trim());
        const result = await secretsApi.listSecrets();
        secrets = result.secrets;
      } else {
        await secretsApi.createVariable(addName.trim(), addValue.trim());
        const result = await secretsApi.listVariables();
        variables = result.variables;
      }
      resetAddForm();
    } catch (e: any) {
      error = e.message || `Failed to create ${activeTab === 'secrets' ? 'secret' : 'variable'}`;
    } finally {
      adding = false;
    }
  }

  function startEdit(name: string, currentValue?: string) {
    editingName = name;
    editValue = currentValue || '';
  }

  function cancelEdit() {
    editingName = null;
    editValue = '';
  }

  async function saveEdit() {
    if (!editingName || !editValue.trim()) return;
    saving = true;
    error = '';
    try {
      if (activeTab === 'secrets') {
        await secretsApi.updateSecret(editingName, editValue.trim());
        const result = await secretsApi.listSecrets();
        secrets = result.secrets;
      } else {
        await secretsApi.updateVariable(editingName, editValue.trim());
        const result = await secretsApi.listVariables();
        variables = result.variables;
      }
      cancelEdit();
    } catch (e: any) {
      error = e.message || `Failed to update ${activeTab === 'secrets' ? 'secret' : 'variable'}`;
    } finally {
      saving = false;
    }
  }

  async function deleteItem(name: string) {
    deletingName = name;
    error = '';
    try {
      if (activeTab === 'secrets') {
        await secretsApi.deleteSecret(name);
        const result = await secretsApi.listSecrets();
        secrets = result.secrets;
      } else {
        await secretsApi.deleteVariable(name);
        const result = await secretsApi.listVariables();
        variables = result.variables;
      }
    } catch (e: any) {
      error = e.message || `Failed to delete ${activeTab === 'secrets' ? 'secret' : 'variable'}`;
    } finally {
      deletingName = null;
    }
  }

  function switchTab(tab: Tab) {
    activeTab = tab;
    resetAddForm();
    cancelEdit();
  }

  function formatDate(date: string): string {
    return new Date(date).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }
</script>

<div class="mx-auto max-w-3xl px-4 py-8">
  <div class="mb-6">
    <a href="/dashboard" class="text-sm text-surface-500 hover:text-surface-700 transition-colors">
      &larr; Back to Dashboard
    </a>
  </div>

  <header class="mb-8">
    <h1 class="text-3xl font-bold text-surface-900">Secrets & Variables</h1>
    <p class="mt-1 text-surface-500">Store and manage secrets and environment variables</p>
  </header>

  {#if error}
    <div class="mb-6 rounded-xl border border-red-200 bg-red-50 p-4 text-red-600 text-sm">
      {error}
      <button onclick={() => error = ''} class="ml-2 text-red-400 hover:text-red-600">×</button>
    </div>
  {/if}

  {#if pageState === 'loading'}
    <Card>
      <div class="py-12 text-center text-surface-400">
        <p>Loading...</p>
      </div>
    </Card>
  {:else if pageState === 'not_enabled' || pageState === 'enabling'}
    <Card>
      <div class="py-12 text-center">
        <div class="mb-4">
          <svg xmlns="http://www.w3.org/2000/svg" class="mx-auto h-12 w-12 text-surface-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
        </div>
        <h2 class="text-xl font-semibold text-surface-900 mb-2">Enable Encrypted Storage</h2>
        <p class="text-surface-500 mb-6 max-w-md mx-auto">
          Store secrets and environment variables with encrypted storage powered by TinyCloud.
        </p>
        <Button onclick={enable} disabled={pageState === 'enabling'}>
          {pageState === 'enabling' ? 'Enabling...' : 'Enable API Keys'}
        </Button>
      </div>
    </Card>
  {:else if pageState === 'error'}
    <Card>
      <div class="py-12 text-center">
        <p class="text-surface-500 mb-4">Something went wrong loading your data.</p>
        <Button onclick={loadStatus}>Retry</Button>
      </div>
    </Card>
  {:else if pageState === 'ready'}
    <!-- Tab bar -->
    <div class="mb-6 flex gap-1 rounded-xl border border-surface-200 bg-surface-50 p-1">
      <button
        onclick={() => switchTab('secrets')}
        class="flex-1 rounded-lg px-4 py-2 text-sm font-medium transition-colors {activeTab === 'secrets' ? 'bg-white text-surface-900 shadow-sm' : 'text-surface-500 hover:text-surface-700'}"
      >
        Secrets ({secrets.length})
      </button>
      <button
        onclick={() => switchTab('variables')}
        class="flex-1 rounded-lg px-4 py-2 text-sm font-medium transition-colors {activeTab === 'variables' ? 'bg-white text-surface-900 shadow-sm' : 'text-surface-500 hover:text-surface-700'}"
      >
        Variables ({variables.length})
      </button>
    </div>

    <!-- Info banner -->
    <div class="mb-6 rounded-xl border border-surface-200 bg-surface-50 p-4 text-sm text-surface-500">
      {#if activeTab === 'secrets'}
        Secrets are encrypted at rest. Values are write-only and cannot be retrieved after creation.
      {:else}
        Variables are stored as plaintext and can be read back. Use secrets for sensitive values.
      {/if}
    </div>

    <Card>
      <div class="mb-6 flex items-center justify-between">
        <h2 class="text-xl font-semibold text-surface-900">
          {activeTab === 'secrets' ? 'Secrets' : 'Variables'}
        </h2>
        {#if !showAddForm}
          <Button onclick={() => showAddForm = true}>
            + Add {activeTab === 'secrets' ? 'Secret' : 'Variable'}
          </Button>
        {/if}
      </div>

      <!-- Add form -->
      {#if showAddForm}
        <div class="mb-6 rounded-xl border border-surface-200 bg-surface-50 p-4">
          <div class="flex flex-col gap-3">
            <div>
              <label for="add-name" class="mb-1 block text-sm text-surface-500">Name</label>
              <Input
                id="add-name"
                bind:value={addName}
                placeholder="e.g. API_KEY"
              />
            </div>
            <div>
              <label for="add-value" class="mb-1 block text-sm text-surface-500">Value</label>
              <Input
                id="add-value"
                bind:value={addValue}
                placeholder="Enter value"
                type={activeTab === 'secrets' ? 'password' : 'text'}
              />
            </div>
            <div class="flex items-center gap-2">
              <Button onclick={addItem} disabled={adding || !addName.trim() || !addValue.trim()}>
                {adding ? 'Adding...' : 'Add'}
              </Button>
              <Button variant="secondary" onclick={resetAddForm}>
                Cancel
              </Button>
            </div>
          </div>
        </div>
      {/if}

      <!-- Items list -->
      {#if activeTab === 'secrets'}
        {#if secrets.length === 0}
          <div class="py-12 text-center text-surface-400">
            <p>No secrets yet. Add your first secret.</p>
          </div>
        {:else}
          <div class="flex flex-col gap-3">
            {#each secrets as secret}
              <div class="flex items-center justify-between rounded-xl border border-surface-200 bg-surface-50 p-4">
                {#if editingName === secret.name}
                  <div class="flex flex-1 items-center gap-2">
                    <span class="font-medium text-surface-900 shrink-0">{secret.name}</span>
                    <Input
                      bind:value={editValue}
                      placeholder="New value"
                      type="password"
                      class="flex-1"
                    />
                    <Button onclick={saveEdit} disabled={saving || !editValue.trim()}>
                      {saving ? 'Saving...' : 'Save'}
                    </Button>
                    <Button variant="secondary" onclick={cancelEdit}>Cancel</Button>
                  </div>
                {:else}
                  <div>
                    <div class="font-semibold text-surface-900">{secret.name}</div>
                    <div class="text-sm text-surface-500">
                      Added {formatDate(secret.createdAt)}{secret.updatedAt ? ` · Updated ${formatDate(secret.updatedAt)}` : ''}
                    </div>
                  </div>
                  <div class="flex items-center gap-2">
                    <button
                      onclick={() => startEdit(secret.name)}
                      class="rounded-lg border border-surface-200 bg-white px-3 py-1.5 text-sm text-surface-500 transition-colors hover:border-surface-300 hover:text-surface-700"
                    >
                      Edit
                    </button>
                    <button
                      onclick={() => deleteItem(secret.name)}
                      disabled={deletingName === secret.name}
                      class="rounded-lg border border-red-200 px-3 py-1.5 text-sm text-red-500 transition-colors hover:border-red-300 hover:bg-red-50 disabled:opacity-50"
                    >
                      {deletingName === secret.name ? 'Deleting...' : 'Delete'}
                    </button>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      {:else}
        {#if variables.length === 0}
          <div class="py-12 text-center text-surface-400">
            <p>No variables yet. Add your first variable.</p>
          </div>
        {:else}
          <div class="flex flex-col gap-3">
            {#each variables as variable}
              <div class="flex items-center justify-between rounded-xl border border-surface-200 bg-surface-50 p-4">
                {#if editingName === variable.name}
                  <div class="flex flex-1 items-center gap-2">
                    <span class="font-medium text-surface-900 shrink-0">{variable.name}</span>
                    <Input
                      bind:value={editValue}
                      placeholder="New value"
                      class="flex-1"
                    />
                    <Button onclick={saveEdit} disabled={saving || !editValue.trim()}>
                      {saving ? 'Saving...' : 'Save'}
                    </Button>
                    <Button variant="secondary" onclick={cancelEdit}>Cancel</Button>
                  </div>
                {:else}
                  <div>
                    <div class="font-semibold text-surface-900">{variable.name}</div>
                    <div class="mt-1 flex items-center gap-2">
                      <code class="rounded bg-surface-100 px-2 py-0.5 font-mono text-sm text-surface-600">{variable.value}</code>
                    </div>
                    <div class="mt-1 text-sm text-surface-500">
                      Added {formatDate(variable.createdAt)}{variable.updatedAt ? ` · Updated ${formatDate(variable.updatedAt)}` : ''}
                    </div>
                  </div>
                  <div class="flex items-center gap-2">
                    <button
                      onclick={() => startEdit(variable.name, variable.value)}
                      class="rounded-lg border border-surface-200 bg-white px-3 py-1.5 text-sm text-surface-500 transition-colors hover:border-surface-300 hover:text-surface-700"
                    >
                      Edit
                    </button>
                    <button
                      onclick={() => deleteItem(variable.name)}
                      disabled={deletingName === variable.name}
                      class="rounded-lg border border-red-200 px-3 py-1.5 text-sm text-red-500 transition-colors hover:border-red-300 hover:bg-red-50 disabled:opacity-50"
                    >
                      {deletingName === variable.name ? 'Deleting...' : 'Delete'}
                    </button>
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      {/if}
    </Card>
  {/if}
</div>
