<script lang="ts">
  import { getContext } from 'svelte';
  import { page } from '$app/stores';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';
  import { api, type ConsoleCredential } from '$lib/api';
  import { copyText } from '$lib/clipboard';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  const { overview, refresh } = getContext<ConsoleShellContext>(CONSOLE_SHELL);
  let currentOrganizationId = $derived($page.params.organizationId ?? '');

  let credentials = $state<ConsoleCredential[]>([]);
  let loading = $state(true);
  let error = $state('');
  let createError = $state('');
  let createLoading = $state(false);
  let revokeLoading = $state('');
  let rotateLoading = $state('');
  let loadedFor = $state('');

  let name = $state('');
  let secretReveal = $state<{ credential: ConsoleCredential; secret: string } | null>(null);
  let rotateReveal = $state<{ credential: ConsoleCredential; secret: string } | null>(null);
  let copyState = $state<'idle' | 'copied' | 'failed'>('idle');
  let acknowledged = $state(false);

  async function loadCredentials() {
    loading = true;
    error = '';
    try {
      const result = await api.listConsoleCredentials(currentOrganizationId);
      credentials = result.credentials;
    } catch (caught: any) {
      error = caught.message || 'Could not load credentials.';
    } finally {
      loading = false;
    }
  }

  function beginCreate() {
    name = '';
    createError = '';
  }

  async function createCredential() {
    createLoading = true;
    createError = '';
    if (!name.trim()) {
      createError = 'Enter a credential name.';
      createLoading = false;
      return;
    }
    try {
      const result = await api.createConsoleCredential(currentOrganizationId, { name: name.trim() });
      secretReveal = { credential: result.credential, secret: result.secret };
      rotateReveal = null;
      acknowledged = false;
      copyState = 'idle';
      beginCreate();
      await Promise.all([loadCredentials(), refresh()]);
    } catch (caught: any) {
      createError = caught.message || 'Could not create the credential.';
    } finally {
      createLoading = false;
    }
  }

  async function copySecret(reveal: { credential: ConsoleCredential; secret: string } | null = secretReveal) {
    if (!reveal) return;
    const copied = await copyText(reveal.secret);
    copyState = copied ? 'copied' : 'failed';
  }

  async function rotateCredential(credential: ConsoleCredential) {
    if (!confirm(`Rotate ${credential.name}? A replacement secret will be issued and the current secret will be revoked immediately. Update every client now; clients still using the old secret will lose access.`)) return;
    rotateLoading = credential.id;
    error = '';
    try {
      const result = await api.rotateConsoleCredential(currentOrganizationId, credential.id);
      rotateReveal = { credential: result.credential, secret: result.secret };
      secretReveal = null;
      acknowledged = false;
      copyState = 'idle';
      await Promise.all([loadCredentials(), refresh()]);
    } catch (caught: any) {
      error = caught.message || 'Could not rotate the credential.';
    } finally {
      rotateLoading = '';
    }
  }

  async function revokeCredential(credential: ConsoleCredential) {
    if (!confirm(`Revoke ${credential.name}? This cannot be undone.`)) return;
    revokeLoading = credential.id;
    error = '';
    try {
      await api.revokeConsoleCredential(currentOrganizationId, credential.id);
      await Promise.all([loadCredentials(), refresh()]);
    } catch (caught: any) {
      error = caught.message || 'Could not revoke the credential.';
    } finally {
      revokeLoading = '';
    }
  }

  $effect(() => {
    const orgId = currentOrganizationId;
    if (loadedFor !== orgId) {
      loadedFor = orgId;
      void loadCredentials();
      beginCreate();
      secretReveal = null;
      rotateReveal = null;
      acknowledged = false;
    }
  });
</script>

<svelte:head>
  <title>Credentials · OpenKey Console</title>
</svelte:head>

<div class="space-y-6">
  <Card class="space-y-4">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Server credentials</p>
        <h1 class="mt-2 text-3xl font-semibold tracking-[-0.04em] text-surface-900">One-time secrets, no second look</h1>
        <p class="mt-3 max-w-2xl text-sm leading-6 text-surface-600">
          The secret appears exactly once at creation time. It is never returned by the list API, so the browser should treat it like a temporary export window, not a durable secret store.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">
          { $overview?.usage.credentials ?? credentials.length } credentials
        </span>
        <span class="rounded-full border border-primary-200 bg-primary-50 px-3 py-1 text-xs font-semibold text-primary-700">
          { $overview?.organization.role ?? 'MEMBER' }
        </span>
      </div>
    </div>
  </Card>

  {#if error}
    <Card class="border-red-200 bg-red-50/60">
      <p class="text-sm font-medium text-red-700">{error}</p>
    </Card>
  {/if}

  {#if secretReveal}
    <Card class="space-y-4 border-primary-200 bg-primary-50/60">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-700">One-time secret</p>
          <h2 class="mt-2 text-lg font-semibold tracking-[-0.03em] text-surface-900">{secretReveal.credential.name}</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            Copy this secret now. It cannot be fetched again after this panel is dismissed.
          </p>
        </div>
        <span class="rounded-full border border-primary-200 bg-white px-3 py-1 text-xs font-semibold text-primary-700">
          {secretReveal.credential.kind}
        </span>
      </div>

      <div class="rounded-2xl border border-dotted border-surface-200 bg-white p-4">
        <div class="flex items-center justify-between gap-3">
          <code class="break-all font-mono text-sm text-surface-900">{secretReveal.secret}</code>
          <Button variant="secondary" type="button" onclick={() => void copySecret()}>
            {copyState === 'copied' ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </div>

      <div class="rounded-2xl border border-surface-200 bg-white p-4 text-sm leading-6 text-surface-600">
        <strong class="text-surface-900">Warning:</strong> this secret will not be shown again in the credential list, search results, or browser storage.
      </div>

      <div class="flex flex-wrap gap-2">
        <Button
          type="button"
          disabled={acknowledged}
          onclick={() => {
            acknowledged = true;
            secretReveal = null;
          }}
        >
          {acknowledged ? 'Acknowledged' : 'I saved this secret'}
        </Button>
        <Button variant="secondary" type="button" onclick={() => { secretReveal = null; }}>
          Dismiss
        </Button>
      </div>
    </Card>
  {/if}

  {#if rotateReveal}
    <Card class="space-y-4 border-amber-200 bg-amber-50/60">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.12em] text-amber-700">Rotated secret</p>
          <h2 class="mt-2 text-lg font-semibold tracking-[-0.03em] text-surface-900">{rotateReveal.credential.name}</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            This rotation created a replacement secret for the same management credential. Save it now; it will not be shown again.
          </p>
        </div>
        <span class="rounded-full border border-amber-200 bg-white px-3 py-1 text-xs font-semibold text-amber-700">
          {rotateReveal.credential.kind}
        </span>
      </div>

      <div class="rounded-2xl border border-dotted border-surface-200 bg-white p-4">
        <div class="flex items-center justify-between gap-3">
          <code class="break-all font-mono text-sm text-surface-900">{rotateReveal.secret}</code>
          <Button variant="secondary" type="button" onclick={() => void copySecret(rotateReveal)}>
            {copyState === 'copied' ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </div>

      <div class="rounded-2xl border border-surface-200 bg-white p-4 text-sm leading-6 text-surface-600">
        <strong class="text-surface-900">Immediate invalidation:</strong> the old secret was revoked when this replacement was created. Update every client to use the new secret now.
      </div>

      <div class="flex flex-wrap gap-2">
        <Button
          type="button"
          disabled={acknowledged}
          onclick={() => {
            acknowledged = true;
            rotateReveal = null;
          }}
        >
          {acknowledged ? 'Acknowledged' : 'I saved this rotated secret'}
        </Button>
        <Button variant="secondary" type="button" onclick={() => { rotateReveal = null; }}>
          Dismiss
        </Button>
      </div>
    </Card>
  {/if}

  {#if $overview?.organization.role === 'ADMIN'}
    <Card class="space-y-5">
      <div class="flex items-start justify-between gap-4">
        <div>
          <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Create credential</h2>
          <p class="mt-1 text-sm leading-6 text-surface-600">
            Create the single management credential for this organization. It can create, sign, disable, restore, rotate, and revoke.
          </p>
        </div>
        <span class="rounded-full border border-surface-200 bg-surface-50 px-3 py-1 text-xs font-semibold text-surface-600">
          Admin only
        </span>
      </div>

      <form class="grid gap-4 lg:grid-cols-[1fr_auto]" onsubmit={(event) => { event.preventDefault(); void createCredential(); }}>
        <div class="space-y-2">
          <label class="text-sm font-semibold text-surface-900" for="credential-name">Credential name</label>
          <Input id="credential-name" bind:value={name} placeholder="First-run provisioner" required />
        </div>
        <div class="flex items-end gap-2">
          <Button type="submit" disabled={createLoading}>{createLoading ? 'Creating...' : 'Create credential'}</Button>
          <Button type="button" variant="secondary" onclick={beginCreate}>Reset</Button>
        </div>
        {#if createError}
          <div class="lg:col-span-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{createError}</div>
        {/if}
      </form>
    </Card>
  {:else}
    <Card class="border-surface-200 bg-surface-50">
      <p class="text-sm leading-6 text-surface-600">
        You can inspect the credential list, but creation and revocation stay hidden because this session is a member.
      </p>
    </Card>
  {/if}

  <Card class="space-y-4">
    <div class="flex items-center justify-between gap-3">
      <div>
        <h2 class="text-lg font-semibold tracking-[-0.03em] text-surface-900">Credential list</h2>
        <p class="mt-1 text-sm leading-6 text-surface-600">Only the prefix and timestamps are listed after creation. The secret itself never comes back.</p>
      </div>
      <Button variant="secondary" onclick={() => void loadCredentials()}>Reload</Button>
    </div>

    {#if loading}
      <div class="space-y-3" aria-label="Loading credentials">
        <div class="h-20 rounded-2xl bg-surface-100"></div>
        <div class="h-20 rounded-2xl bg-surface-100"></div>
      </div>
    {:else if credentials.length === 0}
      <div class="rounded-2xl border border-dotted border-surface-200 bg-surface-50 p-6">
        <h3 class="text-base font-semibold text-surface-900">No credentials yet</h3>
        <p class="mt-2 max-w-2xl text-sm leading-6 text-surface-600">
          Create the first credential to start signing the management requests for this organization.
        </p>
      </div>
    {:else}
      <div class="space-y-3">
        {#each credentials as credential}
          <article class="rounded-2xl border border-surface-200 bg-white p-4">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div class="flex flex-wrap items-center gap-2">
                  <h3 class="text-base font-semibold text-surface-900">{credential.name}</h3>
                  <span class="rounded-full border border-primary-200 bg-primary-50 px-2.5 py-1 text-xs font-semibold text-primary-700">{credential.kind}</span>
                  {#if credential.revokedAt}
                    <span class="rounded-full border border-surface-200 bg-surface-50 px-2.5 py-1 text-xs font-semibold text-surface-600">Revoked</span>
                  {/if}
                </div>
                <p class="mt-2 font-mono text-xs text-surface-500 break-all">{credential.secretPrefix}</p>
                <p class="mt-2 text-sm leading-6 text-surface-600">
                  Created at {new Date(credential.createdAt).toLocaleString()}.
                  {#if credential.lastUsedAt}
                    Last used at {new Date(credential.lastUsedAt).toLocaleString()}.
                  {:else}
                    Not used yet.
                  {/if}
                </p>
              </div>
              <div class="flex flex-wrap gap-2">
                {#if $overview?.organization.role === 'ADMIN' && !credential.revokedAt}
                  <Button variant="secondary" type="button" onclick={() => void rotateCredential(credential)} disabled={rotateLoading === credential.id}>
                    {rotateLoading === credential.id ? 'Rotating...' : 'Rotate'}
                  </Button>
                  <Button variant="secondary" type="button" onclick={() => void revokeCredential(credential)} disabled={revokeLoading === credential.id}>
                    {revokeLoading === credential.id ? 'Revoking...' : 'Revoke'}
                  </Button>
                {/if}
              </div>
            </div>
          </article>
        {/each}
      </div>
    {/if}
  </Card>
</div>
