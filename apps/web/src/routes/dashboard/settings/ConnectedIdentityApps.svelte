<script lang="ts">
  import { tick } from 'svelte';
  import { api, type ConnectedIdentityApp } from '$lib/api';
  import { identityAppCopy as text } from '$lib/connected-mcp-apps';
  import Card from '$lib/components/ui/card.svelte';
  let { apps, onchanged }: { apps: ConnectedIdentityApp[]; onchanged: () => void | Promise<void> } = $props();
  let confirming = $state<ConnectedIdentityApp | null>(null);
  let busyId = $state<string | null>(null);
  let notice = $state('');
  let error = $state('');
  let cancelButton = $state<HTMLButtonElement | null>(null);
  let returnFocus: HTMLElement | null = null;

  function request(app: ConnectedIdentityApp) {
    if (busyId) return;
    returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    notice = '';
    error = '';
    confirming = app;
    void tick().then(() => cancelButton?.focus());
  }

  function dismiss() {
    confirming = null;
    void tick().then(() => returnFocus?.focus());
  }

  async function disconnect() {
    const app = confirming;
    if (!app || busyId) return;
    confirming = null;
    busyId = app.consentId;
    try {
      await api.disconnectIdentityApp(app.consentId);
      notice = text.disconnected;
      await onchanged();
    } catch (cause) {
      error = cause instanceof Error && cause.message ? cause.message : text.failed;
    } finally {
      busyId = null;
    }
  }

  function connected(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString(undefined, { dateStyle: 'medium' });
  }
</script>

{#if apps.length > 0}
  <Card id="connected-identity-apps" class="mt-6">
    <h2 class="text-xl font-semibold text-surface-900">{text.title}</h2>
    <p class="mt-1 text-sm text-surface-500">{text.intro}</p>

    {#if notice}<p role="status" class="mt-4 rounded-lg border border-surface-200 bg-surface-50 p-3 text-sm text-surface-700">{notice}</p>{/if}
    {#if error}<p role="alert" class="mt-4 text-sm text-red-600">{error}</p>{/if}

    <ul class="mt-4 flex flex-col gap-3">
      {#each apps as app (app.consentId)}
        <li class="flex flex-col gap-3 rounded-xl border border-surface-200 bg-surface-50 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div class="min-w-0">
            <div class="flex flex-col gap-0.5">
              <span class="font-semibold text-surface-900">{app.name}</span>
              {#if app.host}<span class="text-sm text-surface-500">{app.host}</span>{/if}
            </div>
            {#if connected(app.connectedAt)}
              <p class="mt-1 text-xs text-surface-500">{text.connected} <time datetime={app.connectedAt}>{connected(app.connectedAt)}</time></p>
            {/if}
          </div>
          <button type="button" disabled={busyId === app.consentId} onclick={() => request(app)}
            class="shrink-0 rounded-lg border border-surface-300 bg-white px-3 py-1.5 text-sm font-medium text-surface-700 hover:border-surface-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-surface-900 disabled:cursor-not-allowed disabled:opacity-60"
            aria-label={`${text.disconnect} ${app.name}`}>
            {text.disconnect}
          </button>
        </li>
      {/each}
    </ul>
  </Card>
{:else if notice}
  <p role="status" class="rounded-lg border border-surface-200 bg-surface-50 p-3 text-sm text-surface-700">{notice}</p>
{/if}

{#if confirming}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-surface-900/40 p-4" role="presentation">
    <div class="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl" role="dialog" aria-modal="true" aria-labelledby="identity-disconnect-title" aria-describedby="identity-disconnect-description" tabindex="-1"
      onkeydown={(event) => { if (event.key === 'Escape') { event.preventDefault(); dismiss(); } }}>
      <h2 id="identity-disconnect-title" class="text-xl font-semibold text-surface-900">{text.confirmTitle(confirming.name)}</h2>
      <p id="identity-disconnect-description" class="mt-3 text-sm leading-6 text-surface-600">{text.confirmBody}</p>
      <div class="mt-6 flex justify-end gap-3">
        <button type="button" bind:this={cancelButton} onclick={dismiss}
          class="rounded-lg border border-surface-300 bg-white px-4 py-2 text-sm font-medium text-surface-700 hover:border-surface-400">{text.cancel}</button>
        <button type="button" onclick={disconnect}
          class="rounded-lg bg-surface-900 px-4 py-2 text-sm font-medium text-white hover:bg-surface-800">{text.confirmAction}</button>
      </div>
    </div>
  </div>
{/if}
