<script lang="ts">
  import { tick } from 'svelte';
  import { api, type TinyCloudManageKeyApp } from '$lib/api';
  import { tinyCloudDisconnectCopy as text } from '$lib/connected-tinycloud-apps';
  import Button from '$lib/components/ui/button.svelte';

  // The TinyCloud signing apps that can be disconnected, with Settings' typed confirmation and nothing
  // else: the ways-out page offers no allow or block.
  let { apps, onchanged }: { apps: TinyCloudManageKeyApp[]; onchanged: () => void | Promise<void> } = $props();
  let confirming = $state<TinyCloudManageKeyApp | null>(null);
  let typed = $state('');
  let busyId = $state<string | null>(null);
  let error = $state('');
  let input = $state<HTMLInputElement | null>(null);
  let returnFocus: HTMLElement | null = null;

  function request(app: TinyCloudManageKeyApp) {
    if (busyId) return;
    returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    error = '';
    typed = '';
    confirming = app;
    void tick().then(() => input?.focus());
  }

  function dismiss() {
    confirming = null;
    typed = '';
    void tick().then(() => returnFocus?.focus());
  }

  async function disconnect() {
    const app = confirming;
    if (!app || typed !== text.confirmation || busyId) return;
    dismiss();
    busyId = app.clientId;
    try {
      await api.disconnectTinyCloudApp(app.clientId);
      await onchanged();
    } catch (cause) {
      error = cause instanceof Error && cause.message ? cause.message : text.failed;
    } finally {
      busyId = null;
    }
  }
</script>

{#if error}<p role="alert" class="mt-4 text-sm text-red-600">{error}</p>{/if}
{#if apps.length === 0}
  <p class="py-4 text-sm text-surface-500">{text.empty}</p>
{/if}
<ul class="mt-4 flex flex-col gap-3">
  {#each apps as app (app.clientId)}
    <li class="flex flex-col gap-3 rounded-xl border border-surface-200 bg-surface-50 p-4 sm:flex-row sm:items-center sm:justify-between">
      <div class="min-w-0">
        <div class="flex items-center gap-2">
          {#if app.icon}<img src={app.icon} alt="" class="h-6 w-6 rounded" />{/if}
          <span class="truncate font-semibold text-surface-900">{app.name}</span>
        </div>
        {#if app.uri}<p class="mt-1 truncate text-sm text-surface-500">{app.uri}</p>{/if}
      </div>
      <button type="button" disabled={busyId === app.clientId} onclick={() => request(app)}
        class="shrink-0 rounded-lg border border-surface-300 bg-white px-3 py-1.5 text-sm font-medium text-surface-700 hover:border-surface-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-surface-900 disabled:cursor-not-allowed disabled:opacity-60"
        aria-label={`${text.disconnect} ${app.name}`}>
        {text.disconnect}
      </button>
    </li>
  {/each}
</ul>

{#if confirming}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-surface-900/40 p-4" role="presentation">
    <div class="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl" role="dialog" aria-modal="true" aria-labelledby="tinycloud-disconnect-title" aria-describedby="tinycloud-disconnect-description" tabindex="-1"
      onkeydown={(event) => { if (event.key === 'Escape') { event.preventDefault(); dismiss(); } }}>
      <h2 id="tinycloud-disconnect-title" class="text-xl font-semibold text-surface-900">{text.title(confirming.name)}</h2>
      <p id="tinycloud-disconnect-description" class="mt-3 text-sm leading-6 text-surface-600">{text.body}</p>
      <label class="mt-5 block text-sm font-medium text-surface-800" for="tinycloud-disconnect-input">{text.typeToConfirm}</label>
      <input
        bind:this={input}
        id="tinycloud-disconnect-input"
        bind:value={typed}
        autocomplete="off"
        spellcheck={false}
        class="flex h-10 w-full rounded-xl border border-surface-200 bg-white px-3 py-2 text-sm text-surface-900 focus-visible:outline-none focus-visible:border-primary-500 focus-visible:ring-2 focus-visible:ring-primary-200"
      />
      <p class="mt-2 text-xs text-surface-500">{text.sessionNote}</p>
      <div class="mt-6 flex justify-end gap-3">
        <Button variant="secondary" onclick={dismiss}>{text.cancel}</Button>
        <Button onclick={disconnect} disabled={typed !== text.confirmation}>{text.action}</Button>
      </div>
    </div>
  </div>
{/if}
