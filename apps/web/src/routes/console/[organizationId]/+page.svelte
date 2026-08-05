<script lang="ts">
  import { getContext } from 'svelte';
  import { CONSOLE_SHELL, type ConsoleShellContext } from '$lib/console-shell';
  import { consoleOrganizationPath } from '$lib/console-routing';
  import Button from '$lib/components/ui/button.svelte';
  const { overview } = getContext<ConsoleShellContext>(CONSOLE_SHELL);
</script>
{#if $overview}
  <section class="space-y-6"><div><p class="text-xs font-semibold uppercase tracking-[0.12em] text-primary-600">Developer Organization</p><h1 class="mt-2 text-3xl font-semibold">{$overview.organization.name}</h1><p class="mt-3 text-surface-600">Manage your team and OAuth application configuration. User keys and TinyCloud data are never available to this organization.</p></div><div class="grid gap-4 sm:grid-cols-3"><div class="rounded-2xl border border-surface-200 p-4"><p class="text-sm text-surface-500">OAuth apps</p><p class="mt-1 text-2xl font-semibold">{$overview.usage.apps}</p></div><div class="rounded-2xl border border-surface-200 p-4"><p class="text-sm text-surface-500">Team members</p><p class="mt-1 text-2xl font-semibold">{$overview.usage.members}</p></div><div class="rounded-2xl border border-surface-200 p-4"><p class="text-sm text-surface-500">Plan</p><p class="mt-1 text-2xl font-semibold">{$overview.organization.plan}</p></div></div><div class="flex gap-2"><Button href={consoleOrganizationPath($overview.organization.id, 'apps')}>Manage apps</Button><Button variant="secondary" href={consoleOrganizationPath($overview.organization.id, 'members')}>Manage members</Button></div></section>
{/if}
