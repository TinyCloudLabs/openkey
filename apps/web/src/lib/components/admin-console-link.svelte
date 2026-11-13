<script lang="ts">
  import { authClient } from '$lib/auth-client';
  import { api } from '$lib/api';
  import { consoleHref } from '$lib/console-host';

  const session = authClient.useSession();
  let adminUserId = $state<string | null>(null);

  $effect(() => {
    const userId = $session.data?.user.id;
    adminUserId = null;
    if ($session.isPending || !userId) return;
    let current = true;
    void api.listConsoleOrganizations().then(({ organizations }) => {
      if (current && organizations.some((organization) => organization.role === 'ADMIN')) adminUserId = userId;
    }).catch(() => {
      // Unknown membership never exposes admin navigation.
    });
    return () => { current = false; };
  });
</script>

{#if adminUserId !== null && adminUserId === $session.data?.user.id}
  <a
    href={consoleHref('/console')}
    class="inline-flex items-center gap-1.5 rounded-full border border-primary-200 bg-primary-50 px-3 py-1.5 text-sm font-semibold text-primary-700 no-underline transition-colors hover:bg-primary-100"
    aria-label="OpenKey Admin console"
  >
    Admin console
    <span aria-hidden="true">↗</span>
  </a>
{/if}
