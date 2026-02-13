<script lang="ts">
  interface DailyStat {
    date: string;
    uniqueUsers: number;
    totalAuthorizations: number;
    totalTokenExchanges: number;
  }

  let { stats, appName = 'Application' }: { stats: DailyStat[]; appName?: string } = $props();

  let totalUsers = $derived(stats.reduce((sum, s) => sum + s.uniqueUsers, 0));
  let totalAuths = $derived(stats.reduce((sum, s) => sum + s.totalAuthorizations, 0));
  let totalExchanges = $derived(stats.reduce((sum, s) => sum + s.totalTokenExchanges, 0));

  function formatDate(dateStr: string): string {
    const date = new Date(dateStr + 'T00:00:00');
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }
</script>

<div class="bg-white border border-surface-200 rounded-lg p-6">
  <h3 class="text-lg font-semibold text-surface-900 mb-4">{appName} - Daily Stats</h3>

  <!-- Summary row -->
  <div class="grid grid-cols-3 gap-4 mb-6">
    <div class="bg-surface-50 rounded-lg p-3 text-center">
      <p class="text-2xl font-bold text-primary-600">{totalUsers}</p>
      <p class="text-xs text-surface-500 mt-1">Unique Users</p>
    </div>
    <div class="bg-surface-50 rounded-lg p-3 text-center">
      <p class="text-2xl font-bold text-primary-600">{totalAuths}</p>
      <p class="text-xs text-surface-500 mt-1">Authorizations</p>
    </div>
    <div class="bg-surface-50 rounded-lg p-3 text-center">
      <p class="text-2xl font-bold text-primary-600">{totalExchanges}</p>
      <p class="text-xs text-surface-500 mt-1">Token Exchanges</p>
    </div>
  </div>

  <!-- Daily stats table -->
  {#if stats.length === 0}
    <p class="text-surface-400 text-center py-4">No data for this month yet.</p>
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-surface-200">
            <th class="text-left py-2 px-3 font-medium text-surface-500">Date</th>
            <th class="text-right py-2 px-3 font-medium text-surface-500">Unique Users</th>
            <th class="text-right py-2 px-3 font-medium text-surface-500">Authorizations</th>
            <th class="text-right py-2 px-3 font-medium text-surface-500">Token Exchanges</th>
          </tr>
        </thead>
        <tbody>
          {#each stats as day}
            <tr class="border-b border-surface-100 hover:bg-surface-50">
              <td class="py-2 px-3 text-surface-700">{formatDate(day.date)}</td>
              <td class="py-2 px-3 text-right text-surface-900 font-medium">{day.uniqueUsers}</td>
              <td class="py-2 px-3 text-right text-surface-900 font-medium">{day.totalAuthorizations}</td>
              <td class="py-2 px-3 text-right text-surface-900 font-medium">{day.totalTokenExchanges}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
