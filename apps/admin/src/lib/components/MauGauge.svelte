<script lang="ts">
  let { current, limit }: { current: number; limit: number } = $props();
  let percentage = $derived(limit > 0 ? Math.round((current / limit) * 100) : 0);
  let color = $derived(percentage >= 100 ? 'red' : percentage >= 80 ? 'yellow' : 'green');
</script>

<div class="bg-white border border-surface-200 rounded-lg p-6">
  <div class="flex items-center justify-between mb-2">
    <h3 class="text-sm font-medium text-surface-500 uppercase tracking-wide">Monthly Active Users</h3>
    <span
      class="text-sm font-semibold"
      class:text-green-600={color === 'green'}
      class:text-yellow-600={color === 'yellow'}
      class:text-red-600={color === 'red'}
    >
      {percentage}%
    </span>
  </div>

  <div class="flex items-baseline gap-2 mb-4">
    <span class="text-3xl font-bold text-surface-900">{current.toLocaleString()}</span>
    <span class="text-surface-400">/ {limit.toLocaleString()}</span>
  </div>

  <div class="w-full bg-surface-100 rounded-full h-3 overflow-hidden">
    <div
      class="h-full rounded-full transition-all duration-500"
      class:bg-green-500={color === 'green'}
      class:bg-yellow-500={color === 'yellow'}
      class:bg-red-500={color === 'red'}
      style="width: {Math.min(percentage, 100)}%"
    ></div>
  </div>

  {#if percentage >= 100}
    <p class="mt-3 text-sm text-red-600 font-medium">
      MAU limit reached. Upgrade your plan to continue serving users.
    </p>
  {:else if percentage >= 80}
    <p class="mt-3 text-sm text-yellow-600">
      Approaching MAU limit. Consider upgrading your plan.
    </p>
  {/if}
</div>
