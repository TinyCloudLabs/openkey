<script lang="ts">
  let { data } = $props();
</script>

<svelte:head>
  <title>Sign In - OpenKey Admin</title>
</svelte:head>

<div class="min-h-screen bg-surface-50 flex flex-col items-center justify-center px-4">
  <!-- Logo mark -->
  <div class="mb-8 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-surface-800 to-surface-950 shadow-md">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-6 w-6">
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  </div>

  <!-- Main card -->
  <div class="rounded-2xl border border-surface-200 bg-white p-10 shadow-sm w-full max-w-md">
    <h1 class="text-[22px] font-semibold text-surface-900 text-center mb-2">OpenKey Admin</h1>
    <p class="text-sm text-surface-500 text-center mb-8">Sign in to your developer account</p>

    {#if data.error}
      <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-6 text-sm" role="alert">
        {data.error}
      </div>
    {/if}

    <div class="flex flex-col gap-4">
      <a
        href="/auth/authorize"
        class="inline-flex items-center justify-center whitespace-nowrap rounded-xl font-medium transition-colors
               focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-surface-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white
               bg-surface-900 text-white hover:bg-surface-800 shadow-sm h-11 px-8 text-lg w-full no-underline"
      >
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mr-2 h-4 w-4">
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
        </svg>
        Sign in with OpenKey
      </a>
    </div>

    <p class="text-xs text-surface-400 text-center mt-6">
      You'll be redirected to OpenKey to authenticate.
    </p>
  </div>

  <!-- Trust badge -->
  <div class="mt-6 flex items-center gap-2 text-xs text-surface-400">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
    Protected by TEE hardware security
  </div>
</div>
