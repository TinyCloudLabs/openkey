<script lang="ts">
  let { data } = $props();
</script>

<svelte:head>
  <title>Sign In - OpenKey Admin</title>
</svelte:head>

<div class="min-h-screen flex items-center justify-center bg-surface-50 px-4">
  <div class="w-full max-w-sm">
    <div class="text-center mb-8">
      <h1 class="text-3xl font-bold text-surface-900">OpenKey Admin</h1>
      <p class="text-surface-500 mt-2">Sign in to your developer account</p>
    </div>

    <div class="bg-white border border-surface-200 rounded-lg p-6">
      <a
        href={data.authorizeUrl}
        class="block w-full py-2.5 px-4 bg-primary-600 text-white rounded-md font-medium text-center hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-colors no-underline"
      >
        Sign in with OpenKey
      </a>
      <p class="text-xs text-surface-400 text-center mt-4">
        You'll be redirected to OpenKey to authenticate.
      </p>
    </div>
  </div>
</div>
