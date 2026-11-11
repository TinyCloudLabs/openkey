<script lang="ts">
  import { onMount } from 'svelte';
  import { API_BASE } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';
  let email = $state('');
  let code = $state('');
  let confirmation = $state('');
  let loading = $state(false);
  let ready = $state(false);
  let deleted = $state(false);
  let error = $state('');
  const post = (action: string, body: object) => fetch(`${API_BASE}/api/review-account/${action}`, {
    method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  async function prepare() {
    try { ready = (await post('delete-intent', {})).ok; }
    catch { ready = false; }
    if (!ready) error = "Couldn't verify the app review account. Check the review account and code, then try again.";
  }
  onMount(prepare);
  async function remove() {
    if (loading || !ready) return;
    loading = true;
    error = '';
    try {
      const response = await post('delete', { email, code, confirmation });
      code = '';
      if (response.ok) deleted = true;
      else error = "Couldn't verify the app review account. Check the review account and code, then try again.";
    } catch { code = ''; error = "Couldn't verify the app review account. Check the review account and code, then try again."; }
    finally { loading = false; }
  }
</script>

<svelte:head><title>Delete app review account - OpenKey</title></svelte:head>
<div class="mx-auto flex min-h-screen max-w-md items-center px-4 py-10">
  <Card class="w-full p-6">
    {#if deleted}
      <h1 class="mb-4 text-xl font-bold">Your app review account was deleted.</h1>
      <p>You can close this page.</p>
    {:else}
      <h1 class="mb-4 text-xl font-bold">Delete OpenKey account</h1>
      <p class="mb-6 text-sm text-surface-600">Deleting your OpenKey account does not delete data that apps keep with other services.</p>
      {#if error}<p class="mb-4 text-sm text-red-700" role="alert">{error}</p>{/if}
      <form class="flex flex-col gap-4" onsubmit={(event) => { event.preventDefault(); remove(); }}>
        <label for="review-email">Review account</label>
        <Input id="review-email" type="email" bind:value={email} autocomplete="username" autocapitalize="none" required disabled={loading} />
        <label for="review-code">Review code</label>
        <Input id="review-code" type="password" bind:value={code} autocomplete="current-password" maxlength={128} required disabled={loading} />
        <label for="confirmation">Type DELETE MY ACCOUNT to confirm</label>
        <Input id="confirmation" bind:value={confirmation} autocomplete="off" required disabled={loading} />
        <Button type="submit" disabled={loading || !ready || confirmation !== 'DELETE MY ACCOUNT'}>Verify and delete account</Button>
      </form>
      <a class="mt-4 block text-center text-sm text-surface-500" href="/auth/login">Back</a>
    {/if}
  </Card>
</div>
