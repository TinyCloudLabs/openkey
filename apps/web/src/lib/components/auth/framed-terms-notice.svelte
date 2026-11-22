<script lang="ts">
  import { onMount } from 'svelte';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import { withSessionCredential } from '$lib/embed-passkey';
  import { loadTermsStatus } from '$lib/terms';

  const POLL_MS = 2000;

  // The Terms screen needs the cookie session, which a frame on another site does not have: it opens in a
  // window of its own. The frame holds its session token, so it watches the account's status with that
  // token and reloads (the token survives the reload) once the account has agreed.
  function openTerms() {
    window.open('/auth/terms', '_blank', 'noopener');
  }

  onMount(() => {
    let checking = false;
    const timer = setInterval(async () => {
      if (checking) return;
      checking = true;
      const status = await loadTermsStatus(withSessionCredential).catch(() => null);
      checking = false;
      if (status && !status.requiresAcceptance) window.location.reload();
    }, POLL_MS);
    return () => clearInterval(timer);
  });
</script>

<div class="flex items-center justify-center px-4 py-6">
  <Card class="w-full max-w-md p-6 text-center" data-testid="framed-terms-notice">
    <h1 class="mb-2 text-lg font-semibold text-surface-900">Agree to the Terms to continue</h1>
    <p class="mb-5 text-sm text-surface-500">OpenKey has new Terms of Service. Open them in a new window, agree, then come back here.</p>
    <Button onclick={openTerms} class="w-full">Open the Terms</Button>
  </Card>
</div>
