<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient, API_BASE } from '$lib/auth-client';
  import { consoleOrigin } from '$lib/console-host';
  import { normalizeAuthReturnTo } from '$lib/auth-flow';
  import { nativeSignIn } from '$lib/native-mode';
  import { safeOAuthNavigationUrl } from '$lib/safe-oauth-url';
  import { loadTermsStatus, oauthClientName, signedOAuthQuery, type TermsStatus } from '$lib/terms';
  import TermsStep from '$lib/components/auth/terms-step.svelte';

  // TC-3232. Two ways in:
  // - the OAuth provider's post-login step: the page carries the provider-signed authorize query, and
  //   Agree resumes it with /oauth2/continue (consent next, or straight back to the app);
  // - an API refusal (`terms_required`): `returnTo` is the page that was refused, under the same rules
  //   as the sign-in redirect.
  const oauthQuery = signedOAuthQuery($page.url.search);
  const native = nativeSignIn($page.url.searchParams);
  const returnTo = normalizeAuthReturnTo(
    $page.url.searchParams.get('returnTo'),
    $page.url.origin,
    undefined,
    { consoleOrigin: consoleOrigin() || undefined },
  );
  const signInHref = oauthQuery
    ? `/auth/login?${oauthQuery}`
    : returnTo ? `/auth/login?redirect=${encodeURIComponent(returnTo)}` : '/auth/login';

  let status = $state<TermsStatus | null>(null);
  let email = $state('');
  let appName = $state<string | null>(null);
  let error = $state('');

  async function proceed() {
    if (oauthQuery) {
      const response = await fetch(`${API_BASE}/api/auth/oauth2/continue`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ postLogin: true, oauth_query: oauthQuery }),
      });
      const result = await response.json().catch(() => null);
      const target = response.ok
        ? safeOAuthNavigationUrl(result?.uri ?? result?.url ?? (typeof result?.redirect === 'string' ? result.redirect : undefined))
        : null;
      if (!target) throw new Error('continue failed');
      window.location.href = target;
      return;
    }
    const target = returnTo ?? '/dashboard';
    if (new URL(target, $page.url.origin).origin === $page.url.origin) await goto(target);
    else window.location.assign(target);
  }

  onMount(async () => {
    const session = await authClient.getSession().catch(() => null);
    if (!session?.data) {
      window.location.assign(signInHref);
      return;
    }
    email = session.data.user.email;
    let loaded: TermsStatus;
    try {
      loaded = await loadTermsStatus();
    } catch {
      error = 'Couldn’t load the Terms. Refresh the page to try again.';
      return;
    }
    if (!loaded.requiresAcceptance) {
      await proceed().catch(() => { error = 'Couldn’t continue. Refresh the page to try again.'; });
      return;
    }
    const clientId = oauthQuery ? new URLSearchParams(oauthQuery).get('client_id') : null;
    if (clientId) appName = await oauthClientName(clientId);
    status = loaded;
  });
</script>

<svelte:head>
  <title>Accept the Terms and Privacy Policy · OpenKey</title>
  <meta name="robots" content="noindex" />
</svelte:head>

{#if status}
  <TermsStep
    {status}
    surface={native ? 'native' : 'web'}
    {email}
    clientId={native?.clientId ?? null}
    {appName}
    {returnTo}
    {signInHref}
    onaccepted={proceed}
  />
{:else}
  <div class="flex min-h-screen items-center justify-center bg-surface-50 px-4 py-12">
    {#if error}
      <p class="text-sm text-red-700" role="alert">{error}</p>
    {/if}
  </div>
{/if}
