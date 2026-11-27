<script lang="ts">
  import '../app.css';
  import { browser } from '$app/environment';
  import { page } from '$app/stores';
  import AdminConsoleLink from '$lib/components/admin-console-link.svelte';
  import TermsGate from '$lib/components/auth/terms-gate.svelte';
  import { authClient } from '$lib/auth-client';
  import { isEmbedContext } from '$lib/embed-passkey';
  import { nativeSignIn } from '$lib/native-mode';
  import { isPreTermsPage } from '$lib/terms';
  import { termsGate } from '$lib/terms-gate';
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();

  // The Terms step for a window or pop-up (cookie session): once someone is signed in, the account's status is read
  // before the page is shown (the gate holds it while the session and the status are read), and the Terms take the
  // page's place while they are owed. The embedded frame runs its own (its session token, in its card). Sign-in, the
  // Terms and their ways out, and the sign-out pages work before an account agrees.
  const framed = browser && isEmbedContext();
  const session = authClient.useSession();
  // The server render is gated too (`framed` is only known in the browser), so a hard load shows the gate's loading
  // state until the session read answers instead of the page's shell.
  const gated = $derived(
    !framed &&
    $page.url.pathname !== '/' &&
    !isPreTermsPage($page.url.pathname) &&
    !$page.url.pathname.endsWith('/sign-out') &&
    !$page.url.pathname.startsWith('/__parity_harness')
  );
  const native = $derived(nativeSignIn($page.url.searchParams));
  $effect(() => {
    if (!gated || $session.isPending) return;
    termsGate.follow($session.data?.user.id ?? null);
  });

  let isWidget = $derived($page.url.pathname === '/widget' || $page.url.pathname.startsWith('/widget/'));
  let isFullScreen = $derived(
    $page.url.pathname === '/' ||
    $page.url.pathname.startsWith('/auth/') ||
    // OAuth flow pages (e.g. /oauth/consent) are often embedded in native
    // auth sheets; the account chrome must not wrap them.
    $page.url.pathname.startsWith('/oauth/') ||
    $page.url.pathname.startsWith('/delegate') ||
    $page.route.id === '/a/[id]' ||
    // The device page draws its own frame, like the other approval pages.
    $page.url.pathname === '/device' ||
    $page.url.pathname.startsWith('/console') ||
    // The dev-only parity harness route hosts a bare adapter mount so
    // Playwright tests can drive it without surrounding chrome
    // interfering with focus order.
    $page.url.pathname.startsWith('/__parity_harness') ||
    isWidget
  );
</script>

<svelte:head>
  <title>OpenKey</title>
  <meta name="description" content="Passkey-first authentication for Ethereum keys" />
</svelte:head>

{#snippet shell()}
  {#if isFullScreen}
    {@render children()}
  {:else}
    <div class="min-h-screen flex flex-col">
      <header class="border-b border-surface-200/80 bg-surface-50/90 backdrop-blur px-5 py-4">
        <nav class="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-4 gap-y-3">
          <a href="/" class="flex items-center gap-3 text-[15px] font-semibold tracking-[-0.03em] text-surface-900 no-underline">
            <span class="inline-grid h-8 w-8 place-items-center rounded-full bg-primary-600 font-mono text-[12px] text-white">OK</span>
            OpenKey Account
          </a>
          <div class="flex flex-wrap items-center gap-2">
            <a href="/dashboard" class="rounded-full px-3 py-1.5 text-sm text-surface-500 no-underline transition-colors hover:bg-surface-100 hover:text-surface-900">
              Dashboard
            </a>
            <a href="/dashboard/api-keys" class="rounded-full px-3 py-1.5 text-sm text-surface-500 no-underline transition-colors hover:bg-surface-100 hover:text-surface-900">
              API keys
            </a>
            <AdminConsoleLink />
          </div>
        </nav>
      </header>

      <main class="flex-1 max-w-6xl mx-auto w-full px-6 py-8">
        {@render children()}
      </main>

      <footer class="border-t border-surface-200/80 px-6 py-6 text-center text-sm text-surface-500">
        <p>OpenKey Account</p>
      </footer>
    </div>
  {/if}
{/snippet}

{#if gated}
  <TermsGate
    surface={native ? 'native' : 'web'}
    email={$session.data?.user.email ?? null}
    clientId={native?.clientId ?? null}
    returnTo={$page.url.pathname + $page.url.search}
    sessionPending={$session.isPending}
    signedIn={!!$session.data?.user}
    onretrysession={() => void $session.refetch()}
  >
    {@render shell()}
  </TermsGate>
{:else}
  {@render shell()}
{/if}
