<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import Card from '$lib/components/ui/card.svelte';
  import Button from '$lib/components/ui/button.svelte';

  const session = authClient.useSession();

  const oauthError = $page.url.searchParams.get('error');
  const errorDescription = $page.url.searchParams.get('error_description');

  function formatErrorMessage(error: string, description: string | null): string {
    const messages: Record<string, string> = {
      invalid_redirect: 'The application provided an invalid redirect URL. This usually means the redirect URI uses http instead of https, or hasn\'t been registered.',
      access_denied: 'Access was denied to the requesting application.',
      invalid_client: 'The application that sent you here is not recognized.',
      server_error: 'Something went wrong on our end. Please try again.',
    };
    return messages[error] || description?.replace(/\+/g, ' ') || `OAuth error: ${error}`;
  }
</script>

<div class="min-h-screen flex flex-col lg:flex-row bg-[#fafafa]">
  <!-- Left brand panel (desktop only) -->
  <div class="hidden lg:flex lg:w-[45%] lg:shrink-0 bg-[#0a0a0a]">
    <div class="flex flex-col justify-center h-full p-12">
      <!-- Logo mark -->
      <div class="mb-8">
        <div class="inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-white/10">
          <svg class="h-7 w-7 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
          </svg>
        </div>
      </div>

      <h2 class="mb-4 text-3xl font-bold tracking-tight text-white">OpenKey</h2>
      <p class="mb-3 text-lg text-surface-300">Your keys, secured by passkeys</p>
      <p class="mb-10 text-sm leading-relaxed text-surface-400">
        A passkey-first key management service that protects your Ethereum keys with hardware-level security.
      </p>

      <!-- Feature bullets -->
      <ul class="space-y-4">
        <li class="flex items-start gap-3">
          <div class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/10">
            <svg class="h-3 w-3 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
          </div>
          <span class="text-sm text-surface-300">Passkey-first security</span>
        </li>
        <li class="flex items-start gap-3">
          <div class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/10">
            <svg class="h-3 w-3 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
          </div>
          <span class="text-sm text-surface-300">Sign transactions in seconds</span>
        </li>
        <li class="flex items-start gap-3">
          <div class="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/10">
            <svg class="h-3 w-3 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
          </div>
          <span class="text-sm text-surface-300">TEE-protected key storage</span>
        </li>
      </ul>
    </div>
  </div>

  <!-- Right content pane -->
  <div class="flex-1 flex items-center justify-center px-6 py-12 lg:w-[55%] lg:p-12">
    <div class="w-full max-w-lg lg:max-w-md">
      {#if oauthError}
        <div class="mb-8 rounded-xl border border-red-200 bg-red-50 p-4 text-center">
          <p class="text-sm font-medium text-red-800">
            {formatErrorMessage(oauthError, errorDescription)}
          </p>
          {#if oauthError === 'invalid_redirect'}
            <p class="mt-2 text-xs text-red-600">
              If you're a developer, check that your OAuth client's redirect URI uses https and matches exactly.
            </p>
          {/if}
        </div>
      {/if}

      <!-- Mobile logo (hidden on desktop) -->
      <div class="mb-6 flex justify-center lg:hidden">
        <div class="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-900">
          <svg class="h-6 w-6 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
          </svg>
        </div>
      </div>

      <h1 class="mb-3 text-center text-4xl font-bold tracking-tight text-surface-900">
        Secure your keys
      </h1>
      <p class="mx-auto mb-10 max-w-md text-center text-lg text-surface-500">
        Passkey-first authentication for Ethereum keys. No passwords, no seed phrases.
      </p>

      <!-- Feature cards -->
      <div class="mx-auto mb-10 grid max-w-lg gap-4">
        <Card class="flex items-start gap-4 text-left">
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-surface-100">
            <svg class="h-5 w-5 text-surface-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
          <div>
            <h3 class="mb-1 text-sm font-semibold text-surface-900">Passkey Security</h3>
            <p class="text-sm text-surface-500">No passwords to remember. Your biometrics are your key.</p>
          </div>
        </Card>

        <Card class="flex items-start gap-4 text-left">
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-surface-100">
            <svg class="h-5 w-5 text-surface-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <h3 class="mb-1 text-sm font-semibold text-surface-900">TEE Protected</h3>
            <p class="text-sm text-surface-500">Private keys secured in a Trusted Execution Environment.</p>
          </div>
        </Card>

        <Card class="flex items-start gap-4 text-left">
          <div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-surface-100">
            <svg class="h-5 w-5 text-surface-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="16 18 22 12 16 6" />
              <polyline points="8 6 2 12 8 18" />
            </svg>
          </div>
          <div>
            <h3 class="mb-1 text-sm font-semibold text-surface-900">Easy Integration</h3>
            <p class="text-sm text-surface-500">Simple SDK for any web application.</p>
          </div>
        </Card>
      </div>

      <!-- CTA Buttons -->
      <div class="mx-auto flex max-w-lg flex-col gap-3 sm:flex-row sm:justify-center">
        {#if $session.data}
          <Button href="/dashboard" size="lg" class="w-full sm:w-auto">
            Go to Dashboard
          </Button>
        {:else}
          <Button href="/auth/register" size="lg" class="w-full sm:w-auto">
            Get Started
          </Button>
          <Button href="/auth/login" variant="secondary" size="lg" class="w-full sm:w-auto">
            Sign In
          </Button>
        {/if}
      </div>
    </div>
  </div>
</div>
