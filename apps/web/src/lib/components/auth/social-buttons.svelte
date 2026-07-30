<script lang="ts">
  import Button from '$lib/components/ui/button.svelte';
  import type { SocialProviderId } from '$lib/social-auth';

  interface Props {
    providers: SocialProviderId[];
    loadingProvider?: SocialProviderId | null;
    disabled?: boolean;
    onsignin: (provider: SocialProviderId) => void;
  }

  let {
    providers,
    loadingProvider = null,
    disabled = false,
    onsignin,
  }: Props = $props();
</script>

<div class="flex w-full flex-col gap-3">
  {#if providers.includes('google')}
    <Button
      variant="secondary"
      onclick={() => onsignin('google')}
      disabled={disabled}
      class="w-full"
      aria-label="Continue with Google"
      aria-busy={loadingProvider === 'google'}
    >
      <svg class="h-4 w-4 shrink-0" viewBox="0 0 18 18" aria-hidden="true">
        <path fill="#4285F4" d="M17.64 9.205c0-.638-.057-1.252-.164-1.841H9v3.482h4.844a4.14 4.14 0 0 1-1.797 2.716v2.258h2.909c1.703-1.568 2.684-3.879 2.684-6.615Z"/>
        <path fill="#34A853" d="M9 18c2.43 0 4.468-.806 5.956-2.18l-2.909-2.258c-.806.54-1.835.859-3.047.859-2.344 0-4.328-1.585-5.037-3.714H.956v2.333A9 9 0 0 0 9 18Z"/>
        <path fill="#FBBC05" d="M3.963 10.707A5.41 5.41 0 0 1 3.682 9c0-.592.102-1.167.281-1.707V4.96H.956A9 9 0 0 0 0 9c0 1.452.347 2.827.956 4.04l3.007-2.333Z"/>
        <path fill="#EA4335" d="M9 3.579c1.321 0 2.507.454 3.441 1.346l2.581-2.581C13.464.892 11.426 0 9 0A9 9 0 0 0 .956 4.96l3.007 2.333C4.672 5.164 6.656 3.579 9 3.579Z"/>
      </svg>
      {loadingProvider === 'google' ? 'Connecting to Google…' : 'Continue with Google'}
    </Button>
  {/if}

  {#if providers.includes('apple')}
    <Button
      variant="secondary"
      onclick={() => onsignin('apple')}
      disabled={disabled}
      class="w-full"
      aria-label="Continue with Apple"
      aria-busy={loadingProvider === 'apple'}
    >
      <svg class="h-[18px] w-[15px] shrink-0 fill-current" viewBox="0 0 15 18" aria-hidden="true">
        <path d="M12.55 9.55c.02-2.02 1.65-2.99 1.73-3.04a3.7 3.7 0 0 0-2.91-1.57c-1.23-.13-2.43.74-3.05.74-.64 0-1.6-.73-2.64-.71a3.86 3.86 0 0 0-3.25 1.98c-1.42 2.46-.36 6.07 1 8.06.68.97 1.47 2.06 2.51 2.02 1.02-.04 1.4-.65 2.63-.65 1.22 0 1.58.65 2.64.63 1.09-.02 1.78-.98 2.43-1.96a8.05 8.05 0 0 0 1.11-2.26 3.49 3.49 0 0 1-2.2-3.24ZM10.57 3.63A3.55 3.55 0 0 0 11.38 1a3.63 3.63 0 0 0-2.35 1.25 3.4 3.4 0 0 0-.83 2.53 3 3 0 0 0 2.37-1.15Z"/>
      </svg>
      {loadingProvider === 'apple' ? 'Connecting to Apple…' : 'Continue with Apple'}
    </Button>
  {/if}
</div>
