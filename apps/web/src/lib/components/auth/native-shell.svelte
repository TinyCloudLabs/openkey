<script lang="ts">
  // Full-bleed shell for the native-mode login and consent pages. Only the
  // client's icon and two validated colours come from its branding; everything
  // else here is fixed OpenKey markup.
  import { onMount, type Snippet } from 'svelte';
  import { loadNativeBranding, type NativeBranding } from '$lib/native-mode';
  import { nativeTheme } from '$lib/native-theme';

  interface Props {
    clientId: string;
    /** Heading for the resolved app name, e.g. `(name) => `Sign in to ${name}``. */
    heading: (name: string) => string;
    /** The app name when the page already knows it; `null` holds the heading back. */
    name?: string | null;
    children: Snippet;
  }

  let { clientId, heading, name: knownName, children }: Props = $props();

  let branding = $state<NativeBranding | null>(null);
  let status = $state<'loading' | 'ready' | 'unavailable'>('loading');

  onMount(() => {
    loadNativeBranding(clientId)
      .then((loaded) => { branding = loaded; status = 'ready'; })
      .catch((cause) => {
        console.error('[NativeShell] Failed to load client branding:', cause);
        status = 'unavailable';
      });
  });

  const theme = $derived(nativeTheme(branding?.theme));
  const name = $derived(knownName !== undefined ? knownName : status === 'loading' ? null : (branding?.name ?? 'OpenKey'));
  const icon = $derived(branding?.icon ?? null);

  // The shell fills the viewport, but overscroll and the area behind the
  // browser chrome show the document background, so match it.
  $effect(() => {
    const root = document.documentElement;
    // app.html paints these before hydration and marks them; they are not the
    // document's own styles, so leaving native mode clears them.
    const preloaded = root.hasAttribute('data-native-preload');
    const previous = {
      background: preloaded ? '' : root.style.background,
      colorScheme: preloaded ? '' : root.style.colorScheme,
      overscroll: root.style.overscrollBehavior,
    };
    root.style.background = theme.background;
    root.style.colorScheme = theme.dark ? 'dark' : 'light';
    root.style.overscrollBehavior = 'none';
    document.body.style.background = theme.background;
    return () => {
      root.removeAttribute('data-native-preload');
      root.style.background = previous.background;
      root.style.colorScheme = previous.colorScheme;
      root.style.overscrollBehavior = previous.overscroll;
      document.body.style.background = '';
    };
  });

  // Let the sheet draw under the notch and home indicator; the shell pads by the safe-area insets.
  $effect(() => {
    const viewport = document.querySelector<HTMLMetaElement>('meta[name="viewport"]');
    if (!viewport || viewport.content.includes('viewport-fit')) return;
    const previous = viewport.content;
    viewport.content = `${previous}, viewport-fit=cover`;
    return () => { viewport.content = previous; };
  });
</script>

<svelte:head>
  <meta name="color-scheme" content={theme.dark ? 'dark' : 'light'} />
  <meta name="theme-color" content={theme.background} />
</svelte:head>

<div class="native-shell" style={theme.style} data-native-shell data-branding={status}>
  <main class="nb-column">
    <header class="nb-header">
      {#if icon}
        <img class="nb-icon" src={icon} alt="" referrerpolicy="no-referrer" />
      {:else if name === null}
        <div class="nb-icon nb-icon-tile" aria-hidden="true"></div>
      {:else if status === 'unavailable'}
        <div class="nb-icon nb-icon-tile" aria-hidden="true">
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
          </svg>
        </div>
      {:else}
        <div class="nb-icon nb-icon-tile" aria-hidden="true">{name.charAt(0).toUpperCase()}</div>
      {/if}
      {#if name !== null}
        <h1 class="nb-heading">{heading(name)}</h1>
      {:else}
        <div class="nb-heading-placeholder" aria-hidden="true"></div>
      {/if}
    </header>

    <div class="nb-body">
      {@render children()}
    </div>

    <footer class="nb-trust">Secured by <strong>OpenKey</strong> · openkey.so</footer>
  </main>
</div>

<style>
  .native-shell {
    min-height: 100vh;
    min-height: 100dvh;
    box-sizing: border-box;
    background: var(--nb-bg);
    color: var(--nb-fg);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    touch-action: manipulation;
    -webkit-tap-highlight-color: transparent;
    padding: max(env(safe-area-inset-top), 28px) max(env(safe-area-inset-right), 24px)
      max(env(safe-area-inset-bottom), 20px) max(env(safe-area-inset-left), 24px);
    -webkit-text-size-adjust: 100%;
  }

  .nb-column {
    display: flex;
    flex-direction: column;
    min-height: calc(100dvh - 48px);
    max-width: 26rem;
    margin: 0 auto;
  }

  .nb-header {
    margin-bottom: 20px;
  }

  .nb-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 64px;
    height: 64px;
    border-radius: 22.5%;
    object-fit: cover;
    margin-bottom: 24px;
  }

  .nb-icon-tile {
    background: var(--nb-field);
    border: 1px solid var(--nb-border);
    font-size: 28px;
    font-weight: 600;
  }

  .nb-heading {
    margin: 0;
    font-family: ui-serif, 'New York', Georgia, 'Times New Roman', serif;
    font-size: 32px;
    line-height: 1.15;
    font-weight: 650;
    letter-spacing: -0.01em;
  }

  .nb-heading-placeholder {
    height: 37px;
  }

  .nb-body {
    flex: 1;
  }

  .nb-trust {
    padding-top: 28px;
    text-align: center;
    font-size: 13px;
    color: var(--nb-faint);
  }

  .nb-trust strong {
    color: var(--nb-muted);
    font-weight: 600;
  }

  /* Shared controls for the login and consent views rendered inside the shell. */
  .native-shell :global(.nb-lede) {
    margin: 0 0 24px;
    font-size: 16px;
    line-height: 1.45;
    color: var(--nb-muted);
  }

  .native-shell :global(.nb-lede strong) {
    color: var(--nb-fg);
    font-weight: 600;
    overflow-wrap: anywhere;
  }

  .native-shell :global(.nb-stack) {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .native-shell :global(.nb-input) {
    box-sizing: border-box;
    width: 100%;
    min-height: 52px;
    padding: 0 16px;
    border-radius: 14px;
    border: 1px solid var(--nb-border);
    background: var(--nb-field);
    color: var(--nb-fg);
    font: inherit;
    font-size: 17px;
  }

  .native-shell :global(.nb-input::placeholder) {
    color: var(--nb-faint);
  }

  .native-shell :global(.nb-input:focus-visible) {
    outline: 2px solid var(--nb-ring);
    outline-offset: 2px;
  }

  .native-shell :global(.nb-input:-webkit-autofill) {
    -webkit-text-fill-color: var(--nb-fg);
    caret-color: var(--nb-fg);
    box-shadow: 0 0 0 1000px var(--nb-field) inset;
    transition: background-color 9999s ease-out;
  }

  .native-shell :global(.nb-button) {
    box-sizing: border-box;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    min-height: 52px;
    padding: 0 20px;
    border-radius: 14px;
    border: 1px solid var(--nb-border);
    background: transparent;
    color: var(--nb-fg);
    font: inherit;
    font-size: 17px;
    font-weight: 600;
    cursor: pointer;
  }

  .native-shell :global(.nb-button.nb-primary) {
    border-color: var(--nb-accent);
    background: var(--nb-accent);
    color: var(--nb-accent-fg);
  }

  .native-shell :global(.nb-button:focus-visible),
  .native-shell :global(.nb-link:focus-visible),
  .native-shell :global(.nb-details-summary:focus-visible) {
    outline: 2px solid var(--nb-ring);
    outline-offset: 2px;
  }

  .native-shell :global(.nb-button:disabled) {
    opacity: 0.5;
    cursor: default;
  }

  .native-shell :global(.nb-button.nb-primary:disabled) {
    opacity: 0.3;
  }

  .native-shell :global(.nb-link) {
    min-height: 48px;
    padding: 0 12px;
    border: 0;
    background: none;
    color: var(--nb-fg);
    font: inherit;
    font-size: 15px;
    text-decoration: underline;
    text-underline-offset: 3px;
    cursor: pointer;
  }

  .native-shell :global(.nb-link.nb-quiet) {
    color: var(--nb-muted);
    text-decoration: none;
  }

  .native-shell :global(.nb-link:disabled) {
    opacity: 0.5;
    cursor: default;
  }

  .native-shell :global(.nb-center) {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-top: 8px;
  }

  .native-shell :global(.nb-row) {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: center;
    margin-top: 20px;
    color: var(--nb-muted);
    font-size: 15px;
  }

  .native-shell :global(.nb-or) {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 8px 0;
    font-size: 13px;
    color: var(--nb-faint);
  }

  .native-shell :global(.nb-or::before),
  .native-shell :global(.nb-or::after) {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--nb-border);
  }

  .native-shell :global(.nb-error) {
    margin: 0 0 16px;
    padding: 12px 14px;
    border-radius: 12px;
    border: 1px solid rgba(248, 113, 113, 0.5);
    background: rgba(248, 113, 113, 0.12);
    color: var(--nb-fg);
    font-size: 15px;
    line-height: 1.4;
  }

  .native-shell :global(.nb-note) {
    margin: 0;
    font-size: 15px;
    line-height: 1.45;
    color: var(--nb-muted);
  }
</style>
