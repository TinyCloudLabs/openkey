<script lang="ts">
  // OpenKey signing-approval browser parity harness.
  //
  // Sol MAJOR-1 (final continuation) required a browser-capable test
  // environment that drives real Tab, Space, and Enter interactions
  // through the rendered DOM. This route mounts the EXACT same three
  // production adapter Svelte components that /delegate,
  // /widget/sign, and /widget/embed/sign import — no wrappers, no
  // re-derivations — and reads a fixture model + selection + surface
  // choice from a global that Playwright installs before navigation.
  //
  // This route is guarded by `dev` from `$app/environment` so it does
  // NOT ship in production builds. The parity spec loads it via
  // `vite dev`, and Playwright drives keyboard interaction from
  // outside the app boundary.
  //
  // The test seeds `window.__openkeyParityHarness` via `addInitScript`
  // BEFORE navigation; the transport records every call back into the
  // SAME window object (NOT a Svelte $state proxy) so the Playwright
  // test can read the raw array with `page.evaluate`.

  import { onMount } from 'svelte';
  import { dev } from '$app/environment';
  import CliSigningAdapter from '$lib/components/signing/cli-signing-adapter.svelte';
  import PopupSigningAdapter from '$lib/components/signing/popup-signing-adapter.svelte';
  import IframeSigningAdapter from '$lib/components/signing/iframe-signing-adapter.svelte';
  import type {
    CliSigningTransport,
    WidgetSigningTransport,
  } from '$lib/components/signing/signing-adapter-types';
  import type { CapabilityReviewModel } from '@openkey/capability-review';

  interface HarnessGlobals {
    model: CapabilityReviewModel;
    initialSelection: string[];
    surface: 'cli' | 'popup' | 'iframe';
    canUseAuthorizeSign?: boolean;
    previewReady?: boolean;
    approving?: boolean;
    error?: string | null;
    calls: Array<{ name: string; args?: unknown }>;
  }

  let ready = $state(false);
  let surface = $state<'cli' | 'popup' | 'iframe' | null>(null);
  let model = $state<CapabilityReviewModel | null>(null);
  let initialSelection = $state<Set<string>>(new Set());

  // Non-reactive reference to the window-scoped harness object so
  // spy transport calls push into the SAME array Playwright reads.
  let rawGlobals: HarnessGlobals | null = null;

  onMount(() => {
    const g = (window as any).__openkeyParityHarness as HarnessGlobals | undefined;
    if (!g) {
      return;
    }
    rawGlobals = g;
    surface = g.surface;
    model = g.model;
    initialSelection = new Set(g.initialSelection);
    ready = true;
    (window as any).__openkeyParityHarnessReady = true;
  });

  function record(name: string, args?: unknown) {
    if (!rawGlobals) return;
    rawGlobals.calls.push({ name, args });
  }

  const cliTransport: CliSigningTransport = {
    get approving() {
      return rawGlobals?.approving ?? false;
    },
    get error() {
      return rawGlobals?.error ?? null;
    },
    approveDelegate: () => record('approveDelegate'),
    goBack: () => record('goBack'),
    updateSelection: (next) => record('updateSelection', Array.from(next).sort()),
  };

  const widgetTransport: WidgetSigningTransport = {
    get canUseAuthorizeSign() {
      return rawGlobals?.canUseAuthorizeSign ?? true;
    },
    get previewReady() {
      return rawGlobals?.previewReady ?? false;
    },
    get approving() {
      return rawGlobals?.approving ?? false;
    },
    get error() {
      return rawGlobals?.error ?? null;
    },
    requestPreview: () => record('requestPreview'),
    approveAndSign: () => record('approveAndSign'),
    cancel: () => record('cancel'),
    onSelectionEdited: (next) => record('onSelectionEdited', Array.from(next).sort()),
    invalidatePreview: () => record('invalidatePreview'),
  };
</script>

{#if !dev}
  <p>Parity harness is dev-only.</p>
{:else if !ready || !surface || !model}
  <p>Waiting for harness globals...</p>
{:else}
  <div data-parity-harness data-surface={surface}>
    {#if surface === 'cli'}
      <CliSigningAdapter {model} {initialSelection} transport={cliTransport} />
    {:else if surface === 'popup'}
      <PopupSigningAdapter {model} {initialSelection} transport={widgetTransport} />
    {:else if surface === 'iframe'}
      <IframeSigningAdapter {model} {initialSelection} transport={widgetTransport} />
    {/if}
  </div>
{/if}
