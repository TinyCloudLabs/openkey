<!--
  TC-3657: outside-app one-tap TinyCloud setup consent screen. DRAFT; final copy + visuals are
  owned by Monica (text) and Soren (interaction). This page is only the state machine: it
  observes the opener's origin via `event.origin` on an opener postMessage (Bobbie C3,
  browser-verified), calls `/api/tinycloud-setup/mint-ticket` + `/publish`, and postMessages
  the outside app's SDK the `TinyCloudSetupResultV1`.

  Guards rendered here:
    - N1: refuses to render inside an iframe (`+layout.ts` + server CSP; see also
      `+page.server.ts` which sets `frame-ancestors 'none'`).
    - C3: the requestingOrigin on screen + sent to the server comes from `event.origin`
      of the opener's postMessage. The outside app cannot forge it — a postMessage to
      this window carries the browser-verified origin of the sender. `requestingApp.name`
      and `requestingApp.manifest` from the request are DISPLAYED CLAIMS labeled as such
      (N2); OpenKey server never uses them for grant input.
    - C5: the server rate-limits per owner; this page surfaces a 429 as a friendly retry hint.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { LayoutData } from './$types';

  // The previous-render refusal from +layout.ts; if present, we show it and self-close.
  export let data: LayoutData;

  type Phase =
    | { kind: 'loading' }
    | { kind: 'ready'; preview: SetupPreview; ticket: string; requestingOrigin: string; requestingAppName?: string; requestingAppManifest?: unknown }
    | { kind: 'submitting' }
    | { kind: 'error'; message: string }
    | { kind: 'refused-embedded' };

  interface SetupPreview {
    subject: string;
    nodeDid: string;
    nodeOrigin: string;
    space: string;
    primarySpaceName: string;
  }

  type SetupResult =
    | { status: 'published'; subject: string }
    | { status: 'already-current'; subject: string }
    | { status: 'declined' }
    | { status: 'unavailable'; reason: 'signature-refused' | 'registry-error' | 'node-unreachable' | 'rate-limited' };

  let phase: Phase = data.embeddedRefusalMessage ? { kind: 'refused-embedded' } : { kind: 'loading' };
  let requestId: string | null = null;

  onMount(() => {
    if (phase.kind === 'refused-embedded') {
      // Close after a short tick so the user sees the message.
      window.setTimeout(() => { try { window.close(); } catch { /* popup may be blocked */ } }, 3000);
      return;
    }
    // Wait for the opener's postMessage identifying itself + the request.
    const listener = async (event: MessageEvent) => {
      // event.origin is browser-verified. Ignore any message that isn't our SDK's setup request.
      const data = event.data;
      if (!data || typeof data !== 'object' || data.type !== 'openkey:tinycloud-setup:request') return;
      if (typeof data.requestId !== 'string') return;
      if (event.source !== window.opener) return;
      requestId = data.requestId;
      try {
        const mint = await fetch('/api/tinycloud-setup/mint-ticket', {
          method: 'POST',
          credentials: 'include',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ requestingOrigin: event.origin }),
        });
        if (mint.status === 429) {
          phase = { kind: 'error', message: 'Too many setup attempts for this account in the last hour. Please try again later.' };
          respond({ status: 'unavailable', reason: 'rate-limited' });
          return;
        }
        if (!mint.ok) {
          phase = { kind: 'error', message: 'Setup is unavailable right now.' };
          respond({ status: 'unavailable', reason: 'node-unreachable' });
          return;
        }
        const body = (await mint.json()) as { ticket: string; preview: SetupPreview };
        phase = {
          kind: 'ready',
          preview: body.preview,
          ticket: body.ticket,
          requestingOrigin: event.origin,
          requestingAppName: typeof data.requestingApp?.name === 'string' ? data.requestingApp.name : undefined,
          requestingAppManifest: data.requestingApp?.manifest,
        };
      } catch {
        phase = { kind: 'error', message: 'Setup is unavailable right now.' };
        respond({ status: 'unavailable', reason: 'node-unreachable' });
      }
    };
    window.addEventListener('message', listener);
    return () => window.removeEventListener('message', listener);
  });

  async function approve() {
    if (phase.kind !== 'ready') return;
    const { ticket, requestingOrigin } = phase;
    phase = { kind: 'submitting' };
    try {
      const publish = await fetch('/api/tinycloud-setup/publish', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ticket, requestingOrigin }),
      });
      if (publish.status === 429) {
        respond({ status: 'unavailable', reason: 'rate-limited' });
        return;
      }
      if (!publish.ok) {
        respond({ status: 'unavailable', reason: 'registry-error' });
        return;
      }
      respond((await publish.json()) as SetupResult);
    } catch {
      respond({ status: 'unavailable', reason: 'node-unreachable' });
    }
  }

  function decline() {
    respond({ status: 'declined' });
  }

  function respond(result: SetupResult): void {
    // postMessage to opener using the opener's exact origin (which we already trust;
    // the outside app receives this via the OpenKey SDK's openFlow listener).
    try {
      if (window.opener && requestId && phase.kind !== 'refused-embedded') {
        const originOk = phase.kind === 'ready' || phase.kind === 'submitting'
          ? (phase as { requestingOrigin?: string }).requestingOrigin ?? null
          : null;
        if (originOk) {
          window.opener.postMessage(
            { type: 'openkey:tinycloud-setup:response', success: true, result, requestId },
            originOk,
          );
        }
      }
    } finally {
      try { window.close(); } catch { /* popup may be blocked */ }
    }
  }
</script>

{#if phase.kind === 'refused-embedded'}
  <main>
    <h1>Embedded setup is refused</h1>
    <p>{data.embeddedRefusalMessage}</p>
  </main>
{:else if phase.kind === 'loading'}
  <main>
    <h1>Opening setup…</h1>
    <p>Waiting for the requesting app to introduce itself.</p>
  </main>
{:else if phase.kind === 'error'}
  <main>
    <h1>Setup is unavailable</h1>
    <p>{phase.message}</p>
    <button type="button" on:click={() => { try { window.close(); } catch { /* popup */ } }}>Close</button>
  </main>
{:else if phase.kind === 'submitting'}
  <main>
    <h1>Publishing…</h1>
    <p>Hold on while OpenKey signs and publishes your account's location record.</p>
  </main>
{:else}
  <main>
    <h1>Let your apps find your space</h1>
    <!-- TODO(Monica): final copy; placeholder below carries the design's §5 wording. -->
    <p>
      To use TinyCloud apps outside TinyCloud Home, we publish a public record that links your
      account address to the server that holds your space. Anyone who knows your account
      address can see it, along with the names of your spaces. It doesn't include any of your content.
    </p>
    <dl>
      <dt>Requesting app (verified origin)</dt>
      <dd><code>{phase.requestingOrigin}</code></dd>
      {#if phase.requestingAppName}
        <dt>App's own claimed name</dt>
        <dd><em>{phase.requestingAppName}</em> <small>(the app's own claim, not verified)</small></dd>
      {/if}
      <dt>Account</dt>
      <dd><code>{phase.preview.subject}</code></dd>
      <dt>Server address</dt>
      <dd><code>{phase.preview.nodeOrigin}</code></dd>
      <dt>Space</dt>
      <dd><code>{phase.preview.space}</code></dd>
    </dl>
    <!-- TODO(Monica/Soren): final button copy + layout. -->
    <button type="button" on:click={approve}>Publish and continue to {phase.requestingAppName ?? 'the app'}</button>
    <button type="button" on:click={decline}>Not now</button>
  </main>
{/if}

<!-- Styles deferred to Soren; the page is intentionally plain for the draft. -->
