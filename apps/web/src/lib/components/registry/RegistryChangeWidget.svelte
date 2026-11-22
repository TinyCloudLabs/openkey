<script lang="ts">
  import { untrack } from 'svelte';
  import { page } from '$app/stores';
  import { confirmWithPasskey, PasskeyPromptError, passkeyApprovalCopy, type ApprovalPasskeyOffer } from '$lib/approval-passkey';
  import { resolveWidgetOrigin } from '$lib/widget-transport';
  import {
    REGISTRY_CHANGE_COPY,
    applyCancel,
    applyPrepareResult,
    applyPublishResult,
    applyRequestMessage,
    initialState,
    screenOriginLine,
    screenTitle,
    type RegistryChangePostBack,
    type RegistryChangeWidgetState,
  } from '../../../routes/widget/registry-change/widget-state';

  const API_BASE = import.meta.env.VITE_API_URL || '';

  interface Props {
    embeddedRefusalMessage?: string | null;
  }

  let { embeddedRefusalMessage = null }: Props = $props();

  const configuredOrigin = resolveWidgetOrigin($page.url.searchParams.get('origin'));
  let widgetState = $state<RegistryChangeWidgetState>(initialState(untrack(() => embeddedRefusalMessage)));
  let initialized = false;

  function counterpartyWindow(): Window | null {
    if (typeof window === 'undefined') return null;
    return window.opener;
  }

  function postBack(envelope: RegistryChangePostBack | null) {
    const target = counterpartyWindow();
    const targetOrigin = widgetState.verifiedRequestingOrigin ?? configuredOrigin;
    if (!envelope || !target || !targetOrigin) return;
    try {
      target.postMessage(envelope, targetOrigin);
    } catch {
      /* counterparty closed */
    }
  }

  function closeSoon() {
    setTimeout(() => {
      try {
        window.close();
      } catch {
        /* no-op */
      }
    }, 300);
  }

  async function runPrepare(preserveError: string | null = null) {
    const requestingOrigin = widgetState.verifiedRequestingOrigin;
    if (!requestingOrigin) return;
    const isUndo = widgetState.mode === 'undo';
    const historyId = widgetState.historyId;
    const requestPayload = widgetState.requestPayload;
    if (isUndo && !historyId) return;
    if (!isUndo && !requestPayload) return;

    widgetState = { ...widgetState, phase: 'preparing', error: preserveError };
    const endpoint = isUndo
      ? `${API_BASE}/api/registry-change/undo/prepare`
      : `${API_BASE}/api/registry-change/prepare`;
    const bodyPayload = isUndo
      ? { historyId }
      : { request: requestPayload };

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'content-type': 'application/json',
          'x-openkey-requesting-origin': requestingOrigin,
        },
        body: JSON.stringify(bodyPayload),
      });
      const body = await response.json().catch(() => ({}));
      const next = applyPrepareResult(
        widgetState,
        response.ok
          ? { ok: true, body }
          : { ok: false, status: response.status, body },
      );
      widgetState = preserveError && next.phase === 'review' ? { ...next, error: preserveError } : next;
    } catch {
      widgetState = applyPrepareResult(widgetState, { ok: false, status: 0, body: { error: 'prepare_failed' } });
    }
  }

  async function approve() {
    const changeId = widgetState.changeId;
    const passkey = widgetState.passkey;
    if (widgetState.phase !== 'review' || !changeId || !passkey) return;
    const beforeSubmit = widgetState;
    widgetState = { ...widgetState, phase: 'submitting', error: null };

    // Call WebAuthn straight from the user's tap so browsers preserve the gesture.
    let passkeyAssertion: unknown;
    try {
      const offer: ApprovalPasskeyOffer = {
        challengeToken: passkey.challengeToken,
        options: passkey.options as ApprovalPasskeyOffer['options'],
      };
      passkeyAssertion = await confirmWithPasskey(offer);
    } catch (error) {
      widgetState = {
        ...beforeSubmit,
        error: error instanceof PasskeyPromptError ? error.message : passkeyApprovalCopy.cancelled,
      };
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/api/registry-change/publish`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          changeId,
          passkeyAssertion,
        }),
      });
      const body = await response.json().catch(() => ({}));
      const update = applyPublishResult(
        widgetState,
        response.ok
          ? { ok: true, body }
          : { ok: false, status: response.status, body },
      );
      widgetState = update.state;
      if (update.needsReprepare) {
        await runPrepare(update.state.error);
        return;
      }
      if (update.postBack) {
        postBack(update.postBack);
        closeSoon();
      }
    } catch {
      const update = applyPublishResult(widgetState, { ok: false, status: 0, body: { error: 'publish_failed' } });
      widgetState = update.state;
    }
  }

  function cancel() {
    const update = applyCancel(widgetState);
    widgetState = update.state;
    postBack(update.postBack);
    closeSoon();
  }

  async function reviewAgain() {
    await runPrepare();
  }

  $effect(() => {
    if (typeof window === 'undefined' || initialized || widgetState.phase === 'embedded-refused') return;
    initialized = true;

    const onMessage = (event: MessageEvent) => {
      const next = applyRequestMessage(widgetState, {
        origin: event.origin,
        source: event.source,
        counterparty: counterpartyWindow(),
        configuredOrigin,
        data: event.data,
      });
      if (next === widgetState) return;
      widgetState = next;
      void runPrepare();
    };

    window.addEventListener('message', onMessage);

    const target = counterpartyWindow();
    if (target && configuredOrigin) {
      try {
        target.postMessage({ type: 'openkey:ready', protocolVersion: 1 }, configuredOrigin);
      } catch {
        /* counterparty gone */
      }
    }

    return () => {
      window.removeEventListener('message', onMessage);
    };
  });

  const currentTitle = $derived(screenTitle(widgetState));
  const currentOriginLine = $derived(screenOriginLine(widgetState));
</script>

<main
  class="rc-shell"
  data-testid="registry-change-widget"
>
  {#if widgetState.phase === 'embedded-refused'}
    <h1 class="rc-title">Can't continue</h1>
    <p class="rc-text">{widgetState.error}</p>
  {:else if widgetState.phase === 'waiting'}
    <p class="rc-muted">{REGISTRY_CHANGE_COPY.waiting}</p>
  {:else if widgetState.phase === 'preparing'}
    <h1 class="rc-title">{currentTitle}</h1>
    {#if currentOriginLine}
      <p class="rc-origin" data-testid="registry-change-origin">{currentOriginLine}</p>
    {/if}
    <p class="rc-muted">{REGISTRY_CHANGE_COPY.loading}</p>
    {#if widgetState.error}
      <p class="rc-error" role="alert">{widgetState.error}</p>
    {/if}
  {:else if widgetState.phase === 'stale'}
    <section class="rc-card" data-testid="registry-change-stale">
      <h1 class="rc-title">{REGISTRY_CHANGE_COPY.staleTitle}</h1>
      <p class="rc-text">{REGISTRY_CHANGE_COPY.staleBody}</p>
      <div class="rc-actions">
        <button type="button" class="rc-btn rc-btn-primary" onclick={reviewAgain}>
          {REGISTRY_CHANGE_COPY.staleButton}
        </button>
        <button type="button" class="rc-btn rc-btn-secondary" onclick={cancel}>
          {REGISTRY_CHANGE_COPY.cancelButton}
        </button>
      </div>
    </section>
  {:else if widgetState.phase === 'invalid' || widgetState.phase === 'error'}
    <section class="rc-card" data-testid="registry-change-error">
      <h1 class="rc-title">{currentTitle}</h1>
      <p class="rc-error" role="alert">{widgetState.error}</p>
      <div class="rc-actions">
        <button type="button" class="rc-btn rc-btn-secondary" onclick={cancel}>
          {REGISTRY_CHANGE_COPY.cancelButton}
        </button>
      </div>
    </section>
  {:else if widgetState.phase === 'done'}
    <section class="rc-card" data-testid="registry-change-done">
      <h1 class="rc-title">{currentTitle}</h1>
      <p class="rc-success" role="status">{REGISTRY_CHANGE_COPY.success}</p>
    </section>
  {:else if widgetState.phase === 'cancelled'}
    <section class="rc-card">
      <p class="rc-muted">Cancelled.</p>
    </section>
  {:else}
    <section class="rc-card" data-testid="registry-change-review">
      <h1 class="rc-title">{currentTitle}</h1>

      {#if currentOriginLine}
        <p class="rc-origin" data-testid="registry-change-origin">{currentOriginLine}</p>
      {/if}

      <p class="rc-text">{REGISTRY_CHANGE_COPY.explainer}</p>
      <p class="rc-risk">{REGISTRY_CHANGE_COPY.riskLine}</p>

      <table class="rc-table" data-testid="registry-change-diff-table">
        <thead>
          <tr>
            <th>{REGISTRY_CHANGE_COPY.tableHeader.space}</th>
            <th>{REGISTRY_CHANGE_COPY.tableHeader.before}</th>
            <th>{REGISTRY_CHANGE_COPY.tableHeader.after}</th>
          </tr>
        </thead>
        <tbody>
          {#each widgetState.diffRows as row (row.label)}
            <tr class:rc-row-encryption={row.isEncryption && row.changed}>
              {#if row.modeOnlyLine}
                <td colspan="3" data-testid="registry-change-mode-only-row">{row.modeOnlyLine}</td>
              {:else}
                <td>{row.label}</td>
                <td>{row.beforeHost}</td>
                <td>{row.afterHost}</td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>

      {#if widgetState.encryptionChanged}
        <div class="rc-encryption-callout" data-testid="registry-change-encryption-callout" role="note">
          <div class="rc-encryption-label">{REGISTRY_CHANGE_COPY.encryptionRowLabel}</div>
          <p class="rc-encryption-body">
            {#if widgetState.encryptionAfterHost}
              {REGISTRY_CHANGE_COPY.encryptionChangedLine(widgetState.encryptionAfterHost)}
            {:else}
              {REGISTRY_CHANGE_COPY.encryptionClearedLine}
            {/if}
          </p>
        </div>
      {/if}

      {#if widgetState.warnings.length > 0}
        <div class="rc-warnings" data-testid="registry-change-identity-warnings" role="alert">
          <ul>
            {#each widgetState.warnings as warning (warning.url)}
              <li>{warning.message}</li>
            {/each}
          </ul>
          <p class="rc-warning-footer">{REGISTRY_CHANGE_COPY.identityWarningFooter}</p>
        </div>
      {/if}

      {#if widgetState.error}
        <p class="rc-error" role="alert">{widgetState.error}</p>
      {/if}

      <div class="rc-actions">
        <button
          type="button"
          class="rc-btn rc-btn-primary approve"
          disabled={widgetState.phase === 'submitting' || !widgetState.passkey}
          onclick={approve}
        >
          {widgetState.phase === 'submitting'
            ? REGISTRY_CHANGE_COPY.approvingButton
            : REGISTRY_CHANGE_COPY.approveButton}
        </button>
        <button
          type="button"
          class="rc-btn rc-btn-secondary"
          disabled={widgetState.phase === 'submitting'}
          onclick={cancel}
        >
          {REGISTRY_CHANGE_COPY.cancelButton}
        </button>
      </div>
    </section>
  {/if}
</main>

<style>
  .rc-shell {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #111827;
    background: #fafafa;
    padding: 20px;
    max-width: 440px;
    margin: 0 auto;
    box-sizing: border-box;
  }

  .rc-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .rc-title {
    margin: 0;
    font-size: 20px;
    font-weight: 600;
    line-height: 1.3;
  }

  .rc-origin {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
    color: #1f2937;
    word-break: break-word;
  }

  .rc-text,
  .rc-risk {
    margin: 0;
    font-size: 13px;
    line-height: 1.5;
    color: #374151;
  }

  .rc-risk {
    color: #1f2937;
  }

  .rc-muted {
    margin: 0;
    font-size: 13px;
    color: #6b7280;
  }

  .rc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    overflow: hidden;
  }

  .rc-table th,
  .rc-table td {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid #e5e7eb;
    word-break: break-word;
  }

  .rc-table th {
    background: #f3f4f6;
    font-weight: 600;
    color: #374151;
  }

  .rc-table tr:last-child td {
    border-bottom: none;
  }

  .rc-row-encryption td {
    background: #fdf2f8;
    color: #831843;
    font-weight: 600;
  }

  /* Distinct colour reserved for encryption-node changes (design-bobbie §3). */
  .rc-encryption-callout {
    background: #fdf2f8;
    border: 1px solid #db2777;
    border-left: 4px solid #be185d;
    border-radius: 8px;
    padding: 10px 12px;
    color: #831843;
  }

  .rc-encryption-label {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    margin-bottom: 4px;
  }

  .rc-encryption-body {
    margin: 0;
    font-size: 13px;
    line-height: 1.45;
  }

  .rc-warnings {
    background: #fffbeb;
    border: 1px solid #f59e0b;
    border-radius: 8px;
    padding: 10px 12px;
    color: #92400e;
    font-size: 13px;
  }

  .rc-warnings ul {
    margin: 0 0 6px;
    padding-left: 18px;
  }

  .rc-warning-footer {
    margin: 0;
    font-size: 12px;
  }

  .rc-error {
    margin: 0;
    font-size: 13px;
    color: #b91c1c;
    background: #fef2f2;
    border: 1px solid #fecaca;
    border-radius: 6px;
    padding: 8px 10px;
  }

  .rc-success {
    margin: 0;
    font-size: 14px;
    color: #065f46;
    background: #ecfdf5;
    border: 1px solid #a7f3d0;
    border-radius: 6px;
    padding: 10px 12px;
  }

  .rc-actions {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 4px;
  }

  .rc-btn {
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid transparent;
  }

  .rc-btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  .rc-btn-primary {
    background: #111827;
    color: #ffffff;
  }

  .rc-btn-secondary {
    background: #ffffff;
    color: #374151;
    border-color: #d1d5db;
  }
</style>
