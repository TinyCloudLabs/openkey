<script lang="ts">
  // SigningApproval — the single canonical content view for every OpenKey
  // authorization surface.
  //
  // It receives:
  //   - `model`: CapabilityReviewModel (parsed from the raw request).
  //   - `selection`: the set of currently-selected action IDs.
  //   - `editing`: whether the edit affordance is expanded.
  //   - callbacks for intent: onApprove, onCancel, onSelectionChange, onEditingChange.
  //
  // It does NOT:
  //   - open popups or iframes
  //   - resolve wallets or select keys
  //   - decide authentication mode
  //   - talk to the API
  //   - size itself for a specific transport
  //   - branch on "CLI" / "popup" / "iframe" — those are container-only
  //
  // Callers wire the transport (widget-transport.ts) and completion.

  import type {
    CapabilityAction,
    CapabilityGrant,
    CapabilityReviewModel,
  } from "@openkey/capability-review";
  import {
    buildRenderPlan,
    grantHeading,
    PROTOCOL_HEADLINE,
    PROTOCOL_HINT,
  } from "@openkey/capability-review";

  interface Props {
    model: CapabilityReviewModel;
    selection: Set<string>;
    editing: boolean;
    approving?: boolean;
    error?: string | null;
    onApprove: () => void;
    onCancel: () => void;
    onSelectionChange: (next: Set<string>) => void;
    onEditingChange: (next: boolean) => void;
  }

  let {
    model,
    selection,
    editing,
    approving = false,
    error = null,
    onApprove,
    onCancel,
    onSelectionChange,
    onEditingChange,
  }: Props = $props();

  const renderPlan = $derived(buildRenderPlan(model.permissions));
  const isEditable = $derived(model.protocol === "tinycloud-siwe-recap");
  const headline = $derived(PROTOCOL_HEADLINE[model.protocol]);
  const hint = $derived(PROTOCOL_HINT[model.protocol]);

  function isSelected(action: CapabilityAction): boolean {
    return selection.has(action.id);
  }

  function toggle(action: CapabilityAction) {
    if (!action.editable) return;
    const next = new Set(selection);
    if (next.has(action.id)) next.delete(action.id);
    else next.add(action.id);
    onSelectionChange(next);
  }

  function resetSelection() {
    const next = new Set<string>();
    for (const grant of model.permissions) {
      for (const action of grant.actions) {
        if (action.selected) next.add(action.id);
      }
    }
    onSelectionChange(next);
  }

  function handleKeydown(event: KeyboardEvent, action: CapabilityAction) {
    if (!action.editable) return;
    if (event.key === " " || event.key === "Enter") {
      event.preventDefault();
      toggle(action);
    }
  }

  const trustLabel: Record<CapabilityReviewModel["metadataTrust"]["status"], string> = {
    verified: "Manifest verified",
    unsigned: "No signed manifest",
    stale: "Manifest signature is stale",
    "wrong-key": "Manifest signed by an unknown key",
    "digest-mismatch": "Manifest digest does not match declared content",
  };

  const severityLabel: Record<CapabilityGrant["severity"], string> = {
    standard: "Standard",
    attention: "Attention",
    sensitive: "Sensitive",
  };
</script>

<div
  class="signing-approval"
  role="dialog"
  aria-modal="true"
  aria-labelledby="signing-approval-headline"
  aria-describedby="signing-approval-hint"
  tabindex="-1"
>
  <header class="header">
    <h2 id="signing-approval-headline" class="headline">{headline}</h2>
    <p id="signing-approval-hint" class="hint">{hint}</p>
  </header>

  <section class="identity" aria-label="Requester identity">
    <div class="row">
      <span class="label">Requester</span>
      <span class="value">{model.requester.displayName}</span>
    </div>
    {#if model.requester.verifiedOrigin}
      <div class="row">
        <span class="label">Origin</span>
        <code class="value mono">{model.requester.verifiedOrigin}</code>
        {#if model.requester.originWarning}
          <span class="warn" role="status">Origin does not match SIWE domain</span>
        {/if}
      </div>
    {/if}
    <div class="row">
      <span class="label">Manifest trust</span>
      <span class="value">{trustLabel[model.metadataTrust.status]}</span>
    </div>
    {#if model.metadataTrust.reason}
      <p class="metadata-reason">{model.metadataTrust.reason}</p>
    {/if}
  </section>

  {#if model.reason.source !== "none" && model.reason.text}
    <section class="reason" aria-label="Reason for request">
      <div class="row">
        <span class="label">Reason provided by {model.reason.source}</span>
      </div>
      <p class="reason-body">{model.reason.text}</p>
      {#if model.reason.source === "caller"}
        <p class="reason-untrusted">
          This reason comes from the caller and is not verified.
        </p>
      {/if}
    </section>
  {/if}

  <section class="signer" aria-label="Signer">
    <div class="row">
      <span class="label">Signing with</span>
      <span class="value">{model.signer.label}</span>
      <code class="value mono">{model.signer.address}</code>
    </div>
    {#if model.expiry}
      <div class="row">
        <span class="label">Expires</span>
        <span class="value">{model.expiry}</span>
      </div>
    {/if}
  </section>

  {#if model.permissions.length > 0}
    <section class="permissions" aria-label="Requested permissions">
      <div class="permissions-header">
        <h3 class="permissions-heading">Requested permissions</h3>
        {#if isEditable}
          <div class="permissions-actions">
            <button
              type="button"
              class="link"
              onclick={() => onEditingChange(!editing)}
              aria-expanded={editing}
              disabled={approving}
            >
              {editing ? "Done editing" : "Edit"}
            </button>
            <button
              type="button"
              class="link"
              onclick={resetSelection}
              disabled={approving}
            >
              Reset
            </button>
          </div>
        {/if}
      </div>

      {#each renderPlan as bucket}
        <section class="severity-bucket" data-severity={bucket.severity} aria-label={bucket.heading}>
          <h4 class="bucket-heading">{bucket.heading}</h4>
          <p class="bucket-hint">{bucket.hint}</p>
          <ul class="grant-list">
            {#each bucket.grants as grant}
              <li class="grant">
                <div class="grant-heading">
                  <span class="grant-title">{grantHeading(grant)}</span>
                  <span class="grant-severity" data-severity={grant.severity}>
                    {severityLabel[grant.severity]}
                  </span>
                </div>
                <code class="grant-path mono">
                  {grant.service} · {grant.space}{grant.path ? "/" + grant.path : ""}
                </code>
                {#if grant.ownedBySelf === false}
                  <p class="cross-app-warning">
                    Cross-app data owned by {grant.owner}
                  </p>
                {/if}
                <ul class="action-list">
                  {#each grant.actions as action}
                    <li class="action">
                      {#if editing && action.editable}
                        <label class="action-toggle">
                          <input
                            type="checkbox"
                            checked={isSelected(action)}
                            onchange={() => toggle(action)}
                            onkeydown={(e) => handleKeydown(e, action)}
                            disabled={approving}
                          />
                          <span class="verb">{action.verb}</span>
                        </label>
                      {:else}
                        <span class="action-static" class:selected={isSelected(action)}>
                          <span class="verb">{action.verb}</span>
                          {#if action.required}
                            <span class="required-flag">required</span>
                          {/if}
                        </span>
                      {/if}
                    </li>
                  {/each}
                </ul>
              </li>
            {/each}
          </ul>
        </section>
      {/each}
    </section>
  {/if}

  {#if model.parseWarnings.length > 0}
    <section class="warnings" aria-label="Parser warnings">
      <h4 class="warnings-heading">Notes</h4>
      <ul>
        {#each model.parseWarnings as warning}
          <li class="warning">
            <code class="warning-code mono">{warning.code}</code>
            {warning.message}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <details class="raw-details">
    <summary>Show exact bytes being signed</summary>
    <pre class="raw-bytes" aria-live="polite">{model.rawMessage}</pre>
  </details>

  {#if error}
    <p class="error" role="alert" aria-live="polite">{error}</p>
  {/if}

  <footer class="actions">
    <button type="button" class="cancel" onclick={onCancel} disabled={approving}>
      Cancel
    </button>
    <button type="button" class="approve" onclick={onApprove} disabled={approving}>
      {approving ? "Signing…" : "Approve"}
    </button>
  </footer>
</div>

<style>
  .signing-approval {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 20px;
    background: #fafafa;
    border-radius: 12px;
    color: #111;
    max-width: 480px;
    margin: 0 auto;
  }
  .header {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .headline {
    font-size: 18px;
    font-weight: 600;
    margin: 0;
  }
  .hint {
    font-size: 13px;
    color: #555;
    margin: 0;
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    font-size: 13px;
    padding: 4px 0;
  }
  .label {
    color: #666;
    font-weight: 500;
    min-width: 100px;
  }
  .value {
    color: #111;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    color: #333;
    word-break: break-all;
  }
  .warn {
    background: #fff4d6;
    color: #995000;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
  }
  .metadata-reason,
  .reason-body,
  .reason-untrusted {
    margin: 4px 0 0;
    font-size: 12px;
    color: #666;
  }
  .reason-untrusted {
    color: #995000;
  }
  .permissions {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .permissions-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .permissions-heading {
    font-size: 14px;
    font-weight: 600;
    margin: 0;
  }
  .permissions-actions {
    display: flex;
    gap: 8px;
  }
  .link {
    background: none;
    border: none;
    color: #555;
    text-decoration: underline;
    cursor: pointer;
    font-size: 12px;
    padding: 0;
  }
  .link:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .severity-bucket {
    background: #fff;
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    padding: 12px;
  }
  .severity-bucket[data-severity="sensitive"] {
    border-color: #d99b9b;
    background: #fff5f5;
  }
  .severity-bucket[data-severity="attention"] {
    border-color: #d9c99b;
    background: #fffaf0;
  }
  .bucket-heading {
    font-size: 13px;
    font-weight: 600;
    margin: 0 0 4px;
  }
  .bucket-hint {
    font-size: 12px;
    color: #555;
    margin: 0 0 8px;
  }
  .grant-list,
  .action-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .grant {
    background: #f8f8f8;
    border-radius: 6px;
    padding: 8px;
  }
  .grant-heading {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 6px;
  }
  .grant-title {
    font-size: 13px;
    font-weight: 500;
  }
  .grant-severity[data-severity="sensitive"] {
    color: #9f2424;
    font-weight: 600;
    font-size: 11px;
  }
  .grant-severity[data-severity="attention"] {
    color: #995000;
    font-weight: 600;
    font-size: 11px;
  }
  .grant-severity[data-severity="standard"] {
    color: #14733b;
    font-weight: 500;
    font-size: 11px;
  }
  .grant-path {
    display: block;
    margin: 4px 0;
  }
  .cross-app-warning {
    color: #9f2424;
    font-size: 12px;
    margin: 4px 0;
  }
  .action-list {
    flex-direction: row;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 6px;
  }
  .action-toggle,
  .action-static {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 4px;
    background: #fff;
    border: 1px solid #ddd;
    font-size: 12px;
  }
  .action-static.selected {
    background: #eef;
    border-color: #99a;
  }
  .required-flag {
    color: #666;
    font-size: 10px;
  }
  .warnings {
    background: #fff4d6;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 12px;
    color: #6e4b0f;
  }
  .warnings-heading {
    margin: 0 0 4px;
    font-size: 12px;
    font-weight: 600;
  }
  .warning {
    margin: 2px 0;
  }
  .warning-code {
    background: #fff;
    padding: 1px 4px;
    border-radius: 3px;
    margin-right: 4px;
    font-size: 11px;
  }
  .raw-details {
    background: #fff;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
  }
  .raw-bytes {
    background: #111;
    color: #eee;
    padding: 8px;
    border-radius: 4px;
    overflow: auto;
    max-height: 200px;
    font-size: 11px;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .error {
    background: #fff0f0;
    color: #9f2424;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 12px;
    margin: 0;
  }
  .actions {
    display: flex;
    gap: 8px;
  }
  .cancel,
  .approve {
    flex: 1;
    padding: 10px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border: none;
  }
  .cancel {
    background: #eee;
    color: #333;
  }
  .approve {
    background: #111;
    color: #fff;
  }
  .cancel:disabled,
  .approve:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  @media (prefers-reduced-motion: reduce) {
    .signing-approval * {
      transition: none !important;
      animation: none !important;
    }
  }
</style>
