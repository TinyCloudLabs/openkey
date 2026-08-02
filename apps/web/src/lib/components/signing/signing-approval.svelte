<script lang="ts">
  // SigningApproval — the single canonical content view for every OpenKey
  // authorization surface.
  //
  // Structural rules (from the merge-readiness contract):
  //   1. Default view is small, deterministic, and derived from the actual
  //      SIWE/ReCap request PLUS explicitly provenance-labelled manifest
  //      data. It surfaces the requester, a short list of understandable
  //      statements (from statements.ts), and a pinned sensitive callout
  //      when any grant reaches secret data or decryption.
  //   2. A SINGLE `<details>` element labelled `Advanced details` contains:
  //      requester, verified browser origin, manifest name/appId/digest with
  //      HONEST trust/provenance label, reason (only when present), signing
  //      identity, categorized exact-grant list, Edit/Reset controls, the
  //      full raw message as `<pre>` (`user-select: text`) plus a
  //      `Copy text` button that copies `model.rawMessage` UNMODIFIED.
  //   3. `originWarning` and `domainWarning` render distinctly — a concrete
  //      but mismatched origin MUST NOT hide the SIWE-domain mismatch.
  //   4. Approve is blocked when `model.protocol === "malformed-recap"`.
  //   5. `manifestLabel/appId/digest` render only under a truthful
  //      `metadataTrust.status` — never claim `verified` for
  //      caller-supplied metadata.
  //
  // It does NOT:
  //   - open popups or iframes
  //   - resolve wallets or select keys
  //   - decide authentication mode
  //   - talk to the API
  //   - size itself for a specific transport
  //   - branch on "CLI" / "popup" / "iframe" — those are container-only

  import type {
    CapabilityAction,
    CapabilityGrant,
    CapabilityReviewModel,
  } from "@openkey/capability-review";
  import {
    buildRenderPlan,
    buildStatement,
    grantHeading,
    PROTOCOL_HEADLINE,
    PROTOCOL_HINT,
    sensitiveCallout,
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
  const isMalformedRecap = $derived(model.protocol === "malformed-recap");
  const headline = $derived(
    isMalformedRecap
      ? "Refusing to sign: malformed capability payload"
      : PROTOCOL_HEADLINE[model.protocol],
  );
  const hint = $derived(
    isMalformedRecap
      ? "This message carries a capability payload we could not decode. Refusing to approve so the request cannot be silently degraded to an exact-byte SIWE signature."
      : PROTOCOL_HINT[model.protocol],
  );

  // Statements for the summary view. Derived structurally from grants.
  const summaryStatements = $derived(
    model.permissions.map((grant) => ({
      grant,
      statement: buildStatement(grant),
    })),
  );

  // A grant is "sensitive" when its structural severity is `sensitive` OR
  // its family reaches secret or decryption data. The callout counts each
  // exact grant that meets this bar.
  function isSensitiveByReach(grant: CapabilityGrant): boolean {
    if (grant.severity === "sensitive") return true;
    return (
      grant.family === "secret-read" ||
      grant.family === "secret-mutation" ||
      grant.family === "encryption-decrypt" ||
      grant.family === "encryption-key"
    );
  }
  const sensitiveCount = $derived(
    model.permissions.filter(isSensitiveByReach).length,
  );

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

  // Honest trust labels. Each status maps to a phrase that describes ONLY
  // what the widget can prove — never overstates verification.
  const trustLabel: Record<
    CapabilityReviewModel["metadataTrust"]["status"],
    string
  > = {
    verified: "Manifest signature verified",
    "origin-bound": "Manifest served by verified https origin",
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

  // Copy-to-clipboard for the raw message. Uses the Async Clipboard API
  // and falls back to a hidden textarea + execCommand for older browsers.
  // The clipboard receives `model.rawMessage` EXACTLY — no normalization.
  let copyState = $state<"idle" | "copied" | "failed">("idle");
  async function copyRawMessage() {
    const text = model.rawMessage;
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(text);
        copyState = "copied";
      } else {
        // Legacy fallback
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "absolute";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        copyState = ok ? "copied" : "failed";
      }
    } catch {
      copyState = "failed";
    }
    setTimeout(() => {
      copyState = "idle";
    }, 2000);
  }

  const approveDisabled = $derived(approving || isMalformedRecap);
  const approveLabel = $derived(
    isMalformedRecap
      ? "Cannot approve"
      : approving
        ? "Signing…"
        : "Approve",
  );
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

  <!--
    Sensitive callout pinned at the top. Exact copy from the contract.
    Rendered only when at least one grant reaches secret data or decryption.
  -->
  {#if sensitiveCount > 0}
    <p class="sensitive-callout" role="status" aria-live="polite">
      {sensitiveCallout(sensitiveCount)}
    </p>
  {/if}

  <!--
    Default summary: requester + short list of deterministic statements.
    Never invents friendly semantics for unknown shapes (see statements.ts).
  -->
  <section class="summary" aria-label="Requested access">
    <div class="summary-requester">
      <span class="summary-requester-label">Requester</span>
      <span class="summary-requester-value">{model.requester.displayName}</span>
    </div>
    {#if summaryStatements.length > 0}
      <ul class="summary-statements">
        {#each summaryStatements as { grant, statement } (grant.id)}
          <li
            class="summary-statement"
            data-severity={grant.severity}
            data-family={grant.family}
          >
            <span class="statement-primary">{statement.primaryText}</span>
            <span class="statement-secondary">
              <code class="mono">{statement.service}</code>
              <span class="statement-resource" title={statement.resource}>
                {statement.resource}
              </span>
            </span>
          </li>
        {/each}
      </ul>
    {:else if !isMalformedRecap}
      <p class="summary-empty">No capability payload — exact-byte signature only.</p>
    {/if}
  </section>

  <!--
    Single Advanced details disclosure. Contains: requester, verified
    origin, manifest name/appId/digest + honest trust label, reason (when
    present), signing identity, categorized exact-grant list with
    Edit/Reset controls, full raw message + Copy text.
  -->
  <details class="advanced-details">
    <summary class="advanced-summary">Advanced details</summary>

    <section class="identity" aria-label="Requester identity">
      <div class="row">
        <span class="label">Requester</span>
        <span class="value">{model.requester.displayName}</span>
      </div>

      {#if model.requester.verifiedOrigin}
        <div class="row">
          <span class="label">Verified browser origin</span>
          <code class="value mono">{model.requester.verifiedOrigin}</code>
        </div>
      {/if}

      <!--
        `originWarning` and `domainWarning` render INDEPENDENTLY. A
        concrete verified origin that disagrees with the SIWE domain must
        show BOTH warnings — never mask domainWarning behind originWarning.
      -->
      {#if model.requester.originWarning}
        <div class="row">
          <span class="warn" role="status">
            Origin warning: parent frame could not be attributed to a specific origin
          </span>
        </div>
      {/if}
      {#if model.requester.domainWarning}
        <div class="row">
          <span class="warn" role="status">
            Domain warning: SIWE domain does not match the verified browser origin
          </span>
        </div>
      {/if}

      <!--
        Sol MAJOR-4: render `manifestName` as a distinct field with its
        provenance stamp. `origin-bound` fields come from a well-known
        manifest whose digest matched the caller-supplied envelope;
        `caller` fields are unverified envelope echoes and MUST carry a
        visible "unverified" hint so an operator cannot mistake them for
        a trusted label. Server code never marks a caller-echoed name as
        origin-bound — see the popup/embed prepare handlers.
      -->
      {#if model.requester.manifestName}
        <div class="row">
          <span class="label">Manifest name</span>
          <span class="value">{model.requester.manifestName}</span>
          <span
            class="provenance-tag"
            data-provenance={model.requester.manifestNameProvenance}
          >
            {#if model.requester.manifestNameProvenance === "verified"}
              signed manifest
            {:else if model.requester.manifestNameProvenance === "origin-bound"}
              from origin-bound manifest
            {:else if model.requester.manifestNameProvenance === "caller"}
              caller-supplied, unverified
            {/if}
          </span>
        </div>
      {/if}

      <!--
        Sol minor: render `appId` and `manifestId` as SEPARATE Advanced-
        details rows. `appId` names the app (from the manifest's
        `app_id`); `manifestId` is the versioned identifier of the
        manifest itself. They agree only when a manifest is unversioned
        and both fields have been set to the same string; anywhere
        else, showing only `manifestId` would hide "which app is this?"
        from the operator.
      -->
      {#if model.requester.appId}
        <div class="row">
          <span class="label">App ID</span>
          <code class="value mono">{model.requester.appId}</code>
        </div>
      {/if}
      {#if model.requester.manifestId}
        <div class="row">
          <span class="label">Manifest ID</span>
          <code class="value mono">{model.requester.manifestId}</code>
          <span
            class="provenance-tag"
            data-provenance={model.requester.manifestIdProvenance}
          >
            {#if model.requester.manifestIdProvenance === "verified"}
              signed manifest
            {:else if model.requester.manifestIdProvenance === "origin-bound"}
              from origin-bound manifest
            {:else if model.requester.manifestIdProvenance === "caller"}
              caller-supplied, unverified
            {/if}
          </span>
        </div>
      {/if}
      {#if model.requester.manifestDigest}
        <div class="row">
          <span class="label">Manifest digest</span>
          <code class="value mono">{model.requester.manifestDigest}</code>
        </div>
      {/if}
      <div class="row">
        <span class="label">Manifest trust</span>
        <span
          class="value trust-value"
          data-trust={model.metadataTrust.status}
        >
          {trustLabel[model.metadataTrust.status]}
        </span>
      </div>
      {#if model.metadataTrust.reason}
        <p class="metadata-reason">{model.metadataTrust.reason}</p>
      {/if}
    </section>

    <!-- Reason only when a reason actually exists. -->
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

    <section class="signer" aria-label="Signing identity">
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
      <section class="permissions" aria-label="Exact grants">
        <div class="permissions-header">
          <h3 class="permissions-heading">Exact grants</h3>
          {#if isEditable}
            <div class="permissions-actions">
              <button
                type="button"
                class="link"
                onclick={() => onEditingChange(!editing)}
                aria-expanded={editing}
                disabled={approveDisabled}
              >
                {editing ? "Done editing" : "Edit"}
              </button>
              <button
                type="button"
                class="link"
                onclick={resetSelection}
                disabled={approveDisabled}
              >
                Reset
              </button>
            </div>
          {/if}
        </div>

        {#each renderPlan as bucket}
          <section
            class="severity-bucket"
            data-severity={bucket.severity}
            aria-label={bucket.heading}
          >
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
                    {grant.service} · {grant.space}{grant.path
                      ? "/" + grant.path
                      : ""}
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
                              disabled={approveDisabled}
                            />
                            <span class="verb">{action.verb}</span>
                          </label>
                        {:else}
                          <span
                            class="action-static"
                            class:selected={isSelected(action)}
                          >
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

    <section class="raw" aria-label="Raw message that will be signed">
      <div class="raw-header">
        <h4 class="raw-heading">Exact bytes being signed</h4>
        <button
          type="button"
          class="copy-btn"
          onclick={copyRawMessage}
          aria-label="Copy text"
        >
          {copyState === "copied"
            ? "Copied"
            : copyState === "failed"
              ? "Copy failed"
              : "Copy text"}
        </button>
      </div>
      <pre class="raw-bytes" aria-live="polite">{model.rawMessage}</pre>
    </section>
  </details>

  {#if error}
    <p class="error" role="alert" aria-live="polite">{error}</p>
  {/if}

  <footer class="actions">
    <button
      type="button"
      class="cancel"
      onclick={onCancel}
      disabled={approving}
    >
      Cancel
    </button>
    <button
      type="button"
      class="approve"
      onclick={onApprove}
      disabled={approveDisabled}
      aria-disabled={approveDisabled}
    >
      {approveLabel}
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
  .sensitive-callout {
    background: #fff5f5;
    color: #9f2424;
    border: 1px solid #d99b9b;
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 13px;
    margin: 0;
    font-weight: 500;
  }
  .summary {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .summary-requester {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 8px;
    font-size: 13px;
  }
  .summary-requester-label {
    color: #666;
    font-weight: 500;
  }
  .summary-requester-value {
    color: #111;
    font-weight: 600;
  }
  .summary-statements {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .summary-statement {
    background: #fff;
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .summary-statement[data-severity="sensitive"] {
    border-color: #d99b9b;
    background: #fff5f5;
  }
  .summary-statement[data-severity="attention"] {
    border-color: #d9c99b;
    background: #fffaf0;
  }
  .statement-primary {
    font-size: 13px;
    font-weight: 500;
    color: #111;
  }
  .statement-secondary {
    display: flex;
    gap: 6px;
    align-items: baseline;
    color: #666;
    font-size: 11px;
    flex-wrap: wrap;
  }
  .statement-resource {
    word-break: break-all;
    color: #555;
  }
  .summary-empty {
    color: #666;
    font-size: 12px;
    margin: 0;
  }
  .advanced-details {
    background: #fff;
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .advanced-summary {
    cursor: pointer;
    font-weight: 600;
    color: #333;
    padding: 4px 0;
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
    min-width: 140px;
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
  .trust-value {
    font-weight: 500;
  }
  .trust-value[data-trust="verified"] {
    color: #14733b;
  }
  .trust-value[data-trust="origin-bound"] {
    color: #4a6f2f;
  }
  .trust-value[data-trust="unsigned"] {
    color: #666;
  }
  .trust-value[data-trust="stale"],
  .trust-value[data-trust="wrong-key"],
  .trust-value[data-trust="digest-mismatch"] {
    color: #9f2424;
  }
  .warn {
    background: #fff4d6;
    color: #995000;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
  }
  /*
    Sol MAJOR-4: provenance tags are attached to Advanced-details fields
    whose value came from a caller-echoed envelope. They exist so an
    operator can never mistake a `caller-supplied, unverified` string
    for an OpenKey-verified identity. The `caller` variant is styled
    like the domain warning; `origin-bound` and `verified` variants are
    neutral so they do not compete with content.
  */
  .provenance-tag {
    font-size: 11px;
    padding: 1px 6px;
    border-radius: 4px;
    line-height: 1.2;
  }
  .provenance-tag[data-provenance="verified"] {
    background: #e6f7ea;
    color: #14733b;
  }
  .provenance-tag[data-provenance="origin-bound"] {
    background: #eef1e6;
    color: #4a6f2f;
  }
  .provenance-tag[data-provenance="caller"] {
    background: #fff4d6;
    color: #995000;
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
  .raw {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .raw-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .raw-heading {
    font-size: 13px;
    font-weight: 600;
    margin: 0;
  }
  .copy-btn {
    background: #fff;
    border: 1px solid #ccc;
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 12px;
    cursor: pointer;
    color: #333;
  }
  .copy-btn:hover {
    background: #eee;
  }
  .raw-bytes {
    background: #111;
    color: #eee;
    padding: 8px;
    border-radius: 4px;
    overflow: auto;
    max-height: 240px;
    font-size: 11px;
    white-space: pre-wrap;
    word-break: break-word;
    user-select: text;
    -webkit-user-select: text;
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
