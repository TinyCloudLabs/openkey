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
    grantReachesSecretDataOrDecryption,
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
    finalPreview?: boolean;
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
    finalPreview = false,
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
      : finalPreview && model.protocol === "tinycloud-siwe-recap"
        ? "Review the server-prepared request. Approving signs the exact bytes shown in Advanced details."
      : PROTOCOL_HINT[model.protocol],
  );

  // Summary copy and the sensitive count describe only actions the user is
  // currently approving. Advanced details deliberately retains the baseline
  // grants so Edit/Reset can re-add a removed action, but a removed decrypt or
  // secret action must never survive in the top-level final review.
  const selectedGrants = $derived(
    model.permissions.flatMap((grant) => {
      const actions = grant.actions.filter((action) => selection.has(action.id));
      return actions.length > 0 ? [{ ...grant, actions }] : [];
    }),
  );

  // Statements for the summary view. Group by primary text so repeated
  // statements collapse into one visible row while preserving the strongest
  // severity and an exact-grant/service count in the compact secondary copy.
  const summaryStatements = $derived.by(() => {
    const severityRank: Record<CapabilityGrant["severity"], number> = {
      standard: 0,
      attention: 1,
      sensitive: 2,
    };

    const grouped = new Map<
      string,
      {
        key: string;
        primaryText: string;
        count: number;
        severity: CapabilityGrant["severity"];
        services: string[];
        resource: string;
      }
    >();

    for (const grant of selectedGrants) {
      const statement = buildStatement(grant);
      const existing = grouped.get(statement.primaryText);
      if (existing) {
        existing.count += 1;
        if (severityRank[grant.severity] > severityRank[existing.severity]) {
          existing.severity = grant.severity;
        }
        if (!existing.services.includes(statement.service)) {
          existing.services.push(statement.service);
        }
      } else {
        grouped.set(statement.primaryText, {
          key: grant.id,
          primaryText: statement.primaryText,
          count: 1,
          severity: grant.severity,
          services: [statement.service],
          resource: statement.resource,
        });
      }
    }

    return [...grouped.values()];
  });

  const sensitiveCount = $derived(
    selectedGrants.filter(grantReachesSecretDataOrDecryption).length,
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
        : finalPreview
          ? "Approve exact bytes"
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
        {#each summaryStatements as statement (statement.key)}
          <li
            class="summary-statement"
            data-severity={statement.severity}
            data-count={statement.count}
          >
            <span class="statement-primary">{statement.primaryText}</span>
            <span class="statement-secondary">
              <span class="summary-meta">
                {statement.count} exact grant{statement.count === 1 ? "" : "s"} ·
                {statement.services.join(", ")}
              </span>
              {#if statement.count === 1}
                <span class="statement-resource" title={statement.resource}>
                  {statement.resource}
                </span>
              {/if}
            </span>
          </li>
        {/each}
      </ul>
    {:else if !isMalformedRecap}
      <p class="summary-empty">
        {model.permissions.length > 0
          ? "No optional access selected."
          : "No capability payload — exact-byte signature only."}
      </p>
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
                    <span class="grant-service">{grant.service}</span>
                    <span class="grant-target">
                      {grant.space}{grant.path ? "/" + grant.path : ""}
                    </span>
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
    gap: 14px;
    width: min(100%, 560px);
    max-width: 560px;
    margin: 0 auto;
    padding: 18px;
    box-sizing: border-box;
    background: #fff;
    border: 1px solid #dbe2ea;
    border-radius: 16px;
    color: #0f172a;
  }
  .header {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .headline {
    font-size: 20px;
    font-weight: 700;
    line-height: 1.2;
    margin: 0;
    text-wrap: balance;
  }
  .hint {
    font-size: 14px;
    line-height: 1.5;
    color: #475569;
    margin: 0;
  }
  .sensitive-callout {
    background: #fff7ed;
    color: #9a3412;
    border: 1px solid #fdba74;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 13px;
    line-height: 1.45;
    margin: 0;
    font-weight: 600;
  }
  .summary {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 14px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
  }
  .summary-requester {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 8px;
    font-size: 13px;
  }
  .summary-requester-label {
    color: #475569;
    font-weight: 600;
  }
  .summary-requester-value {
    color: #0f172a;
    font-weight: 700;
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
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .summary-statement[data-severity="sensitive"] {
    border-color: #f2c0c0;
    background: #fff7f7;
  }
  .summary-statement[data-severity="attention"] {
    border-color: #ead8a5;
    background: #fffbf3;
  }
  .statement-primary {
    font-size: 13px;
    line-height: 1.45;
    font-weight: 600;
    color: #0f172a;
  }
  .statement-secondary {
    display: flex;
    flex-direction: column;
    gap: 2px;
    align-items: flex-start;
    color: #475569;
    font-size: 11px;
    line-height: 1.4;
  }
  .summary-meta {
    color: #475569;
    font-weight: 600;
  }
  .statement-resource {
    word-break: break-word;
    color: #334155;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .summary-empty {
    color: #475569;
    font-size: 13px;
    line-height: 1.45;
    margin: 0;
  }
  .advanced-details {
    background: #fff;
    border: 1px solid #dbe2ea;
    border-radius: 14px;
    padding: 12px 14px;
    font-size: 13px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .advanced-details[open] {
    background: #fbfdff;
    border-color: #cfd8e3;
  }
  .advanced-summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    cursor: pointer;
    font-weight: 700;
    color: #0f172a;
    padding: 2px 0 6px;
    list-style: none;
  }
  .advanced-summary::-webkit-details-marker {
    display: none;
  }
  .advanced-summary::after {
    content: "▾";
    color: #64748b;
    transition: transform 160ms ease;
  }
  .advanced-details[open] .advanced-summary::after {
    transform: rotate(180deg);
  }
  .row {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    flex-wrap: wrap;
    font-size: 13px;
    line-height: 1.45;
    padding: 3px 0;
  }
  .label {
    color: #475569;
    font-weight: 600;
    min-width: 136px;
  }
  .value {
    color: #0f172a;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    color: #334155;
    word-break: break-word;
  }
  .trust-value {
    font-weight: 600;
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
    background: #fef3c7;
    color: #92400e;
    border: 1px solid #fde68a;
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 12px;
    line-height: 1.35;
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
    padding: 2px 8px;
    border-radius: 999px;
    line-height: 1.2;
    border: 1px solid transparent;
  }
  .provenance-tag[data-provenance="verified"] {
    background: #eefbf3;
    color: #14733b;
  }
  .provenance-tag[data-provenance="origin-bound"] {
    background: #f1f5eb;
    color: #4a6f2f;
  }
  .provenance-tag[data-provenance="caller"] {
    background: #fff7ed;
    color: #9a3412;
    border-color: #fdba74;
  }
  .metadata-reason,
  .reason-body,
  .reason-untrusted {
    margin: 4px 0 0;
    font-size: 12px;
    line-height: 1.45;
    color: #475569;
  }
  .reason-untrusted {
    color: #9a3412;
  }
  .permissions {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .permissions-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .permissions-heading {
    font-size: 15px;
    font-weight: 700;
    margin: 0;
    color: #0f172a;
  }
  .permissions-actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  }
  .link {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 12px;
    padding: 0;
    font-weight: 600;
    color: #334155;
    text-decoration: underline;
    text-underline-offset: 2px;
  }
  .link:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .severity-bucket {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 12px;
    min-width: 0;
  }
  .severity-bucket[data-severity="sensitive"] {
    border-color: #f2c0c0;
    background: #fff7f7;
  }
  .severity-bucket[data-severity="attention"] {
    border-color: #ead8a5;
    background: #fffbf3;
  }
  .bucket-heading {
    font-size: 13px;
    font-weight: 700;
    margin: 0 0 4px;
    color: #0f172a;
  }
  .bucket-hint {
    font-size: 12px;
    line-height: 1.45;
    color: #475569;
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
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 10px 12px;
    min-width: 0;
  }
  .grant-heading {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 8px;
    min-width: 0;
  }
  .grant-title {
    font-size: 13px;
    line-height: 1.45;
    font-weight: 600;
    color: #0f172a;
    min-width: 0;
    overflow-wrap: anywhere;
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
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin: 6px 0 0;
    min-width: 0;
  }
  .grant-service {
    color: #64748b;
    font-size: 11px;
    line-height: 1.2;
  }
  .grant-target {
    color: #334155;
    line-height: 1.35;
    overflow-wrap: anywhere;
    word-break: break-word;
  }
  .cross-app-warning {
    color: #9a3412;
    font-size: 12px;
    line-height: 1.45;
    margin: 6px 0 0;
    font-weight: 600;
  }
  .action-list {
    flex-direction: row;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
  }
  .action-toggle,
  .action-static {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 999px;
    background: #fff;
    border: 1px solid #dbe2ea;
    font-size: 12px;
    line-height: 1.2;
  }
  .action-static.selected {
    background: #e0ecff;
    border-color: #b6ccff;
    color: #1d4ed8;
  }
  .required-flag {
    color: #64748b;
    font-size: 10px;
  }
  .warnings {
    background: #fff7ed;
    border: 1px solid #fed7aa;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 12px;
    color: #9a3412;
  }
  .warnings-heading {
    margin: 0 0 4px;
    font-size: 12px;
    font-weight: 700;
  }
  .warning {
    margin: 2px 0;
    line-height: 1.45;
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
    gap: 8px;
  }
  .raw-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .raw-heading {
    font-size: 13px;
    font-weight: 700;
    margin: 0;
    color: #0f172a;
  }
  .copy-btn {
    background: #fff;
    border: 1px solid #cbd5e1;
    border-radius: 999px;
    padding: 6px 10px;
    font-size: 12px;
    font-weight: 600;
    line-height: 1.2;
    cursor: pointer;
    color: #334155;
    transition: background-color 120ms ease, border-color 120ms ease, color 120ms ease;
  }
  .copy-btn:hover {
    background: #f8fafc;
    border-color: #94a3b8;
    color: #0f172a;
  }
  .raw-bytes {
    background: #0f172a;
    color: #e2e8f0;
    padding: 12px;
    border-radius: 12px;
    overflow: auto;
    max-height: 280px;
    font-size: 12px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
    user-select: text;
    -webkit-user-select: text;
  }
  .error {
    background: #fff7f7;
    color: #9f2424;
    padding: 8px 10px;
    border-radius: 10px;
    font-size: 12px;
    line-height: 1.45;
    margin: 0;
    border: 1px solid #f2c0c0;
  }
  .actions {
    display: flex;
    gap: 10px;
  }
  .cancel,
  .approve {
    flex: 1;
    padding: 10px 12px;
    border-radius: 12px;
    font-size: 14px;
    font-weight: 700;
    line-height: 1.2;
    cursor: pointer;
    border: 1px solid transparent;
  }
  .cancel {
    background: #fff;
    color: #0f172a;
    border-color: #cbd5e1;
  }
  .approve {
    background: #0f172a;
    color: #fff;
    border-color: #0f172a;
  }
  .cancel:hover {
    background: #f8fafc;
  }
  .approve:hover {
    background: #111827;
  }
  .cancel:disabled,
  .approve:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  @media (max-width: 520px) {
    .signing-approval {
      padding: 14px;
      border-radius: 14px;
    }

    .summary-requester,
    .row {
      flex-direction: column;
      align-items: flex-start;
    }

    .label {
      min-width: 0;
    }

    .permissions-header,
    .raw-header {
      align-items: flex-start;
    }

    .actions {
      flex-direction: column-reverse;
    }

    .cancel,
    .approve {
      width: 100%;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    .signing-approval * {
      transition: none !important;
      animation: none !important;
    }
  }
</style>
