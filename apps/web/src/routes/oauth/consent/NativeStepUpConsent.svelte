<script lang="ts">
  // The step-up screen of a native consent: a framed app asks for more than the Home sign-in grant holds. It is
  // rendered inside NativeDelegationConsent's shell and runs on its prepare/approve/deny plumbing, so the approve
  // protocol (revision, digest, passkey) is the sign-in one. Consent is all-or-nothing: the API requires every
  // requested capability, so nothing here can be switched off.
  import { renderSiweLiteral, type CapabilityReviewModel } from '@openkey/capability-review';
  import { stepUpAccess, stepUpAppName, type StepUpPreview } from '$lib/native-stepup';
  import { formatLocalAccessEnd } from '$lib/access-end';

  let { preview, model, email, error, malformed, loading, submitting, onapprove, ondeny }: {
    preview: StepUpPreview;
    model: CapabilityReviewModel;
    email?: string;
    error: string;
    malformed: boolean;
    loading: boolean;
    submitting: boolean;
    onapprove: () => void;
    ondeny: () => void;
  } = $props();

  const appName = $derived(stepUpAppName(preview.stepUp.appId));
  const access = $derived(stepUpAccess(model.permissions));
</script>

{#if email}<p class="nb-lede signed-in">Signed in as <strong>{email}</strong></p>{/if}

<section class="panel" aria-label="Requested access">
  <p class="sentence">
    {appName} will be able to {access.readOnly ? 'read' : 'use'} more of your data, on top of what {preview.client.name} already has.
  </p>
  {#if preview.reactivation}
    <p class="note">You removed {appName} before. Allowing it now turns it back on.</p>
  {/if}

  <ul class="spaces">
    {#each access.spaces as group (group.spaceId)}
      <li>
        <div class="space-title">The <code>{group.space}</code> space</div>
        <ul class="items">
          {#each group.items as item (item.resource)}
            <li>
              <code class="resource">{item.resource}</code>
              <span class="verbs">{item.readOnly ? 'Read only' : 'Can change data'}: {item.actions.join(', ')}</span>
            </li>
          {/each}
        </ul>
      </li>
    {/each}
  </ul>

  <p class="note">{appName} stays allowed and renews with {preview.client.name} until you remove it.</p>
</section>

<details class="details">
  <summary class="nb-details-summary">Details</summary>
  <div class="details-body">
    <dl>
      <dt>App</dt><dd>{appName}{#if appName !== preview.stepUp.appId} <code>{preview.stepUp.appId}</code>{/if}</dd>
      {#if preview.client.organization}
        <dt>App by</dt><dd>{preview.client.organization}</dd>
      {/if}
      <dt>TinyCloud node</dt><dd><code>{preview.tinycloudHost}</code></dd>
      <dt>Returns to</dt><dd><code>{preview.redirectScheme}://</code></dd>
      <dt>Signing key</dt><dd>{model.signer.label} <code>{model.signer.address}</code></dd>
      {#if model.expiry}<dt>Expires</dt><dd>{formatLocalAccessEnd(model.expiry)}</dd>{/if}
    </dl>
    <details class="raw">
      <summary>Exact message being signed</summary>
      <pre>{renderSiweLiteral(model.rawMessage)}</pre>
    </details>
  </div>
</details>

{#if error}<p class="nb-error" role="alert">{error}</p>{/if}
{#if malformed}
  <p class="nb-error" role="alert">This request can’t be read, so it can’t be allowed.</p>
{/if}

<div class="nb-stack actions-row">
  <button type="button" class="nb-button nb-primary" onclick={onapprove} disabled={submitting || loading || malformed}>
    {submitting ? 'Working…' : 'Allow'}
  </button>
  <button type="button" class="nb-button" onclick={ondeny} disabled={submitting}>Don't allow</button>
</div>

<style>
  .signed-in {
    margin-bottom: 16px;
  }

  .panel {
    padding: 18px;
    margin-bottom: 8px;
    border-radius: 16px;
    border: 1px solid var(--nb-border);
    background: var(--nb-field);
  }

  .sentence {
    margin: 0 0 10px;
    font-size: 18px;
    line-height: 1.4;
    font-weight: 500;
  }

  .note {
    margin: 10px 0 0;
    font-size: 14px;
    line-height: 1.45;
    color: var(--nb-muted);
  }

  .spaces,
  .items {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .spaces {
    margin-top: 12px;
  }

  .spaces > li {
    padding: 12px 0;
    border-top: 1px solid var(--nb-border);
  }

  .space-title {
    font-weight: 600;
    color: var(--nb-fg);
  }

  .items > li {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-top: 6px;
  }

  .resource {
    overflow-wrap: anywhere;
    color: var(--nb-fg);
  }

  .verbs {
    font-size: 14px;
    color: var(--nb-muted);
  }

  .details {
    margin-bottom: 20px;
  }

  .nb-details-summary,
  .raw summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    min-height: 48px;
    padding: 0 4px;
    font-size: 15px;
    color: var(--nb-muted);
    cursor: pointer;
  }

  .nb-details-summary::after,
  .raw summary::after {
    content: '+';
    font-size: 20px;
  }

  details[open] > .nb-details-summary::after,
  .raw[open] > summary::after {
    content: '−';
  }

  .details-body {
    padding: 4px 4px 12px;
    font-size: 14px;
    line-height: 1.45;
    color: var(--nb-muted);
  }

  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 14px;
    margin: 0;
  }

  dt {
    color: var(--nb-faint);
  }

  dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
    color: var(--nb-fg);
  }

  code,
  pre {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12.5px;
  }

  .raw {
    margin-top: 12px;
  }

  pre {
    margin: 0;
    padding: 12px;
    max-height: 240px;
    overflow: auto;
    white-space: pre;
    border-radius: 12px;
    background: var(--nb-field);
    color: var(--nb-muted);
  }

  .actions-row {
    margin-top: 4px;
  }
</style>
