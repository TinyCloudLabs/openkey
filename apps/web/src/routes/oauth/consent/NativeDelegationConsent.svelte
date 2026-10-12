<script lang="ts">
  import { API_BASE, authClient } from '$lib/auth-client';
  import { safeOAuthNavigationUrl } from '$lib/safe-oauth-url';
  import NativeShell from '$lib/components/auth/native-shell.svelte';
  import { nativeAccessSummary } from '$lib/native-access';
  import { NATIVE_SWITCH_ACCOUNT_PARAM } from '$lib/native-mode';
  import {
    parseCapabilityReview, defaultSelection, buildRenderPlan, grantHeading,
    type CapabilityAction, type CapabilityGrant, type CapabilityReviewModel,
  } from '@openkey/capability-review';
  import { reviewSelectionToActionKeys, preparedMatchesSelection, type ServerPermissionOption } from '$lib/delegate-review-selection';

  let { requestId, clientId, email, ready }: {
    requestId: string; clientId: string; email?: string;
    /** The session has resolved; the request is only prepared once it has. */
    ready: boolean;
  } = $props();
  type Preview = {
    requestId: string; revision: number; digest: string; sessionSiwe: string;
    hostPlan: { host: string; spaceId: string; peerId: string; hostSiwe: string } | null;
    client: { name: string; icon?: string | null; organization?: string | null };
    address: string; keyId: string; redirectScheme: string; tinycloudHost: string;
    ttlSeconds: number; grantLifetimeSeconds: number; permissionOptions: ServerPermissionOption[]; selectedActionKeys: string[];
  };
  let preview = $state<Preview | null>(null);
  let model = $state<CapabilityReviewModel | null>(null);
  let baselineOptions = $state<ServerPermissionOption[]>([]);
  let selection = $state<Set<string>>(new Set());
  let loading = $state(true);
  let submitting = $state(false);
  let approved = $state(false);
  let error = $state('');
  let serial = 0;
  const blocked = $derived(model && preview && !preparedMatchesSelection(model, baselineOptions, selection, preview.selectedActionKeys)
    ? 'The selected permissions have not been prepared yet.' : null);

  function oauthQuery(): string | undefined {
    const params = new URLSearchParams(window.location.search);
    if (!params.has('sig')) return undefined;
    const signed = new URLSearchParams();
    for (const [key, value] of params) { signed.append(key, value); if (key === 'sig') break; }
    return signed.toString();
  }
  async function route(action: 'prepare' | 'approve' | 'deny', body: unknown) {
    const response = await fetch(`${API_BASE}/api/oauth/tinycloud/requests/${encodeURIComponent(requestId)}/${action}`, {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error_description ?? data.error ?? `${action} failed (${response.status})`);
    return data;
  }
  async function prepare(actionKeys?: string[]) {
    const turn = ++serial;
    loading = true;
    error = '';
    try {
      const data = await route('prepare', actionKeys ? { actionKeys } : {}) as Preview | { status: 'APPROVED' };
      if (turn !== serial) return;
      if ('status' in data) { approved = true; return; }
      if (!model) {
        const parsed = parseCapabilityReview({
          message: data.sessionSiwe,
          signer: { label: 'Canonical OpenKey key', address: data.address, chainId: 1, provenance: 'managed' },
          editable: true,
          metadataTrust: { status: 'unsigned', reason: 'Private-use redirect schemes do not verify the app' },
          reason: { text: '', source: 'none' },
          requester: { displayName: data.client.name, verifiedOrigin: null, appId: null, manifestName: null,
            manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none', manifestDigest: null,
            domainWarning: false, originWarning: false },
        });
        model = parsed;
        baselineOptions = data.permissionOptions;
        selection = defaultSelection(parsed);
      } else {
        model = { ...model, rawMessage: data.sessionSiwe };
      }
      preview = data;
    } catch (cause) { if (turn === serial) error = cause instanceof Error ? cause.message : 'Preparation failed'; }
    finally { if (turn === serial) loading = false; }
  }
  async function providerConsent(accept: boolean) {
    const response = await fetch(`${API_BASE}/api/auth/oauth2/consent`, {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accept, oauth_query: oauthQuery() }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error ?? data.message ?? 'Consent failed');
    const target = safeOAuthNavigationUrl(data.uri ?? data.url ?? (typeof data.redirect === 'string' ? data.redirect : undefined));
    if (!target) throw new Error('The application returned an unsafe redirect URI');
    window.location.href = target;
  }
  async function approve() {
    if ((!approved && (!preview || blocked)) || submitting) return;
    submitting = true; error = '';
    try {
      if (!approved) {
        const current = preview;
        if (!current) throw new Error('Preparation missing');
        await route('approve', { revision: current.revision, digest: current.digest,
          sessionSiwe: current.sessionSiwe, ...(current.hostPlan ? { hostSiwe: current.hostPlan.hostSiwe } : {}) });
        approved = true;
      }
      await providerConsent(true);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Approval failed';
      if (error === 'preparation_superseded') await prepare(reviewSelectionToActionKeys(model!, baselineOptions, selection));
      submitting = false;
    }
  }
  async function deny() {
    submitting = true; error = '';
    try { await route('deny', {}); }
    catch (cause) { console.warn('Native request denial could not be recorded', cause instanceof Error ? cause.message : 'unknown error'); }
    try { await providerConsent(false); }
    catch (cause) { error = cause instanceof Error ? cause.message : 'Denial failed'; submitting = false; }
  }
  async function notYou() {
    const signed = oauthQuery();
    submitting = true; error = '';
    try {
      const result = await authClient.signOut();
      if (result.error) throw new Error(result.error.message ?? 'Sign out failed');
      window.location.assign(`/auth/login?${signed ?? ''}&${NATIVE_SWITCH_ACCOUNT_PARAM}=1`);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Sign out failed';
      submitting = false;
    }
  }
  function toggle(action: CapabilityAction) {
    const next = new Set(selection);
    if (next.has(action.id)) next.delete(action.id); else next.add(action.id);
    changeSelection(next);
  }
  function changeSelection(next: Set<string>) {
    selection = next;
    if (model) prepare(reviewSelectionToActionKeys(model, baselineOptions, next));
  }
  const duration = (seconds: number) => {
    const [count, unit] = seconds % 86400 === 0 ? [seconds / 86400, 'day']
      : seconds % 3600 === 0 ? [seconds / 3600, 'hour'] : [Math.round(seconds / 60), 'minute'];
    return `${count} ${unit}${count === 1 ? '' : 's'}`;
  };
  let started = false;
  $effect(() => { if (ready && !started) { started = true; prepare(); } });
  const summary = $derived(model && preview ? nativeAccessSummary(model, selection, preview.client.name) : null);
  const grants = $derived(model ? buildRenderPlan(model.permissions).flatMap((bucket) => bucket.grants) : []);
  const malformed = $derived(model?.protocol === 'malformed-recap');
  const exactTarget = (grant: CapabilityGrant) =>
    `${grant.space}${grant.resourceService ? `/${grant.resourceService}` : ''}${grant.path ? `/${grant.path}` : ''}`;
</script>

<NativeShell {clientId} heading={(name) => `${name} wants access`} name={preview?.client.name ?? null}>
  {#if !ready || (loading && !preview)}
    <p class="nb-lede" role="status">Preparing your request…</p>
  {:else if approved}
    <p class="nb-lede">Your delegation was approved. Continue to return to the app.</p>
    {#if error}<p role="alert" class="nb-error">{error}</p>{/if}
    <button type="button" class="nb-button nb-primary" disabled={submitting} onclick={approve}>Continue to app</button>
  {:else if preview && model && summary}
    <p class="nb-lede signed-in">
      Signed in as <strong>{email}</strong> · <button type="button" class="nb-link nb-inline" disabled={submitting} onclick={notYou}>Not you?</button>
    </p>

    <section class="panel" aria-label="Requested access">
      <p class="sentence">{summary.sentence}</p>
      {#each summary.warnings as warning}
        <p class="note warning" role="status">{warning}</p>
      {/each}
      <p class="note">Access lasts up to {duration(preview.grantLifetimeSeconds)} and renews automatically while you use {preview.client.name}.</p>
      {#if preview.hostPlan}
        <p class="note">First sign-in: this also lets your TinyCloud node host your data.</p>
      {/if}
    </section>

    <details class="details">
      <summary class="nb-details-summary">Details</summary>
      <div class="details-body">
        <dl>
          {#if preview.client.organization}
            <dt>App by</dt><dd>{preview.client.organization}</dd>
          {/if}
          <dt>TinyCloud node</dt><dd><code>{preview.tinycloudHost}</code></dd>
          <dt>Returns to</dt><dd><code>{preview.redirectScheme}://</code></dd>
          <dt>Signing key</dt><dd><code>{preview.address}</code></dd>
          <dt>Renewals</dt><dd>Each renewal lasts {duration(preview.ttlSeconds)} from approval.</dd>
        </dl>
        {#if preview.hostPlan}
          <p class="note">If your applications space does not exist on {preview.hostPlan.host} yet, OpenKey will create it there. This is a permanent hosting authorization for that node.</p>
        {/if}

        <h2>Exact grants</h2>
        <ul class="grants">
          {#each grants as grant (grant.id)}
            <li>
              <div class="grant-title">
                {grantHeading(grant)}
                {#if grant.severity === 'sensitive'}<span class="pill">Sensitive</span>{/if}
              </div>
              <code class="grant-target">{exactTarget(grant)}</code>
              {#if grant.ownedBySelf === false}<p class="note">This data belongs to another user.</p>{/if}
              <ul class="actions">
                {#each grant.actions as action (action.id)}
                  <li>
                    {#if action.editable}
                      <label class="action-toggle">
                        <input type="checkbox" checked={selection.has(action.id)} disabled={loading || submitting} onchange={() => toggle(action)} />
                        <span>{action.verb}</span>
                      </label>
                    {:else}
                      <span class="action-static">{action.verb}{#if action.required} <span class="pill">required</span>{/if}</span>
                    {/if}
                  </li>
                {/each}
              </ul>
            </li>
          {/each}
        </ul>

        <details class="raw">
          <summary>Exact message being signed</summary>
          <pre>{model.rawMessage}</pre>
        </details>
      </div>
    </details>

    {#if error}<p class="nb-error" role="alert">{error}</p>{/if}
    {#if malformed}
      <p class="nb-error" role="alert">This request carries a capability payload that could not be decoded, so it cannot be approved.</p>
    {:else if blocked}
      <p class="nb-note" role="status">{blocked}</p>
    {/if}

    <div class="nb-stack actions-row">
      <button type="button" class="nb-button nb-primary" onclick={approve} disabled={submitting || loading || malformed || Boolean(blocked)}>
        {submitting ? 'Working…' : 'Allow'}
      </button>
      <button type="button" class="nb-button" onclick={deny} disabled={submitting}>Deny</button>
    </div>
  {:else}
    <p role="alert" class="nb-error">{error || 'Unable to prepare this request.'}</p>
  {/if}
</NativeShell>

<style>
  .signed-in {
    margin-bottom: 16px;
  }

  .signed-in .nb-inline {
    min-height: 0;
    padding: 0;
    font-size: inherit;
    color: var(--nb-fg);
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

  .warning {
    color: var(--nb-fg);
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

  h2 {
    margin: 18px 0 8px;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: var(--nb-faint);
  }

  .grants,
  .actions {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .grants > li {
    padding: 12px 0;
    border-top: 1px solid var(--nb-border);
  }

  .grant-title {
    font-weight: 600;
    color: var(--nb-fg);
  }

  .grant-target {
    display: block;
    margin: 4px 0 6px;
    overflow-wrap: anywhere;
    color: var(--nb-muted);
  }

  .pill {
    margin-left: 6px;
    padding: 1px 8px;
    border-radius: 999px;
    border: 1px solid var(--nb-border);
    font-size: 12px;
    font-weight: 500;
    color: var(--nb-muted);
  }

  .action-toggle,
  .action-static {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 44px;
    color: var(--nb-fg);
  }

  .action-toggle input {
    width: 22px;
    height: 22px;
    accent-color: var(--nb-accent);
  }

  .raw {
    margin-top: 12px;
  }

  pre {
    margin: 0;
    padding: 12px;
    max-height: 240px;
    overflow: auto;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    border-radius: 12px;
    background: var(--nb-field);
    color: var(--nb-muted);
  }

  .actions-row {
    margin-top: 4px;
  }
</style>
