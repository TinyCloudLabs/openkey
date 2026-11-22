<script lang="ts">
  import { API_BASE } from '$lib/auth-client';
  import { safeOAuthNavigationUrl } from '$lib/safe-oauth-url';
  import { daysOverTwoDays, formatDuration, formatEndDay } from '$lib/approval-expiry';
  import { formatLocalAccessEnd } from '$lib/access-end';
  import { isTermsRequired } from '$lib/terms';
  import { termsRefused } from '$lib/terms-gate';
  import NativeShell from '$lib/components/auth/native-shell.svelte';
  import { nativeAccessSummary } from '$lib/native-access';
  import {
    parseCapabilityReview, defaultSelection, buildRenderPlan, grantHeading, renderSiweLiteral,
    type CapabilityAction, type CapabilityGrant, type CapabilityReviewModel,
  } from '@openkey/capability-review';
  import { reviewSelectionToActionKeys, preparedMatchesSelection, type ServerPermissionOption } from '$lib/delegate-review-selection';
  import { answerApprovalPasskey, isPasskeyApprovalRefusal, type ApprovalPasskeyNeed } from '$lib/approval-passkey';
  import NativeStepUpConsent from './NativeStepUpConsent.svelte';
  import { isStepUpPreview, stepUpAppName, type StepUpSpace } from '$lib/native-stepup';

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
    /** TC-3442: whether Approve needs the passkey, with the challenge for this revision. */
    passkey?: ApprovalPasskeyNeed;
    /** The request kind: SIGNIN, or STEPUP (with `stepUp`, `spaces` and `reactivation`). */
    kind?: string;
    stepUp?: { grantId: string; appId: string };
    spaces?: StepUpSpace[];
    reactivation?: boolean;
  };
  let preview = $state<Preview | null>(null);
  let model = $state<CapabilityReviewModel | null>(null);
  let baselineOptions = $state<ServerPermissionOption[]>([]);
  let selection = $state<Set<string>>(new Set());
  let loading = $state(true);
  let submitting = $state(false);
  let approved = $state(false);
  let error = $state('');
  /** The API refused to prepare or approve a step-up because a space it needs is not hosted (`space_not_hosted`). */
  let unhosted = $state(false);
  /** The API sent a kind this page cannot show (none, an unknown one, or a STEPUP that names no app or spaces). */
  let refused = $state(false);
  let serial = 0;
  const stepUpPreview = $derived(preview && isStepUpPreview(preview) ? preview : null);
  // A step-up has no optional actions: every capability is requested and none can be switched off.
  const blocked = $derived(model && preview && !stepUpPreview && !preparedMatchesSelection(model, baselineOptions, selection, preview.selectedActionKeys)
    ? 'The selected permissions have not been prepared yet.' : null);
  const failedWith = (cause: unknown, code: string) => (cause as { errorCode?: unknown } | null)?.errorCode === code;
  const preparedKeys = () => (stepUpPreview ? undefined : reviewSelectionToActionKeys(model!, baselineOptions, selection));

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
    if (isTermsRequired(response.status, data)) termsRefused();
    if (!response.ok) {
      const failure = new Error(data.error_description ?? data.error ?? `${action} failed (${response.status})`);
      throw Object.assign(failure, { code: typeof data.code === 'string' ? data.code : undefined, errorCode: typeof data.error === 'string' ? data.error : undefined });
    }
    return data;
  }
  async function prepare(actionKeys?: string[]) {
    const turn = ++serial;
    loading = true;
    error = '';
    unhosted = false;
    refused = false;
    try {
      const data = await route('prepare', actionKeys ? { actionKeys } : {}) as Preview | { status: 'APPROVED' };
      if (turn !== serial) return;
      if ('status' in data) { approved = true; return; }
      // An explicit kind decides the screen, with no default: SIGNIN renders the sign-in screen, STEPUP the step-up
      // screen, and anything else is an error with no Allow: no kind (a preview that carries `stepUp` or `spaces`
      // without one is not a sign-in), an unknown kind, or a STEPUP that does not name its app and spaces. The API
      // sends a kind on every preview, so the web must not be deployed before it.
      if (data.kind === 'STEPUP' ? !isStepUpPreview(data) : data.kind !== 'SIGNIN') {
        // Nothing of an earlier prepare stays on screen: no model and no preview to Allow from, only the way back.
        preview = null;
        model = null;
        refused = true;
        return;
      }
      // A step-up is always read afresh from the text it will sign: its list is what that text says, never an older
      // prepare's. (A sign-in keeps its first parse, which holds the user's selection across re-prepares.)
      if (!model || data.kind === 'STEPUP') {
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
    } catch (cause) {
      if (turn !== serial) return;
      error = cause instanceof Error ? cause.message : 'Preparation failed';
      // This step-up asks for a space the account does not host yet; the screen says so instead of a generic failure.
      if (failedWith(cause, 'space_not_hosted')) unhosted = true;
    }
    finally { if (turn === serial) loading = false; }
  }
  async function providerConsent(accept: boolean) {
    const response = await fetch(`${API_BASE}/api/auth/oauth2/consent`, {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accept, oauth_query: oauthQuery() }),
    });
    const data = await response.json().catch(() => ({}));
    if (isTermsRequired(response.status, data)) termsRefused();
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
        // TC-3442: the passkey prompt comes first, while the tap still counts as the user's gesture.
        const passkeyAssertion = await answerApprovalPasskey(current.passkey);
        await route('approve', { revision: current.revision, digest: current.digest,
          sessionSiwe: current.sessionSiwe, ...(current.hostPlan ? { hostSiwe: current.hostPlan.hostSiwe } : {}),
          ...(passkeyAssertion ? { passkeyAssertion } : {}) });
        approved = true;
      }
      await providerConsent(true);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Approval failed';
      // The API withdrew this approval because a space the app needs is not hosted: there is nothing left to Allow.
      if (failedWith(cause, 'space_not_hosted')) unhosted = true;
      else if (error === 'preparation_superseded') await prepare(preparedKeys());
      // The refused challenge is spent: prepare again for a new one, and keep the API's words on screen.
      else if (isPasskeyApprovalRefusal(cause)) {
        const refusal = error;
        await prepare(preparedKeys());
        error = refusal;
      }
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
  function toggle(action: CapabilityAction) {
    const next = new Set(selection);
    if (next.has(action.id)) next.delete(action.id); else next.add(action.id);
    changeSelection(next);
  }
  function changeSelection(next: Set<string>) {
    selection = next;
    if (model) prepare(reviewSelectionToActionKeys(model, baselineOptions, next));
  }
  const duration = (seconds: number) => formatDuration(seconds * 1000);
  // Over two days the day the longest grant ends too: "30 days, until 17 Dec,".
  const lifetime = (seconds: number) =>
    daysOverTwoDays(seconds * 1000) === null ? duration(seconds) : `${duration(seconds)}, until ${formatEndDay(seconds * 1000)},`;
  let started = false;
  $effect(() => { if (ready && !started) { started = true; prepare(); } });
  const summary = $derived(model && preview ? nativeAccessSummary(model, selection, preview.client.name) : null);
  const grants = $derived(model ? buildRenderPlan(model.permissions).flatMap((bucket) => bucket.grants) : []);
  const malformed = $derived(model?.protocol === 'malformed-recap');
  const trustLabel: Record<CapabilityReviewModel['metadataTrust']['status'], string> = {
    verified: 'Manifest signature verified',
    'origin-bound': 'Manifest served by verified https origin',
    unsigned: 'No signed manifest',
    stale: 'Manifest signature is stale',
    'wrong-key': 'Manifest signed by an unknown key',
    'digest-mismatch': 'Manifest digest does not match declared content',
  };
  const exactTarget = (grant: CapabilityGrant) =>
    `${grant.space}${grant.resourceService ? `/${grant.resourceService}` : ''}${grant.path ? `/${grant.path}` : ''}`;
</script>

<NativeShell {clientId} name={preview ? preview.client.name : unhosted || refused ? undefined : null}
  heading={(name) => unhosted || refused ? 'This app can’t be allowed yet' : stepUpPreview ? `Give ${stepUpAppName(stepUpPreview.stepUp.appId)} more access` : `${name} wants access`}>
  {#if !ready || (loading && !preview && !unhosted && !refused)}
    <p class="nb-lede" role="status">Preparing your request…</p>
  {:else if refused}
    <section class="panel" aria-label="Request not supported">
      <p class="sentence" role="alert">This request needs a newer version of the app.</p>
      <p class="note">Nothing was allowed. Update the app, then try again.</p>
    </section>
    {#if error}<p class="nb-error" role="alert">{error}</p>{/if}
    <div class="nb-stack actions-row">
      <button type="button" class="nb-button" onclick={deny} disabled={submitting}>Back to the app</button>
    </div>
  {:else if unhosted}
    <section class="panel" aria-label="Space not set up">
      <p class="sentence" role="alert">One of the spaces this app needs is not set up on your TinyCloud account yet, so it can’t be allowed yet.</p>
      <p class="note">Nothing was allowed. Go back to the app; it can ask again once the space is set up.</p>
    </section>
    <div class="nb-stack actions-row">
      <button type="button" class="nb-button" onclick={deny} disabled={submitting}>Back to the app</button>
    </div>
  {:else if approved}
    <p class="nb-lede">Your delegation was approved. Continue to return to the app.</p>
    {#if error}<p role="alert" class="nb-error">{error}</p>{/if}
    <button type="button" class="nb-button nb-primary" disabled={submitting} onclick={approve}>Continue to app</button>
  {:else if stepUpPreview && model}
    <NativeStepUpConsent preview={stepUpPreview} {model} {email} {error} {malformed} {loading} {submitting} onapprove={approve} ondeny={deny} />
  {:else if preview && model && summary}
    <p class="nb-lede signed-in">Signed in as <strong>{email}</strong></p>

    <section class="panel" aria-label="Requested access">
      <p class="sentence">{summary.sentence}</p>
      {#each summary.warnings as warning}
        <p class="note warning" role="status">{warning}</p>
      {/each}
      <p class="note">Access lasts up to {lifetime(preview.grantLifetimeSeconds)} and renews automatically while you use {preview.client.name}.</p>
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
          <dt>Signing key</dt><dd>{model.signer.label} <code>{model.signer.address}</code></dd>
          <dt>App identity</dt><dd>{trustLabel[model.metadataTrust.status]}</dd>
          {#if model.expiry}<dt>Expires</dt><dd>{formatLocalAccessEnd(model.expiry)}</dd>{/if}
          <dt>Renewals</dt><dd>Each renewal lasts {duration(preview.ttlSeconds)} from approval.</dd>
        </dl>
        {#if model.metadataTrust.reason}
          <p class="note">{model.metadataTrust.reason}</p>
        {/if}
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

        {#if model.parseWarnings.length > 0}
          <h2>Notes</h2>
          <ul class="warnings">
            {#each model.parseWarnings as warning}
              <li><code>{warning.code}</code> {warning.message}</li>
            {/each}
          </ul>
        {/if}

        <details class="raw">
          <summary>Exact message being signed</summary>
          <pre>{renderSiweLiteral(model.rawMessage)}</pre>
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
      <button type="button" class="nb-button" onclick={deny} disabled={submitting}>Don't allow</button>
    </div>
  {:else}
    <p role="alert" class="nb-error">{error || 'Unable to prepare this request.'}</p>
  {/if}
</NativeShell>

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
    min-height: 48px;
    color: var(--nb-fg);
  }

  .warnings {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .warnings li {
    padding: 6px 0;
    overflow-wrap: anywhere;
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
    white-space: pre;
    border-radius: 12px;
    background: var(--nb-field);
    color: var(--nb-muted);
  }

  .actions-row {
    margin-top: 4px;
  }
</style>
