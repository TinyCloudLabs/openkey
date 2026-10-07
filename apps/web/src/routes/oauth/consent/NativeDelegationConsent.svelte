<script lang="ts">
  import { onMount } from 'svelte';
  import { API_BASE } from '$lib/auth-client';
  import { safeExternalHttpUrl, safeOAuthNavigationUrl } from '$lib/safe-oauth-url';
  import SigningApproval from '$lib/components/signing/signing-approval.svelte';
  import { parseCapabilityReview, defaultSelection, type CapabilityReviewModel } from '@openkey/capability-review';
  import { reviewSelectionToActionKeys, preparedMatchesSelection, type ServerPermissionOption } from '$lib/delegate-review-selection';

  let { requestId, email }: { requestId: string; email?: string } = $props();
  type Preview = {
    requestId: string; revision: number; digest: string; sessionSiwe: string;
    hostPlan: { host: string; spaceId: string; peerId: string; hostSiwe: string } | null;
    client: { name: string; icon?: string | null; organization?: string | null; verified: false };
    address: string; keyId: string; redirectScheme: string; tinycloudHost: string;
    ttlSeconds: number; grantLifetimeSeconds: number; permissionOptions: ServerPermissionOption[]; selectedActionKeys: string[];
  };
  let preview = $state<Preview | null>(null);
  let model = $state<CapabilityReviewModel | null>(null);
  let baselineOptions = $state<ServerPermissionOption[]>([]);
  let selection = $state<Set<string>>(new Set());
  let editing = $state(false);
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
  function changeSelection(next: Set<string>) {
    selection = next;
    if (model) prepare(reviewSelectionToActionKeys(model, baselineOptions, next));
  }
  const duration = (seconds: number) => {
    const [count, unit] = seconds % 86400 === 0 ? [seconds / 86400, 'day']
      : seconds % 3600 === 0 ? [seconds / 3600, 'hour'] : [Math.round(seconds / 60), 'minute'];
    return `${count} ${unit}${count === 1 ? '' : 's'}`;
  };
  onMount(() => { prepare(); });
</script>

{#if loading && !preview}
  <p class="text-surface-600">Preparing delegation…</p>
{:else if approved}
  <div class="space-y-4 text-center">
    <p>Your delegation was approved. Continue to return to the app.</p>
    {#if error}<p role="alert" class="text-red-600">{error}</p>{/if}
    <button type="button" class="rounded-lg bg-primary-600 px-4 py-2 text-white disabled:opacity-50" disabled={submitting} onclick={approve}>Continue to app</button>
  </div>
{:else if preview && model}
  {#snippet context()}
    {#if preview}
    <div class="space-y-3 text-sm text-surface-700">
      <div class="flex items-center gap-3">
        {#if safeExternalHttpUrl(preview.client.icon)}<img src={safeExternalHttpUrl(preview.client.icon)!} alt="" class="h-10 w-10 rounded-lg" />{/if}
        <div><strong>{preview.client.name}</strong><div>Unverified app{preview.client.organization ? ` · ${preview.client.organization}` : ''}</div></div>
      </div>
      <p>Return to <code>{preview.redirectScheme}://</code> after approval.</p>
      <p>Delegation lasts {duration(preview.ttlSeconds)} from approval. The app may auto-renew for up to {duration(preview.grantLifetimeSeconds)}.</p>
      <p>TinyCloud node: <code>{preview.tinycloudHost}</code></p>
      {#if preview.hostPlan}
        <p class="rounded-lg border border-amber-300 bg-amber-50 p-3">If your applications space does not exist on {preview.hostPlan.host} yet, OpenKey will create it there. This is a permanent hosting authorization for that node.</p>
      {/if}
    </div>
    {/if}
  {/snippet}
  <SigningApproval {model} {selection} {editing} approving={submitting || loading} {error} approveBlockedReason={blocked}
    approveText="Allow" cancelText="Deny" {context} onApprove={approve} onCancel={deny}
    onSelectionChange={changeSelection} onEditingChange={(next) => { editing = next; }} />
  <p class="mt-4 text-center text-xs text-surface-500">Signed in as {email}</p>
{:else}
  <p role="alert" class="text-red-600">{error || 'Unable to prepare this request.'}</p>
{/if}
