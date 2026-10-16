<script lang="ts">
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { copyText } from '$lib/clipboard';
  import { parseCapabilityReview, defaultSelection, type CapabilityReviewModel } from '@openkey/capability-review';
  import { validatePreviewSelection } from '$lib/preview-review';

  let { ticket }: { ticket: string } = $props();
  const session = authClient.useSession();
  const apiUrl = import.meta.env.VITE_API_URL || '';
  type Request = { protocolVersion: 1; siwe: string; jwk: Record<string, unknown>; host: string; sessionDid: string; keyId?: string; presentation?: Record<string, unknown> };
  type Handoff = { transportVersion: 2; request: Request; delivery: { callback?: string }; expiresAt: string };
  type Result = { protocolVersion: 1; address: string; signature: string; signedMessage: string; selectedActionKeys: string[]; permissions: unknown[] };
  type KeyChoice = { key: EthereumKey; review: CapabilityReviewModel };
  function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }
  function isHandoff(value: Record<string, unknown>): value is Handoff {
    if (!isRecord(value.request) || !isRecord(value.delivery)) return false;
    const request = value.request;
    return value.transportVersion === 2 && request.protocolVersion === 1 &&
      typeof request.siwe === 'string' && typeof request.host === 'string' &&
      typeof request.sessionDid === 'string' && isRecord(request.jwk) &&
      (request.keyId === undefined || typeof request.keyId === 'string') &&
      (request.presentation === undefined || isRecord(request.presentation)) &&
      (value.delivery.callback === undefined || typeof value.delivery.callback === 'string') &&
      typeof value.expiresAt === 'string';
  }
  let handoff = $state<Handoff | null>(null);
  let key = $state<EthereumKey | null>(null);
  let keyChoices = $state<KeyChoice[]>([]);
  let signingChain = $state('');
  let model = $state<CapabilityReviewModel | null>(null);
  let selected = $state(new Set<string>());
  let contextToken = $state('');
  let previewToken = $state('');
  let previewMessage = $state('');
  let previewActions = $state<string[]>([]);
  let code = $state('');
  let callbackFailed = $state(false);
  let delivered = $state(false);
  let error = $state('');
  let busy = $state(false);
  let loaded = $state(false);
  let submitted = $state(false);
  let signingIn = $state(false);
  let phase = $state<'review' | 'preview' | 'done'>('review');
  function validCallback(callback: string): boolean {
    if (!/^http:\/\/(?:127\.0\.0\.1|\[::1\]):[0-9]{4,5}\/callback\/[A-Za-z0-9_-]{22}$/.test(callback)) return false;
    const port = Number(new URL(callback).port);
    return port >= 1024 && port <= 65535;
  }

  async function post(path: string, body: unknown): Promise<Record<string, unknown>> {
    const response = await fetch(`${apiUrl}/api/delegate/${path}`, {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const data: unknown = await response.json().catch(() => ({}));
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error(`Invalid response from ${path}.`);
    const record = data as Record<string, unknown>;
    if (!response.ok) throw new Error(typeof record.error === 'string' ? record.error : `HTTP ${response.status}`);
    return record;
  }

  function selectedIds(): string[] {
    return model?.permissions.flatMap(grant => grant.actions.filter(action => selected.has(action.id)).map(action => action.id)) ?? [];
  }
  function chooseKey(choice: KeyChoice) {
    if (contextToken) return;
    key = choice.key;
    model = choice.review;
    selected = defaultSelection(choice.review);
  }

  async function load() {
    busy = true;
    try {
      if (!ticket) throw new Error('Missing prepared sign-in ticket. Restart the CLI command.');
      const resolved = await post('handoffs/resolve', { ticket });
      if (!isHandoff(resolved)) {
        throw new Error('Unknown prepared sign-in transport version. Restart the CLI command.');
      }
      if (resolved.delivery.callback && !validCallback(resolved.delivery.callback)) {
        throw new Error('The registered CLI callback is not a valid loopback address.');
      }
      const match = /(?:^|\n)([^\n]+) wants you to sign in with your Ethereum account:\n(0x[0-9a-fA-F]{40})(?:\n|$)/.exec(resolved.request.siwe);
      const chain = /^Chain ID: ([1-9][0-9]*)$/m.exec(resolved.request.siwe);
      if (!match || !chain) throw new Error('The prepared SIWE does not name a valid signer and chain.');
      signingChain = chain[1]!;
      const { keys } = await api.listKeys();
      const candidates = keys.filter(item => item.address.toLowerCase() === match[2]!.toLowerCase() && (!resolved.request.keyId || item.id === resolved.request.keyId));
      if (!candidates.length) throw new Error('Requested signing key is not available for this SIWE account and chain.');
      const choices = candidates.map(candidate => {
        const review = parseCapabilityReview({
          message: resolved.request.siwe,
          signer: { label: candidate.label ?? `Key ${candidate.keyIndex}`, address: candidate.address, chainId: Number(chain[1]), provenance: candidate.keyType === 'EXTERNAL' ? 'external' : 'managed' },
          editable: true,
          metadataTrust: { status: 'unsigned', reason: 'No verified manifest supplied' },
          reason: { text: '', source: 'none' },
          requester: { displayName: match[1]!, verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none', manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false },
        });
        if (review.protocol !== 'tinycloud-siwe-recap') throw new Error('The prepared SIWE contains no valid capability request.');
        return { key: candidate, review };
      });
      keyChoices = choices;
      handoff = resolved;
      if (choices.length === 1) chooseKey(choices[0]!);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not resolve prepared sign-in.';
    } finally { busy = false; }
  }

  $effect(() => {
    if ($session.data && !loaded) { loaded = true; void load(); }
  });

  function toggle(id: string) {
    if (phase !== 'review') return;
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    selected = next;
  }

  async function preview() {
    if (!handoff || !key || !model || busy || submitted) return;
    busy = true;
    error = '';
    try {
      const request = handoff.request;
      if (!contextToken) {
        const prepared = await post('authorize-sign-prepare', {
          ticket, keyId: key.id, siwe: request.siwe, jwk: request.jwk, host: request.host,
          ...(request.presentation ? { presentation: request.presentation } : {}),
        });
        if (typeof prepared.authorizationContextToken !== 'string') throw new Error('Missing bound authorization context.');
        contextToken = prepared.authorizationContextToken;
      }
      const actions = selectedIds();
      if (!actions.length) throw new Error('Select at least one ability.');
      const candidate = await post('authorize-sign-preview', { ticket, authorizationContextToken: contextToken, selectedActionIds: actions });
      if (typeof candidate.previewApprovalToken !== 'string' || typeof candidate.signedMessage !== 'string') throw new Error('Missing sealed signing preview.');
      validatePreviewSelection(candidate, actions);
      previewToken = candidate.previewApprovalToken;
      previewMessage = candidate.signedMessage;
      previewActions = actions;
      phase = 'preview';
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Could not preview sign-in.'; }
    finally { busy = false; }
  }

  function encode(value: unknown): string {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function approve() {
    if (!handoff || !key || !previewToken || !contextToken || busy || submitted) return;
    busy = true;
    error = '';
    try {
      const body: Record<string, unknown> = { ticket, authorizationContextToken: contextToken, previewApprovalToken: previewToken, selectedActionIds: previewActions, protocolVersion: 1 };
      if (key.keyType === 'EXTERNAL') {
        const provider = (window as Window & { ethereum?: { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> } }).ethereum;
        if (!provider) throw new Error('No browser wallet is available for this external key.');
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        if (!Array.isArray(accounts) || !accounts.every(value => typeof value === 'string')) throw new Error('Wallet returned invalid accounts.');
        const account = accounts.find(value => value.toLowerCase() === key!.address.toLowerCase());
        if (!account) throw new Error('The browser wallet does not contain the requested account.');
        const signature = await provider.request({ method: 'personal_sign', params: [previewMessage, account] });
        if (typeof signature !== 'string') throw new Error('Wallet returned an invalid signature.');
        body.externalSignature = signature;
      }
      submitted = true;
      const signed = await post('authorize-sign', body);
      if (signed.protocolVersion !== 1 || typeof signed.signature !== 'string' || typeof signed.address !== 'string' ||
          !Array.isArray(signed.selectedActionKeys) || !signed.selectedActionKeys.every(value => typeof value === 'string') ||
          !Array.isArray(signed.permissions) ||
          signed.signedMessage !== previewMessage || signed.selectedKeyId !== key.id || typeof signed.deliveryState !== 'string') {
        throw new Error('Signed response differs from the reviewed request. Restart the CLI command.');
      }
      const result: Result = {
        protocolVersion: 1, address: signed.address, signature: signed.signature,
        signedMessage: previewMessage, selectedActionKeys: signed.selectedActionKeys, permissions: signed.permissions,
      };
      const envelope = { transportVersion: 2, state: signed.deliveryState, selectedKeyId: signed.selectedKeyId, result };
      code = encode(envelope);
      phase = 'done';
      if (handoff.delivery.callback) {
        try {
          const response = await fetch(handoff.delivery.callback, { method: 'POST', redirect: 'error', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope) });
          const receipt: unknown = await response.json().catch(() => null);
          if (!response.ok || !receipt || typeof receipt !== 'object' || !('accepted' in receipt) || receipt.accepted !== true) {
            throw new Error('CLI did not accept the response.');
          }
          delivered = true;
        } catch { callbackFailed = true; }
      }
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Signing failed. Restart the CLI command.';
    } finally { busy = false; }
  }

  async function cancel() {
    if (!handoff || busy || submitted) return;
    busy = true;
    error = '';
    try {
      const response = await post('handoffs/cancel-claimed', { ticket });
      if (response.cancelled !== true) throw new Error('The handoff was not cancelled.');
      handoff = null;
      contextToken = '';
      previewToken = '';
      previewMessage = '';
      phase = 'review';
      error = 'Approval cancelled. Restart the CLI command for a new sign-in.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not cancel sign-in.';
    } finally { busy = false; }
  }

  async function signIn() {
    signingIn = true;
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) error = authErrorMessage(result.error, 'Passkey sign-in failed');
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Passkey sign-in failed'; }
    finally { signingIn = false; }
  }
</script>

<div class="min-h-screen bg-[#fafafa] flex items-center justify-center px-4 py-8">
  <main class="w-full max-w-xl rounded-xl border border-surface-200 bg-white p-6 shadow-sm space-y-5">
    <header><h1 class="text-xl font-semibold text-surface-900">Prepared CLI sign-in</h1></header>
    {#if error}<p role="alert" class="rounded-lg bg-red-50 p-3 text-red-800">{error}</p>{/if}
    {#if !$session.data}
      <p>Sign in to review this request.</p>
      <a href={`/auth/login?redirect=${encodeURIComponent('/delegate?transportVersion=2&ticket=' + ticket)}`}>Continue with email</a>
      <button disabled={signingIn} onclick={signIn}>Use a passkey instead</button>
    {:else if busy && !handoff && !code}<p>Loading prepared sign-in…</p>
    {:else if handoff && phase === 'done'}
      {#if delivered}<p role="status">CLI accepted your sign-in. You can close this window.</p>
      {:else}
        <p>{callbackFailed ? 'Could not reach the CLI automatically. Paste this same response in your CLI.' : 'Paste this response in your CLI to complete sign-in.'}</p>
        <p>Only paste this code into a terminal you started yourself.</p>
        <textarea readonly aria-label="Full delegation code" class="w-full h-28 break-all rounded-lg border p-2 font-mono text-xs" value={code}></textarea>
        <button onclick={() => copyText(code)}>Copy full code</button>
      {/if}
    {:else if handoff && keyChoices.length > 1 && !key}
      <p class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">Only approve if you started this sign-in yourself on your own computer.</p>
      <dl class="space-y-2 text-sm break-all">
        <div><dt class="font-semibold">Session DID (display only)</dt><dd>{handoff.request.sessionDid}</dd></div>
        <div><dt class="font-semibold">Node host</dt><dd>{handoff.request.host}</dd></div>
        <div><dt class="font-semibold">Expires</dt><dd>{handoff.expiresAt}</dd></div>
      </dl>
      <h2 class="font-semibold">Choose an OpenKey signing key</h2>
      {#each keyChoices as choice (choice.key.id)}
        <button class="block w-full rounded-lg border p-3 text-left text-sm break-all" onclick={() => chooseKey(choice)}>{choice.key.label ?? `Key ${choice.key.keyIndex}`} · {choice.key.id} · {choice.key.address} (chain {signingChain})</button>
      {/each}
      <h2 class="font-semibold">Requested abilities and spaces</h2>
      {#each keyChoices[0].review.permissions as grant}
        <p class="break-all text-sm">{grant.service} · {grant.space} · {grant.path}: {grant.actions.map(action => action.ability).join(', ')}</p>
      {/each}
      <h2 class="font-semibold">Original SIWE message</h2>
      <pre class="whitespace-pre-wrap break-all rounded-lg bg-surface-50 p-3 text-xs">{handoff.request.siwe}</pre>
      <button disabled={busy || submitted} onclick={cancel}>Cancel</button>
    {:else if handoff && model && key}
      <p class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">Only approve if you started this sign-in yourself on your own computer.</p>
      <dl class="space-y-2 text-sm break-all">
        <div><dt class="font-semibold">Session DID (display only)</dt><dd>{handoff.request.sessionDid}</dd></div>
        <div><dt class="font-semibold">Node host</dt><dd>{handoff.request.host}</dd></div>
        <div><dt class="font-semibold">Expires</dt><dd>{handoff.expiresAt}</dd></div>
        <div><dt class="font-semibold">Signing key</dt><dd>{key.address} (chain {signingChain})</dd></div>
      </dl>
      <h2 class="font-semibold">Requested abilities and spaces</h2>
      {#each model.permissions as grant}
        <div class="rounded-lg border p-3 text-sm">
          <p class="font-semibold break-all">{grant.service} · {grant.space} · {grant.path}</p>
          {#each grant.actions as action}
            <label class="flex gap-2 py-1"><input type="checkbox" checked={selected.has(action.id)} disabled={phase !== 'review' || !action.editable} onchange={() => toggle(action.id)} /><span class="break-all">{action.ability}</span></label>
          {/each}
        </div>
      {/each}
      <h2 class="font-semibold">Original SIWE message</h2>
      <pre class="whitespace-pre-wrap break-all rounded-lg bg-surface-50 p-3 text-xs">{handoff.request.siwe}</pre>
      {#if phase === 'preview'}
        <h2 class="font-semibold">Exact candidate signedMessage</h2>
        <pre class="whitespace-pre-wrap break-all rounded-lg bg-surface-50 p-3 text-xs">{previewMessage}</pre>
        <button onclick={() => { phase = 'review'; previewToken = ''; }}>Change abilities</button>
        <button disabled={busy || submitted} onclick={approve}>Approve</button>
      {:else}
        <button disabled={busy || submitted || selectedIds().length === 0} onclick={preview}>Preview signing message</button>
      {/if}
      <button disabled={busy || submitted} onclick={cancel}>Cancel</button>
    {/if}
  </main>
</div>
