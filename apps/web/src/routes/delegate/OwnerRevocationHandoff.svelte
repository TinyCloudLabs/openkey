<script lang="ts">
  import { onMount } from 'svelte';
  import { afterNavigate, replaceState } from '$app/navigation';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { copyText } from '$lib/clipboard';
  import { getSessionToken } from '$lib/embed-passkey';
  import { ownerRevocationCopy as text } from '$lib/owner-revocation-copy';
  import { deliverOwnerRevocation } from '$lib/owner-revocation-response';
  import { fitsPreparedLinkBudget } from '$lib/prepared-link';
  import { ownerRevocationAddress, parseOwnerRevocationRequest, renderSiweLiteral, type OwnerRevocationRequest } from '@openkey/capability-review';

  let { encoded, onClear }: { encoded: string; onClear: () => void } = $props();
  const session = authClient.useSession();
  const apiUrl = import.meta.env.VITE_API_URL || '';
  type Delivery = { handoffId: string; state: string; cancelSecret: string; callback?: string };
  type Claim = { transportVersion: 2; request: OwnerRevocationRequest; delivery: Delivery };
  let pending = $state<Claim | null>(null);
  let request = $state<OwnerRevocationRequest | null>(null);
  let delivery = $state<Delivery | null>(null);
  let ticket = $state('');
  let keys = $state<EthereumKey[]>([]);
  let key = $state<EthereumKey | null>(null);
  let contextToken = $state('');
  let siwe = $state('');
  let code = $state('');
  let delivered = $state(false);
  let error = $state('');
  let initialized = $state(false);
  let loaded = $state(false);
  let busy = $state(false);
  let submitted = $state(false);
  let signingIn = $state(false);
  let loginRequired = $state(false);
  let pendingTimeout: ReturnType<typeof setTimeout> | undefined;
  let routerReady = false;
  let markerNeeded = false;
  afterNavigate(() => {
    routerReady = true;
    if (markerNeeded) {
      markerNeeded = false;
      replaceState(`${location.pathname}?transportVersion=2`, {});
    }
  });

  function clearPending() {
    if (pendingTimeout !== undefined) clearTimeout(pendingTimeout);
    try { sessionStorage.removeItem('openkey.delegate.tv2.pending'); } catch { /* Tab storage is optional after claim. */ }
    onClear();
    if (routerReady) replaceState(`${location.pathname}?transportVersion=2`, {});
    else markerNeeded = true;
  }

  function validDelivery(value: unknown): value is Delivery {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const item = value as Record<string, unknown>;
    const opaque = (part: unknown) => typeof part === 'string' && /^[A-Za-z0-9_-]{43}$/.test(part);
    return Object.keys(item).every(field => ['handoffId', 'state', 'cancelSecret', 'callback'].includes(field)) &&
      opaque(item.handoffId) && opaque(item.state) && opaque(item.cancelSecret) &&
      item.handoffId !== item.state && item.handoffId !== item.cancelSecret && item.state !== item.cancelSecret &&
      (item.callback === undefined || (typeof item.callback === 'string' &&
        /^http:\/\/(?:127\.0\.0\.1|\[::1\]):[0-9]{4,5}\/callback\/[A-Za-z0-9_-]{22}$/.test(item.callback) &&
        Number(new URL(item.callback).port) >= 1024));
  }

  onMount(() => {
    try {
      if (!encoded.startsWith('#tv2=') || !fitsPreparedLinkBudget(location, encoded)) throw new Error('Invalid prepared revocation link. Restart the CLI command.');
      const binary = atob(encoded.slice(5).replace(/-/g, '+').replace(/_/g, '/'));
      const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
      const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid prepared revocation request.');
      const claim = value as Record<string, unknown>;
      if (Object.keys(claim).sort().join(',') !== 'delivery,request,transportVersion' || claim.transportVersion !== 2 || !validDelivery(claim.delivery)) {
        throw new Error('Invalid prepared revocation envelope.');
      }
      const checked = parseOwnerRevocationRequest(claim.request);
      pending = { transportVersion: 2, request: claim.request as OwnerRevocationRequest, delivery: claim.delivery };
      pendingTimeout = setTimeout(() => {
        pending = null;
        clearPending();
        error = 'Prepared revocation request expired. Restart the CLI command.';
      }, Math.min(Date.parse(checked.expiresAt) - Date.now(), 300_000));
    } catch (cause) {
      clearPending();
      error = cause instanceof Error ? cause.message : 'Invalid prepared revocation request.';
    } finally { initialized = true; }
    return () => { if (pendingTimeout !== undefined) clearTimeout(pendingTimeout); };
  });

  async function post(path: string, body: unknown): Promise<Record<string, unknown>> {
    const token = getSessionToken();
    const response = await fetch(`${apiUrl}/api/delegate/${path}`, {
      method: 'POST', credentials: token ? 'omit' : 'include',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });
    const data: unknown = await response.json().catch(() => null);
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('OpenKey returned an unreadable response.');
    const result = data as Record<string, unknown>;
    if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : `HTTP ${response.status}`);
    return result;
  }

  async function load() {
    const input = pending;
    if (!input) return;
    busy = true;
    try {
      const availability = await fetch(`${apiUrl}/api/delegate/handoffs/available`, { credentials: 'include', cache: 'no-store' });
      if (!availability.ok || (await availability.json()).transportVersion !== 2) throw new Error('Prepared handoff is unavailable. Restart the CLI command.');
      const claimed = await post('handoffs/claim', input);
      if (pending !== input || claimed.ticket !== input.delivery.handoffId || typeof claimed.expiresAt !== 'string') {
        throw new Error('Prepared handoff expired. Restart the CLI command.');
      }
      const listed = await api.listKeys();
      const owner = ownerRevocationAddress(input.request);
      const choices = listed.keys.filter(item => item.address.toLowerCase() === owner.toLowerCase());
      if (!choices.length) throw new Error('The signed-in account has no key matching the requested owner.');
      ticket = input.delivery.handoffId;
      request = input.request;
      delivery = input.delivery;
      keys = choices;
      pending = null;
      clearPending();
      if (choices.length === 1) await chooseKey(choices[0]!);
    } catch (cause) {
      pending = null;
      clearPending();
      error = cause instanceof Error ? cause.message : 'Could not claim the prepared revocation.';
    } finally { busy = false; }
  }

  $effect(() => {
    if (!initialized || !pending || loaded || $session.isPending) return;
    if (!$session.data) loginRequired = true;
    else if (!loginRequired) { loaded = true; void load(); }
  });

  async function chooseKey(choice: EthereumKey) {
    if (!request || !ticket || contextToken) return;
    busy = true;
    error = '';
    try {
      const prepared = await post('owner-revocation/prepare', { ticket, keyId: choice.id });
      if (typeof prepared.siwe !== 'string' || typeof prepared.authorizationContextToken !== 'string') {
        throw new Error('OpenKey did not return a signing preview.');
      }
      key = choice;
      siwe = prepared.siwe;
      contextToken = prepared.authorizationContextToken;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not prepare owner signature.';
    } finally { busy = false; }
  }

  async function revoke() {
    if (!key || !request || !delivery || !ticket || !contextToken || !siwe || busy || submitted) return;
    busy = true;
    error = '';
    try {
      let externalSignature: string | undefined;
      if (key.keyType === 'EXTERNAL') {
        const provider = (window as Window & { ethereum?: { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> } }).ethereum;
        if (!provider) throw new Error('The owner wallet is unavailable.');
        const chain = await provider.request({ method: 'eth_chainId' });
        if (typeof chain !== 'string' || !/^0x[0-9a-fA-F]+$/.test(chain) ||
          BigInt(chain) !== BigInt(request.ownerDid.split(':')[3]!)) {
          throw new Error('The owner wallet is on a different chain.');
        }
        const accounts = await provider.request({ method: 'eth_requestAccounts' });
        if (!Array.isArray(accounts) || !accounts.every(value => typeof value === 'string')) throw new Error('Owner wallet returned invalid accounts.');
        const account = accounts.find(value => value.toLowerCase() === key!.address.toLowerCase());
        if (!account) throw new Error('The owner wallet does not match this request.');
        const signed = await provider.request({ method: 'personal_sign', params: [siwe, account] });
        if (typeof signed !== 'string') throw new Error('Owner wallet did not return a signature.');
        externalSignature = signed;
      }
      submitted = true;
      const signed = await post('owner-revocation/sign', { ticket, keyId: key.id, authorizationContextToken: contextToken, ...(externalSignature ? { externalSignature } : {}) });
      if (signed.siwe !== siwe || typeof signed.signature !== 'string' || signed.deliveryState !== delivery.state || signed.selectedKeyId !== key.id) {
        throw new Error('Signed response differs from the reviewed revocation.');
      }
      const result = await deliverOwnerRevocation({ state: delivery.state, siwe, signature: signed.signature, callback: delivery.callback });
      code = result.code;
      delivered = result.delivered;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Owner signing failed. Restart the CLI command.';
    } finally { busy = false; }
  }

  async function cancel() {
    if (busy || submitted) return;
    if (!ticket) { pending = null; clearPending(); error = 'Approval cancelled. Restart the CLI command.'; return; }
    busy = true;
    try {
      const result = await post('handoffs/cancel-claimed', { ticket });
      if (result.cancelled !== true) throw new Error('The handoff was not cancelled.');
      request = null;
      delivery = null;
      error = 'Approval cancelled. Restart the CLI command.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not cancel the handoff.';
    } finally { busy = false; }
  }

  async function signIn() {
    signingIn = true;
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) error = authErrorMessage(result.error, 'Passkey sign-in failed');
      else loginRequired = false;
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Passkey sign-in failed'; }
    finally { signingIn = false; }
  }
</script>

<div class="min-h-screen bg-[#fafafa] flex items-center justify-center px-4 py-8">
  <main class="w-full max-w-xl rounded-xl border border-surface-200 bg-white p-6 shadow-sm space-y-5">
    <header><h1 class="text-xl font-semibold text-surface-900">{text.title}</h1></header>
    {#if error}<p role="alert" class="rounded-lg bg-red-50 p-3 text-red-800">{error}</p>{/if}
    {#if !initialized || $session.isPending}<p>Checking your OpenKey account…</p>
    {:else if error && !request && !pending}<p>Start a new CLI revocation request.</p>
    {:else if !$session.data}
      <p>Sign in to review this request.</p>
      <a href={`/auth/login?redirect=${encodeURIComponent('/delegate?transportVersion=2')}`}>Continue with email</a>
      <button disabled={signingIn} onclick={signIn}>Use a passkey instead</button>
      <button onclick={cancel}>{text.cancel}</button>
    {:else if loginRequired}
      <p>Sign-in completed in this tab. Continue to review the prepared request.</p>
      <button onclick={() => { loginRequired = false; }}>Continue to approval</button>
      <button onclick={cancel}>{text.cancel}</button>
    {:else if code}
      {#if delivered}<p role="status">{text.signed} You can close this window.</p>
      {:else}
        <p>{text.paste}</p>
        <textarea readonly aria-label="Full revocation code" class="w-full h-28 break-all rounded-lg border p-2 font-mono text-xs" value={code}></textarea>
        <button onclick={() => copyText(code)}>Copy full code</button>
      {/if}
    {:else if request}
      <p class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">{text.warning}</p>
      <dl class="space-y-2 text-sm break-all">
        <div><dt class="font-semibold">{text.permission}</dt><dd><code>{request.cid.slice(0, 10)}…{request.cid.slice(-6)}</code></dd></div>
        <div><dt class="font-semibold">{text.fullCid}</dt><dd><input aria-label={text.fullCid} readonly value={request.cid} class="w-full rounded-lg border border-surface-200 bg-surface-50 p-2 font-mono text-xs" /><p class="mt-1">{text.matchCid}</p></dd></div>
        <div><dt class="font-semibold">{text.owner}</dt><dd><code>{ownerRevocationAddress(request)}</code></dd></div>
        {#if siwe}<div><dt class="font-semibold">{text.expires}</dt><dd>{siwe.match(/^Expiration Time: (.+)$/m)?.[1]}</dd></div>{/if}
      </dl>
      {#if !key}
        <h2 class="font-semibold">Choose the owner signing key</h2>
        {#each keys as choice (choice.id)}
          <button class="block w-full rounded-lg border p-3 text-left text-sm break-all" disabled={busy} onclick={() => chooseKey(choice)}>{choice.label ?? `Key ${choice.keyIndex}`} · {choice.address}</button>
        {/each}
      {:else}
        <h2 class="font-semibold">Exact message to sign</h2>
        <pre class="whitespace-pre overflow-x-auto max-w-full min-w-0 rounded-lg bg-surface-50 p-3 text-xs">{renderSiweLiteral(siwe)}</pre>
        <button disabled={busy || submitted} onclick={revoke}>{text.revoke}</button>
      {/if}
      <button disabled={busy || submitted} onclick={cancel}>{text.cancel}</button>
    {:else}<p>Loading prepared revocation…</p>{/if}
  </main>
</div>
