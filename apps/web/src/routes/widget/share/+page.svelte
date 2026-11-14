<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { startAuthentication } from '@simplewebauthn/browser';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { autoSelectKey } from '$lib/delegate-key-selection';
  import { parseSIWE } from '$lib/siwe-parser';
  import { acceptRequesterHello } from '$lib/requester-window';
  import { listenForApprovalCancellation } from '$lib/approval-cancellation';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import ShareApproval, { type ShareReviewPreview } from '$lib/components/signing/share-approval.svelte';

  type Preview = ShareReviewPreview & { expiresAt: number; assertion: { token: string; options: Parameters<typeof startAuthentication>[0]['optionsJSON'] } };
  const session = authClient.useSession();
  const outerRequestId = $page.url.searchParams.get('requestId') ?? '';
  const apiUrl = import.meta.env.VITE_API_URL || '';
  let origin = $state('');
  let intent = $state<Record<string, unknown> | null>(null);
  let selectedKey = $state<EthereumKey | null>(null);
  let preview = $state<Preview | null>(null);
  let windowToken = '';
  let pinnedSession = '';
  let busy = $state(false);
  let error = $state('');
  let enabled = $state(false);
  let terminal = $state(false);
  let signatureResolve: ((signature: string) => void) | undefined;
  let signatureReject: ((error: Error) => void) | undefined;

  function post(type: string, data: Record<string, unknown> = {}) {
    if (origin) window.opener?.postMessage({ type, protocolVersion: 1, outerRequestId, ...data }, origin);
  }
  async function request(phase: string, body: Record<string, unknown>, keepalive = false) {
    const response = await fetch(`${apiUrl}/api/delegate/share/${phase}`, {
      method: 'POST', credentials: 'include', keepalive,
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.code ?? 'Share approval refused');
    return result;
  }
  function payload() {
    return preview && selectedKey ? { requestId: preview.requestId, keyId: selectedKey.id, token: preview.assertion.token } : null;
  }
  async function cancel(close = false) {
    terminal = true;
    signatureReject?.(new Error('Share approval cancelled'));
    const body = payload();
    try {
      if (body) await request('cancel', body, true);
      else if (windowToken && selectedKey) await request('window/cancel', {
        requestId: outerRequestId, keyId: selectedKey.id, windowContextToken: windowToken,
      }, true);
    } catch { /* The short-lived contexts also expire fail closed. */ }
    post('openkey:share:error', { error: 'Share approval cancelled' });
    if (close) window.close();
  }
  function checkSession() {
    if (!pinnedSession || $session.data?.session.id !== pinnedSession || terminal) throw new Error('Share account changed');
  }
  async function prepare() {
    if (!enabled || !intent || !$session.data || busy || preview || terminal) return;
    busy = true;
    try {
      pinnedSession = $session.data.session.id;
      const proof = intent.session as { siwe?: string } | undefined;
      const parsed = typeof proof?.siwe === 'string' ? parseSIWE(proof.siwe) : null;
      const address = parsed?.message.address;
      if (!address) throw new Error('Invalid signed share session');
      const keys = await api.listKeys();
      checkSession();
      selectedKey = autoSelectKey(keys.keys, address);
      if (!selectedKey) throw new Error('The signed session does not belong to this account');
      const context = await request('window', { requestId: outerRequestId, keyId: selectedKey.id, observedOrigin: origin });
      windowToken = context.windowContextToken;
      checkSession();
      const prepared = await request('options', { requestId: outerRequestId, windowContextToken: windowToken,
        intent: { ...intent, origin, keyId: selectedKey.id } });
      // Retain the returned token before a post-await account check, so cancellation can revoke it.
      preview = prepared;
      checkSession();
      post('openkey:share:preview', { preview: prepared, key: { id: selectedKey.id,
        address: selectedKey.address, keyType: selectedKey.keyType } });
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
      await cancel();
    } finally { busy = false; }
  }
  $effect(() => {
    if (enabled && intent && $session.data && !pinnedSession) void prepare();
    if (pinnedSession && $session.data?.session.id !== pinnedSession && !terminal) void cancel();
  });
  async function approve(requestId: string, intentDigest: string) {
    if (!preview || !selectedKey || busy || requestId !== preview.requestId || intentDigest !== preview.intentDigest) return;
    busy = true;
    try {
      checkSession();
      const response = await startAuthentication({ optionsJSON: preview.assertion.options });
      checkSession();
      const body = payload()!;
      await request('verify', { ...body, response });
      checkSession();
      const resumed = await request('resume', body);
      if (resumed.resumed !== true) throw new Error('Share approval could not resume');
      checkSession();
      let externalSignature: string | undefined;
      if (selectedKey.keyType === 'EXTERNAL') {
        externalSignature = await new Promise<string>((resolve, reject) => {
          signatureResolve = resolve; signatureReject = reject;
          post('openkey:share:sign', { requestId, intentDigest, message: preview!.prepared.siwe,
            address: selectedKey!.address });
        });
        signatureResolve = undefined; signatureReject = undefined;
        checkSession();
      }
      const result = await request('sign', { ...body, intentDigest, ...(externalSignature ? { externalSignature } : {}) });
      checkSession();
      terminal = true;
      post('openkey:share:result', { result });
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
      await cancel();
    } finally { busy = false; }
  }
  onMount(() => {
    const opener = window.opener;
    if (!opener || !outerRequestId) { error = 'Open this share approval from the requesting site.'; return; }
    void fetch(`${apiUrl}/api/delegate/share/capabilities`, { credentials: 'omit' })
      .then(response => response.ok ? response.json() : null).then(result => {
        enabled = result?.enabled === true && result?.protocolVersion === 1;
        if (enabled) opener.postMessage({ type: 'openkey:share:ready', protocolVersion: 1,
          purpose: 'share-create', requestId: outerRequestId }, '*');
        else error = 'Share approval is unavailable.';
      }).catch(() => { error = 'Share approval is unavailable.'; });
    const receive = (event: MessageEvent) => {
      if (!intent && enabled && !terminal) {
        const hello = acceptRequesterHello(event, { source: opener, requestId: outerRequestId,
          purpose: 'share-create', originHint: $page.url.searchParams.get('origin') });
        if (hello && hello.intent && typeof hello.intent === 'object' && !Array.isArray(hello.intent)) {
          origin = hello.origin; intent = hello.intent as Record<string, unknown>;
        }
      }
      if (event.source !== opener || event.origin !== origin || event.data?.protocolVersion !== 1 ||
        event.data?.outerRequestId !== outerRequestId) return;
      if (event.data.type === 'openkey:share:signature' && preview &&
        event.data.requestId === preview.requestId && event.data.intentDigest === preview.intentDigest &&
        typeof event.data.signature === 'string') signatureResolve?.(event.data.signature);
      if (event.data.type === 'openkey:close') void cancel(true);
    };
    const stopCancellation = listenForApprovalCancellation('share-create', () => {
      const body = payload(); return body ? { ...body, origin } : undefined;
    }, () => { terminal = true; signatureReject?.(new Error('Share approval cancelled')); });
    const onHide = () => { if (!terminal) void cancel(); };
    window.addEventListener('message', receive);
    window.addEventListener('pagehide', onHide);
    return () => { stopCancellation(); window.removeEventListener('message', receive); window.removeEventListener('pagehide', onHide); };
  });
</script>

{#if preview && selectedKey}
  <ShareApproval {preview} signer={{ label: 'Selected key', address: selectedKey.address,
    chainId: Number(preview.ownerDid.split(':')[3]), provenance: selectedKey.keyType === 'EXTERNAL' ? 'external' : 'managed' }}
    ready={!terminal} approving={busy} {error} onApprove={approve} onCancel={() => { void cancel(true); }} />
{:else if enabled && intent && !$session.data}
  <EmbeddedSignIn prompt="" onauthenticated={prepare} />
{:else if error}
  <p role="alert">{error}</p>
{/if}
