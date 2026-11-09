<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { activeKeys, ARCHIVED_KEY_MESSAGE } from '$lib/delegate-key-selection';
  import Button from '$lib/components/ui/button.svelte';
  import KeyPicker from '$lib/components/keys/KeyPicker.svelte';
  import SigningKeyRefusal from '$lib/components/signing/signing-key-refusal.svelte';
  import { originAuthority } from '$lib/requester-display';
  import Card from '$lib/components/ui/card.svelte';
  import { passkeysSupportedFromParams, withPasskeysFlag } from '$lib/passkey-support';
  import { isFromWidgetCounterparty, resolveWidgetOrigin } from '$lib/widget-transport';

  const session = authClient.useSession();

  let typedData = $state<{
    domain: any;
    types: any;
    primaryType: string;
    message: any;
  } | null>(null);
  let keyId = $state<string | null>(null);
  let key = $state<EthereumKey | null>(null);
  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');
  let archivedKey = $state(false);
  let requestVersion = $state(0);

  // Exact requesting origin; never '*' (TC-690).
  const origin = resolveWidgetOrigin($page.url.searchParams.get('origin'));
  const passkeysSupported = passkeysSupportedFromParams($page.url.searchParams);
  const requester = originAuthority(origin ?? '');
  const reconnectHint = `Go back to ${requester || 'the requesting app'} and connect again to choose a key.`;
  const refusalMessage = $derived(archivedKey ? ARCHIVED_KEY_MESSAGE :
    error || (keyId ? 'Selected key could not be loaded.' : 'No active managed keys are available to sign this data.'));

  // The window that opened this widget: the opener for a popup, otherwise
  // the parent frame.
  const counterparty: Window | null = typeof window === 'undefined'
    ? null
    : window.opener ?? (window.parent !== window ? window.parent : null);
  let initialized = $state(false);

  // Use $effect instead of onMount for Svelte 5 compatibility with SSR disabled
  // onMount doesn't fire when ssr=false in SvelteKit, but $effect does
  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      // Listen for incoming messages
      window.addEventListener('message', handleMessage);

      // Notify parent that widget is ready (AFTER listener is set up)
      if (origin) counterparty?.postMessage({ type: 'openkey:ready' }, origin);
    }
  });

  // Load public metadata before allowing this request to reach signing review.
  $effect(() => {
    const requestedKeyId = keyId;
    const version = requestVersion;
    if (!$session.data) return;
    if (!version) {
      loading = false;
      return;
    }

    let active = true;
    loading = true;
    key = null;
    keys = [];
    archivedKey = false;
    error = '';
    void (async () => {
      try {
        if (requestedKeyId) {
          const result = await api.getKey(requestedKeyId);
          if (!active || version !== requestVersion) return;
          if (result.key.archivedAt != null) {
            archivedKey = true;
          } else if (result.key.keyType !== 'MANAGED') {
            error = 'This key cannot sign typed data here. Reconnect to choose a managed key.';
          } else {
            key = result.key;
          }
        } else {
          const result = await api.listKeys();
          if (!active || version !== requestVersion) return;
          // External-wallet typed-data signing is handled separately by the SDK.
          const usableKeys = activeKeys(result.keys).filter(candidate => candidate.keyType === 'MANAGED');
          keys = usableKeys;
          if (usableKeys.length === 1) key = usableKeys[0]!;
        }
      } catch {
        if (!active || version !== requestVersion) return;
        error = requestedKeyId ? 'Selected key could not be loaded.' : 'Keys could not be loaded. Reconnect to try again.';
      } finally {
        if (active && version === requestVersion) loading = false;
      }
    })();
    return () => { active = false; };
  });

  function handleMessage(event: MessageEvent) {
    if (!isFromWidgetCounterparty(event, origin, counterparty)) return;
    if (event.data?.type === 'openkey:signTypedData:request') {
      requestVersion += 1;
      key = null;
      keys = [];
      archivedKey = false;
      error = '';
      signing = false;
      loading = true;
      typedData = event.data.data;
      keyId = event.data.data?.keyId || null;
    }
  }

  async function signTypedData() {
    if (!key || key.keyType !== 'MANAGED' || key.archivedAt != null || archivedKey || !typedData || signing) return;

    const version = requestVersion;

    signing = true;
    error = '';

    try {
      const result = await api.signTypedData(key.id, typedData);
      if (version !== requestVersion) return;
      sendResponse({
        type: 'openkey:signTypedData:response',
        success: true,
        signature: result.signature,
        address: result.address,
      });
      sendClose();
    } catch (e: any) {
      if (version === requestVersion) error = e.message || 'Signing failed';
    } finally {
      if (version === requestVersion) signing = false;
    }
  }

  function reconnect() {
    sendResponse({
      type: 'openkey:signTypedData:response',
      success: false,
      error: { code: 'NO_KEY', message: `${refusalMessage} ${reconnectHint}` },
    });
    sendClose();
  }

  function cancel() {
    sendResponse({
      type: 'openkey:signTypedData:response',
      success: false,
      error: archivedKey
        ? { code: 'NO_KEY', message: ARCHIVED_KEY_MESSAGE }
        : { code: 'USER_CANCELLED', message: 'User cancelled' },
    });
    sendClose();
  }

  function sendResponse(data: object) {
    if (origin) counterparty?.postMessage(data, origin);
  }

  function sendClose() {
    if (origin) counterparty?.postMessage({ type: 'openkey:close' }, origin);
    if (window.opener) window.close();
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
</script>

<div class="flex-1 flex flex-col">
  <header class="flex justify-between items-center mb-6">
    <h1 class="text-xl font-semibold text-surface-900">Sign Typed Data</h1>
    <button
      class="bg-transparent border-none text-surface-600 text-2xl cursor-pointer p-0 leading-none hover:text-surface-900 transition-colors"
      onclick={cancel}
    >
      &times;
    </button>
  </header>

  {#if !$session.data}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p class="mb-4">Sign in to sign data</p>
      <Button href={withPasskeysFlag(`/auth/login?redirect=/widget/sign-typed-data?origin=${encodeURIComponent(origin ?? '')}`, passkeysSupported)}>Sign In</Button>
    </div>
  {:else if loading}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      Loading...
    </div>
  {:else if archivedKey}
    <SigningKeyRefusal message={refusalMessage} {requester} onreconnect={reconnect} />
  {:else if !key && !keyId && keys.length > 1}
    <div class="flex flex-col gap-4">
      <KeyPicker
        {keys}
        onselect={selected => { key = selected; }}
        listHeading="Select a key to sign this data:"
        primaryHeading="Sign with your primary key:"
        compact={false}
      />
      <Button variant="secondary" onclick={cancel}>Cancel</Button>
    </div>
  {:else if !key}
    <SigningKeyRefusal message={refusalMessage} {requester} onreconnect={reconnect} />
  {:else if !typedData}
    <div class="flex-1 flex flex-col items-center justify-center text-center text-surface-400">
      <p>No data to sign.</p>
    </div>
  {:else}
    <div class="flex flex-col gap-4 flex-1">
      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">Signing with:</span>
        <span class="font-semibold mr-2">{key.label || `Key ${key.keyIndex}`}</span>
        <code class="font-mono text-surface-400 text-sm">{formatAddress(key.address)}</code>
      </Card>

      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">Domain:</span>
        <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs max-h-[120px] overflow-y-auto">{JSON.stringify(typedData.domain, null, 2)}</pre>
      </Card>

      <Card class="p-4">
        <span class="block text-surface-400 text-xs uppercase mb-2">{typedData.primaryType}:</span>
        <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs max-h-[120px] overflow-y-auto">{JSON.stringify(typedData.message, null, 2)}</pre>
      </Card>

      {#if error}
        <Card class="bg-red-500/10 border-red-500 text-red-500 p-4">
          {error}
        </Card>
      {/if}

      <div class="flex gap-3 mt-auto">
        <Button variant="secondary" class="flex-1" onclick={cancel}>Cancel</Button>
        <Button class="flex-1" onclick={signTypedData} disabled={signing}>
          {signing ? 'Signing...' : 'Sign Data'}
        </Button>
      </div>
    </div>
  {/if}
</div>
