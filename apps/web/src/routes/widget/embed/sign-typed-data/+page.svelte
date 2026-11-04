<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { activeKeys, ARCHIVED_KEY_MESSAGE } from '$lib/delegate-key-selection';
  import { getSessionToken, isEmbedContext } from '$lib/embed-passkey';
  import { isFromWidgetCounterparty, resolveWidgetOrigin } from '$lib/widget-transport';
  import EmbeddedSignIn from '$lib/components/auth/embedded-sign-in.svelte';
  import { passkeysSupportedFromParams } from '$lib/passkey-support';
  import Button from '$lib/components/ui/button.svelte';
  import KeyPicker from '$lib/components/keys/KeyPicker.svelte';

  type KeyCredential = { token: string | null; sessionId: string | null | undefined };
  let keyReadCredential: KeyCredential | null = null;
  let keyOwnerCredential: KeyCredential | null = null;

  const session = authClient.useSession();
  const inIframe = typeof window !== 'undefined' && isEmbedContext();

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
  let initialized = $state(false);
  let contentEl = $state<HTMLDivElement | undefined>(undefined);
  let embedAuthenticated = $state(typeof window !== 'undefined' && !!getSessionToken());

  const isAuthenticated = $derived(inIframe ? embedAuthenticated : !!$session.data);

  // Exact embedding origin; never '*' (TC-690).
  const origin = resolveWidgetOrigin($page.url.searchParams.get('origin'));
  const passkeysSupported = passkeysSupportedFromParams($page.url.searchParams);

  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      window.addEventListener('message', handleMessage);

      if (origin) window.parent.postMessage({ type: 'openkey:ready' }, origin);
    }
  });

  // ResizeObserver to notify parent of height changes
  $effect(() => {
    if (!contentEl) return;
    const observer = new ResizeObserver(() => {
      const height = contentEl!.scrollHeight;
      if (origin) window.parent.postMessage({ type: 'openkey:resize', height }, origin);
    });
    observer.observe(contentEl);
    return () => observer.disconnect();
  });

  // Load public metadata before allowing this request to reach signing review.
  $effect(() => {
    const requestedKeyId = keyId;
    const version = requestVersion;
    if (!isAuthenticated) return;
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
    const credential = {
      token: getSessionToken(),
      sessionId: inIframe ? null : $session.data?.session?.id,
    };
    keyReadCredential = credential;
    keyOwnerCredential = null;
    void (async () => {
      try {
        if (requestedKeyId) {
          const result = await api.getKey(requestedKeyId);
          if (!active || version !== requestVersion) return;
          if (!checkKeyCredential(credential)) return;
          if (result.key.archivedAt != null) {
            archivedKey = true;
          } else if (result.key.keyType !== 'MANAGED') {
            error = 'This key cannot sign typed data here. Reconnect to choose a managed key.';
          } else {
            key = result.key;
            keyOwnerCredential = credential;
          }
        } else {
          const result = await api.listKeys();
          if (!active || version !== requestVersion) return;
          if (!checkKeyCredential(credential)) return;
          // External-wallet typed-data signing is handled separately by the SDK.
          const usableKeys = activeKeys(result.keys).filter(candidate => candidate.keyType === 'MANAGED');
          keys = usableKeys;
          if (usableKeys.length === 1) chooseSigningKey(usableKeys[0]!);
        }
      } catch {
        if (!active || version !== requestVersion) return;
        if (!checkKeyCredential(credential)) return;
        error = requestedKeyId ? 'Selected key could not be loaded.' : 'Keys could not be loaded. Reconnect to try again.';
      } finally {
        if (active && version === requestVersion) loading = false;
      }
    })();
    return () => { active = false; };
  });

  function handleMessage(event: MessageEvent) {
    if (!isFromWidgetCounterparty(event, origin, window.parent)) return;
    if (event.data?.type === 'openkey:signTypedData:request') {
      requestVersion += 1;
      key = null;
      keys = [];
      keyReadCredential = null;
      keyOwnerCredential = null;
      archivedKey = false;
      error = '';
      signing = false;
      loading = true;
      typedData = event.data.data;
      keyId = event.data.data?.keyId || null;
      // A sessionToken in the message is ignored: the session comes only
      // from OpenKey-origin storage or cookies (TC-690).
    }
  }

  function checkKeyCredential(credential: KeyCredential | null): boolean {
    if (credential && isAuthenticated && getSessionToken() === credential.token &&
        (inIframe ? null : $session.data?.session?.id) === credential.sessionId) return true;
    key = null;
    keys = [];
    keyReadCredential = null;
    keyOwnerCredential = null;
    archivedKey = false;
    error = 'Signing session changed. Reconnect to choose a key.';
    return false;
  }

  function chooseSigningKey(selected: EthereumKey) {
    if (!checkKeyCredential(keyReadCredential)) return;
    const choice = keys.find(candidate => candidate.id === selected.id);
    if (!choice) return;
    key = choice;
    keyOwnerCredential = keyReadCredential;
  }

  async function signTypedData() {
    if (!key || key.keyType !== 'MANAGED' || key.archivedAt != null || archivedKey || !typedData || signing) return;

    const credential = keyOwnerCredential;
    if (!checkKeyCredential(credential)) return;
    const version = requestVersion;

    signing = true;
    error = '';

    try {
      const result = await api.signTypedData(key.id, typedData);
      if (version !== requestVersion) return;
      if (!checkKeyCredential(credential)) return;
      sendResponse({
        type: 'openkey:signTypedData:response',
        success: true,
        signature: result.signature,
        address: result.address,
      });
      sendClose();
    } catch (e: any) {
      if (version === requestVersion && checkKeyCredential(credential)) error = e.message || 'Signing failed';
    } finally {
      if (version === requestVersion) signing = false;
    }
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
    if (origin) window.parent.postMessage(data, origin);
  }

  function sendClose() {
    if (origin) window.parent.postMessage({ type: 'openkey:close' }, origin);
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }

</script>

<div bind:this={contentEl} class="flex flex-col gap-4 bg-[#fafafa] p-4 rounded-2xl">
  <!-- Header -->
  <div class="flex flex-col items-center gap-3">
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
      </svg>
    </div>
    <h1 class="text-lg font-semibold text-surface-900">Sign Typed Data</h1>
  </div>

  <!-- Card body -->
  <div class="bg-white border border-surface-200 rounded-2xl shadow-sm p-5">
    {#if !isAuthenticated}
      <EmbeddedSignIn
        prompt="Sign in to review and sign this data"
        onauthenticated={() => { embedAuthenticated = true; }}
        {passkeysSupported}
      />
    {:else if loading}
      <div class="flex flex-col items-center justify-center text-center text-surface-400 py-6">
        <svg class="w-6 h-6 animate-spin text-surface-400 mb-3" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
        <span class="text-sm text-surface-500">Loading...</span>
      </div>
    {:else if archivedKey}
      <div class="flex flex-col items-center justify-center text-center text-surface-500 py-4 gap-4">
        <p class="text-sm">{ARCHIVED_KEY_MESSAGE}</p>
        <Button variant="secondary" size="sm" onclick={cancel}>Cancel</Button>
      </div>
    {:else if !key && !keyId && keys.length > 1}
      <div class="flex flex-col gap-4">
        <KeyPicker
          {keys}
          onselect={chooseSigningKey}
          listHeading="Select a key to sign this data:"
          primaryHeading="Sign with your primary key:"
          compact={true}
        />
        <Button variant="secondary" onclick={cancel}>Cancel</Button>
      </div>
    {:else if !key}
      <div class="flex flex-col items-center justify-center text-center text-surface-500 py-4 gap-4">
        <p class="text-sm">{error || (keyId ? 'Selected key could not be loaded.' : 'No active managed keys are available to sign this data.')}</p>
        <Button variant="secondary" size="sm" onclick={cancel}>Cancel</Button>
      </div>
    {:else if !typedData}
      <div class="flex flex-col items-center justify-center text-center text-surface-500 py-4">
        <p class="text-sm">No data to sign.</p>
      </div>
    {:else}
      <div class="flex flex-col gap-3">
        <!-- Signing with -->
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Signing with</span>
          <div class="flex items-center gap-2">
            <span class="font-medium text-sm text-surface-900">{key.label || `Key ${key.keyIndex}`}</span>
            <code class="font-mono text-surface-400 text-xs">{formatAddress(key.address)}</code>
          </div>
        </div>

        <!-- Domain -->
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">Domain</span>
          <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs text-surface-900 max-h-[100px] overflow-y-auto">{JSON.stringify(typedData.domain, null, 2)}</pre>
        </div>

        <!-- Primary type data -->
        <div class="bg-surface-50 border border-surface-200 rounded-xl p-3">
          <span class="block text-surface-400 text-xs uppercase tracking-wide mb-1">{typedData.primaryType}</span>
          <pre class="m-0 whitespace-pre-wrap break-all font-mono text-xs text-surface-900 max-h-[100px] overflow-y-auto">{JSON.stringify(typedData.message, null, 2)}</pre>
        </div>

        {#if error}
          <div class="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex gap-2 mt-1">
          <Button variant="secondary" size="sm" class="flex-1 rounded-xl" onclick={cancel}>Cancel</Button>
          <Button size="sm" class="flex-1 rounded-xl" onclick={signTypedData} disabled={signing}>
            {signing ? 'Signing...' : 'Sign Data'}
          </Button>
        </div>
      </div>
    {/if}
  </div>

  <!-- Trust badge -->
  <div class="flex items-center justify-center gap-1.5 text-surface-400">
    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
    <span class="text-xs">Protected by TEE hardware security</span>
  </div>
</div>
