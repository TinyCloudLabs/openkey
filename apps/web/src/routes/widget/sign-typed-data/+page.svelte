<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';

  const session = authClient.useSession();

  let typedData = $state<{
    domain: any;
    types: any;
    primaryType: string;
    message: any;
  } | null>(null);
  let keyId = $state<string | null>(null);
  let key = $state<EthereumKey | null>(null);
  let loading = $state(true);
  let signing = $state(false);
  let error = $state('');

  const origin = $page.url.searchParams.get('origin') || '*';

  onMount(async () => {
    window.addEventListener('message', handleMessage);

    if ($session.data) {
      loading = false;
    }
  });

  async function handleMessage(event: MessageEvent) {
    if (event.data?.type === 'openkey:signTypedData:request') {
      typedData = event.data.data;
      keyId = event.data.data?.keyId || null;

      if (keyId && $session.data) {
        try {
          const result = await api.getKey(keyId);
          key = result.key;
        } catch {
          // Key not found
        }
      }
    }
  }

  async function signTypedData() {
    if (!key || !typedData) return;

    signing = true;
    error = '';

    try {
      const result = await api.signTypedData(key.id, typedData);
      sendResponse({
        type: 'openkey:signTypedData:response',
        success: true,
        signature: result.signature,
        address: result.address,
      });
      sendClose();
    } catch (e: any) {
      error = e.message || 'Signing failed';
    } finally {
      signing = false;
    }
  }

  function cancel() {
    sendResponse({
      type: 'openkey:signTypedData:response',
      success: false,
      error: { code: 'USER_CANCELLED', message: 'User cancelled' },
    });
    sendClose();
  }

  function sendResponse(data: object) {
    if (window.opener) {
      window.opener.postMessage(data, origin);
    } else if (window.parent !== window) {
      window.parent.postMessage(data, origin);
    }
  }

  function sendClose() {
    const closeMsg = { type: 'openkey:close' };
    if (window.opener) {
      window.opener.postMessage(closeMsg, origin);
      window.close();
    } else if (window.parent !== window) {
      window.parent.postMessage(closeMsg, origin);
    }
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
</script>

<div class="sign-widget">
  <header>
    <h1>Sign Typed Data</h1>
    <button class="close-btn" onclick={cancel}>×</button>
  </header>

  {#if !$session.data}
    <div class="auth-needed">
      <p>Sign in to sign data</p>
      <a href="/auth/login" class="button primary">Sign In</a>
    </div>
  {:else if loading}
    <div class="loading">Loading...</div>
  {:else if !key}
    <div class="no-key">
      <p>Please connect first to sign data.</p>
    </div>
  {:else if !typedData}
    <div class="no-data">
      <p>No data to sign.</p>
    </div>
  {:else}
    <div class="sign-form">
      <div class="key-info">
        <span class="label">Signing with:</span>
        <span class="value">{key.label || `Key ${key.keyIndex}`}</span>
        <code>{formatAddress(key.address)}</code>
      </div>

      <div class="data-preview">
        <span class="label">Domain:</span>
        <pre>{JSON.stringify(typedData.domain, null, 2)}</pre>
      </div>

      <div class="data-preview">
        <span class="label">{typedData.primaryType}:</span>
        <pre>{JSON.stringify(typedData.message, null, 2)}</pre>
      </div>

      {#if error}
        <div class="error">{error}</div>
      {/if}

      <div class="actions">
        <button class="button secondary" onclick={cancel}>Cancel</button>
        <button class="button primary" onclick={signTypedData} disabled={signing}>
          {signing ? 'Signing...' : 'Sign Data'}
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .sign-widget {
    flex: 1;
    display: flex;
    flex-direction: column;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  h1 {
    font-size: 1.25rem;
    margin: 0;
  }

  .close-btn {
    background: transparent;
    border: none;
    color: #888;
    font-size: 1.5rem;
    cursor: pointer;
    padding: 0;
    line-height: 1;
  }

  .auth-needed, .loading, .no-key, .no-data {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    color: #888;
  }

  .sign-form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    flex: 1;
  }

  .key-info, .data-preview {
    background: #1a1a1a;
    border: 1px solid #333;
    border-radius: 8px;
    padding: 1rem;
  }

  .label {
    display: block;
    color: #888;
    font-size: 0.75rem;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }

  .value {
    font-weight: 600;
    margin-right: 0.5rem;
  }

  code {
    font-family: 'SF Mono', Monaco, monospace;
    color: #888;
    font-size: 0.875rem;
  }

  pre {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
    font-family: 'SF Mono', Monaco, monospace;
    font-size: 0.75rem;
    max-height: 120px;
    overflow-y: auto;
  }

  .actions {
    display: flex;
    gap: 0.75rem;
    margin-top: auto;
  }

  .button {
    flex: 1;
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    text-align: center;
    transition: all 0.2s;
  }

  .button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .button.primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }

  .button.secondary {
    background: transparent;
    border: 1px solid #333;
    color: #fafafa;
  }

  .error {
    background: rgba(255, 68, 68, 0.1);
    border: 1px solid #ff4444;
    color: #ff4444;
    padding: 1rem;
    border-radius: 8px;
  }
</style>
