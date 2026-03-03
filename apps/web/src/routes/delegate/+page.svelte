<script lang="ts">
  import { page } from '$app/stores';
  import { authClient } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import SiweMessage from '$lib/components/ui/siwe-message.svelte';

  interface EIP6963ProviderInfo {
    uuid: string;
    name: string;
    icon: string;
    rdns: string;
  }

  interface EIP6963ProviderDetail {
    info: EIP6963ProviderInfo;
    provider: any;
  }

  const session = authClient.useSession();

  let keys = $state<EthereumKey[]>([]);
  let loading = $state(true);
  let selectedKey = $state<EthereumKey | null>(null);
  let error = $state('');
  let keysLoaded = $state(false);
  let initialized = $state(false);
  let signingIn = $state(false);
  let delegating = $state(false);
  let done = $state(false);
  let pasteCode = $state('');
  let step = $state<'select-key' | 'link-wallet' | 'consent' | 'choose-wallet' | 'done'>('select-key');
  let preparedData = $state<any>(null);
  let siweMessage = $state('');
  let preparing = $state(false);

  // Link wallet state
  let wallets = $state<EIP6963ProviderDetail[]>([]);
  let selectedWallet = $state<EIP6963ProviderDetail | null>(null);
  let linking = $state(false);

  // Parse query params
  const did = $page.url.searchParams.get('did') || '';
  const jwkB64 = $page.url.searchParams.get('jwk') || '';
  const callback = $page.url.searchParams.get('callback') || '';
  const host = $page.url.searchParams.get('host') || 'https://node.tinycloud.xyz';

  // Decode JWK from base64url
  let jwk: object | null = null;
  if (jwkB64) {
    try {
      jwk = JSON.parse(atob(jwkB64.replace(/-/g, '+').replace(/_/g, '/')));
    } catch {
      // Will show error in UI
    }
  }

  $effect(() => {
    if (typeof window !== 'undefined' && !initialized) {
      initialized = true;

      // Discover wallets via EIP-6963
      window.addEventListener('eip6963:announceProvider', ((event: CustomEvent<EIP6963ProviderDetail>) => {
        const detail = event.detail;
        if (!wallets.find(w => w.info.uuid === detail.info.uuid)) {
          wallets = [...wallets, detail];
        }
      }) as EventListener);
      window.dispatchEvent(new Event('eip6963:requestProvider'));
    }
  });

  // Reactively load keys when session becomes available
  $effect(() => {
    if ($session.data && !keysLoaded) {
      keysLoaded = true;
      loadKeys();
    }
  });

  async function loadKeys() {
    loading = true;
    try {
      const result = await api.listKeys();
      keys = result.keys;
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function generateAndSelect() {
    loading = true;
    error = '';
    try {
      const { key } = await api.generateKey();
      loading = false;
      await onKeySelect(key);
    } catch (e: any) {
      error = e.message;
      loading = false;
    }
  }

  async function onKeySelect(key: EthereumKey) {
    if (!jwk) {
      error = 'Missing JWK parameter. Please restart the CLI auth flow.';
      return;
    }

    selectedKey = key;
    error = '';
    preparing = true;

    try {
      // Always call /prepare to get the SIWE message for display
      const API_URL = import.meta.env.VITE_API_URL || '';
      const res = await fetch(`${API_URL}/api/delegate/prepare`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          keyId: key.id,
          jwk,
          host,
          prefix: 'default',
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(body.error || `HTTP ${res.status}`);
      }

      const data = await res.json();
      preparedData = data.prepared;
      siweMessage = data.prepared.siwe || '';
      step = 'consent';
    } catch (e: any) {
      error = e.message || 'Failed to prepare delegation';
      selectedKey = null;
    } finally {
      preparing = false;
    }
  }

  function showLinkWallet() {
    step = 'link-wallet';
    error = '';
    selectedWallet = null;
  }

  function goBack() {
    selectedKey = null;
    step = 'select-key';
    error = '';
  }

  function selectWallet(wallet: EIP6963ProviderDetail) {
    selectedWallet = wallet;
    error = '';
  }

  function getProvider(): any {
    if (selectedWallet) return selectedWallet.provider;
    return (window as any).ethereum;
  }

  async function connectAndLink() {
    const provider = getProvider();
    if (!provider) {
      error = 'No wallet detected. Please install a browser wallet and try again.';
      return;
    }

    linking = true;
    error = '';

    try {
      const accounts: string[] = await provider.request({ method: 'eth_requestAccounts' });
      if (!accounts || accounts.length === 0) {
        throw new Error('No accounts returned from wallet');
      }
      const account = accounts[0];

      const challenge = await api.getLinkChallenge();

      const signature: string = await provider.request({
        method: 'personal_sign',
        params: [challenge.message, account],
      });

      await api.linkWallet({
        address: account,
        signature,
        message: challenge.message,
      });

      // Reload keys and go back to selection
      await loadKeys();
      step = 'select-key';
    } catch (e: any) {
      if (e.code === 4001) {
        error = 'Wallet connection was rejected.';
      } else {
        error = e.message || 'Failed to link wallet';
      }
    } finally {
      linking = false;
    }
  }

  // Wallet chosen by user for external key signing (distinct from selectedWallet used in link-wallet flow)
  let signingWallet = $state<EIP6963ProviderDetail | null>(null);

  function getSigningProvider(): any {
    if (signingWallet) return signingWallet.provider;
    return (window as any).ethereum;
  }

  function approveDelegate() {
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }

    if (selectedKey.keyType === 'MANAGED') {
      doManagedDelegate();
    } else {
      // External key: need a wallet to sign
      if (wallets.length > 1 && !signingWallet) {
        // Multiple wallets detected — let user choose
        step = 'choose-wallet';
        error = '';
      } else {
        doExternalDelegate();
      }
    }
  }

  function onSigningWalletSelect(wallet: EIP6963ProviderDetail) {
    signingWallet = wallet;
    error = '';
  }

  function confirmSigningWallet() {
    if (!signingWallet && wallets.length > 0) {
      error = 'Please select a wallet.';
      return;
    }
    doExternalDelegate();
  }

  function backToConsent() {
    step = 'consent';
    error = '';
  }

  async function doManagedDelegate() {
    delegating = true;
    error = '';

    try {
      const API_URL = import.meta.env.VITE_API_URL || '';
      const res = await fetch(`${API_URL}/api/delegate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          keyId: selectedKey!.id,
          jwk,
          host,
          prefix: 'default',
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(body.error || `HTTP ${res.status}`);
      }

      await finishDelegate(await res.json());
    } catch (e: any) {
      error = e.message || 'Delegation failed';
    } finally {
      delegating = false;
    }
  }

  async function doExternalDelegate() {
    if (!preparedData) {
      error = 'No prepared session data. Please go back and try again.';
      return;
    }

    delegating = true;
    error = '';

    try {
      const provider = getSigningProvider();
      if (!provider) {
        throw new Error('No wallet detected. Please install a browser wallet to sign with external keys.');
      }

      // Try each wallet to find the matching account
      let matchingAccount: string | undefined;
      let matchingProvider = provider;

      // If multiple wallets and no explicit choice, try all of them
      const providersToTry = signingWallet
        ? [signingWallet.provider]
        : wallets.length > 0
          ? wallets.map(w => w.provider)
          : [provider];

      for (const p of providersToTry) {
        try {
          const accounts: string[] = await p.request({ method: 'eth_requestAccounts' });
          const found = accounts.find(
            (a: string) => a.toLowerCase() === selectedKey!.address.toLowerCase()
          );
          if (found) {
            matchingAccount = found;
            matchingProvider = p;
            break;
          }

          // Try requesting more accounts
          try {
            await p.request({
              method: 'wallet_requestPermissions',
              params: [{ eth_accounts: {} }],
            });
            const moreAccounts: string[] = await p.request({ method: 'eth_accounts' });
            const found2 = moreAccounts.find(
              (a: string) => a.toLowerCase() === selectedKey!.address.toLowerCase()
            );
            if (found2) {
              matchingAccount = found2;
              matchingProvider = p;
              break;
            }
          } catch {
            // wallet_requestPermissions not supported or rejected
          }
        } catch {
          // This provider failed, try next
        }
      }

      if (!matchingAccount) {
        throw new Error(
          `None of your connected wallets have account ${selectedKey!.address}. ` +
          `Please connect the wallet that holds this account and try again.`
        );
      }

      const signature: string = await matchingProvider.request({
        method: 'personal_sign',
        params: [preparedData.siwe, matchingAccount],
      });

      const API_URL = import.meta.env.VITE_API_URL || '';
      const compRes = await fetch(`${API_URL}/api/delegate/complete`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prepared: preparedData,
          signature,
          host,
          jwk,
        }),
      });

      if (!compRes.ok) {
        const body = await compRes.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(body.error || `HTTP ${compRes.status}`);
      }

      await finishDelegate(await compRes.json());
    } catch (e: any) {
      if (e.code === 4001) {
        error = 'Signature was rejected by wallet.';
      } else {
        error = e.message || 'Delegation failed';
      }
    } finally {
      delegating = false;
    }
  }

  async function finishDelegate(data: any) {
    if (callback) {
      const cbRes = await fetch(callback, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!cbRes.ok) {
        throw new Error('Failed to send delegation data to CLI');
      }

      done = true;
      step = 'done';
    } else {
      pasteCode = btoa(JSON.stringify(data));
      done = true;
      step = 'done';
    }
  }

  async function signInWithPasskey() {
    signingIn = true;
    error = '';
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) {
        error = result.error.message || 'Passkey sign-in failed';
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
    } finally {
      signingIn = false;
    }
  }

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
</script>

<div class="min-h-screen bg-[#fafafa] flex flex-col items-center justify-center px-4 py-8">
  <div class="w-full max-w-sm flex flex-col items-center gap-6">
    <!-- Logo mark -->
    <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-surface-800 to-surface-900 flex items-center justify-center shadow-sm">
      <svg class="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
      </svg>
    </div>

    <!-- Main card -->
    <Card class="w-full p-6">
      {#if step === 'done'}
        <div class="flex flex-col items-center justify-center text-center py-4">
          <svg class="w-12 h-12 text-green-500 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>

          {#if pasteCode}
            <h2 class="text-lg font-semibold text-surface-900 mb-2">Delegation Created</h2>
            <p class="text-surface-500 text-sm mb-4">Copy this code and paste it into the CLI:</p>
            <textarea
              readonly
              class="w-full h-24 p-3 bg-surface-50 border border-surface-200 rounded-xl text-xs font-mono resize-none"
              value={pasteCode}
              onfocus={(e) => (e.target as HTMLTextAreaElement).select()}
            ></textarea>
          {:else}
            <h2 class="text-lg font-semibold text-surface-900 mb-2">Authenticated</h2>
            <p class="text-surface-500 text-sm">You can close this window and return to the CLI.</p>
          {/if}
        </div>

      {:else if !$session.data}
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">TinyCloud CLI Login</h1>
          <p class="text-surface-500 text-sm mt-1">Sign in to authorize the CLI</p>
        </header>

        <div class="flex flex-col items-center justify-center text-center py-4">
          <p class="text-surface-500 text-sm mb-5">Sign in with your passkey to continue</p>

          {#if error}
            <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
              {error}
            </div>
          {/if}

          <Button onclick={signInWithPasskey} disabled={signingIn} class="w-full rounded-xl">
            {signingIn ? 'Signing in...' : 'Sign in with Passkey'}
          </Button>
        </div>

      {:else if loading || preparing}
        <div class="flex flex-col items-center justify-center text-center text-surface-400 py-8">
          <svg class="w-6 h-6 animate-spin text-surface-400 mb-3" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
          </svg>
          <span class="text-sm text-surface-500">{preparing ? 'Preparing delegation...' : 'Loading your keys...'}</span>
        </div>

      {:else if step === 'link-wallet'}
        <!-- Link external wallet -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">Link External Wallet</h1>
          <p class="text-surface-500 text-sm mt-1">Connect a browser wallet to your account</p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-4">
          <p class="text-surface-500 text-sm">
            Select a wallet to link. You'll sign a verification message.
          </p>

          {#if wallets.length > 0}
            <div class="flex flex-col gap-2">
              {#each wallets as wallet}
                <button
                  class="flex items-center gap-3 p-3 bg-white border rounded-xl w-full text-left cursor-pointer transition-all hover:bg-surface-50"
                  class:border-surface-900={selectedWallet?.info.uuid === wallet.info.uuid}
                  class:bg-surface-50={selectedWallet?.info.uuid === wallet.info.uuid}
                  class:border-surface-200={selectedWallet?.info.uuid !== wallet.info.uuid}
                  onclick={() => selectWallet(wallet)}
                >
                  <img src={wallet.info.icon} alt={wallet.info.name} class="w-8 h-8 rounded" />
                  <span class="text-surface-900 font-medium text-sm">{wallet.info.name}</span>
                </button>
              {/each}
            </div>
          {:else}
            <div class="bg-amber-50 border border-amber-200 text-amber-700 px-4 py-3 rounded-xl text-sm">
              No wallet detected. Please install a browser wallet.
            </div>
          {/if}

          <div class="flex gap-3 mt-1">
            <Button variant="secondary" onclick={goBack} disabled={linking} class="flex-1 rounded-xl">
              Back
            </Button>
            <Button onclick={connectAndLink} disabled={linking || (wallets.length > 0 && !selectedWallet) || wallets.length === 0} class="flex-1 rounded-xl">
              {linking ? 'Linking...' : 'Connect Wallet'}
            </Button>
          </div>
        </div>

      {:else if step === 'choose-wallet' && selectedKey}
        <!-- Wallet selection for external key signing -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">Choose Wallet</h1>
          <p class="text-surface-500 text-sm mt-1">Select the wallet that holds <code class="font-mono text-xs">{formatAddress(selectedKey.address)}</code></p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-3">
          {#each wallets as wallet}
            <button
              class="flex items-center gap-3 p-3 bg-white border rounded-xl w-full text-left cursor-pointer transition-all hover:bg-surface-50"
              class:border-surface-900={signingWallet?.info.uuid === wallet.info.uuid}
              class:bg-surface-50={signingWallet?.info.uuid === wallet.info.uuid}
              class:border-surface-200={signingWallet?.info.uuid !== wallet.info.uuid}
              onclick={() => onSigningWalletSelect(wallet)}
            >
              <img src={wallet.info.icon} alt={wallet.info.name} class="w-8 h-8 rounded" />
              <span class="text-surface-900 font-medium text-sm">{wallet.info.name}</span>
              {#if signingWallet?.info.uuid === wallet.info.uuid}
                <svg class="w-5 h-5 text-surface-900 ml-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              {/if}
            </button>
          {/each}

          <div class="flex gap-3 mt-1">
            <Button variant="secondary" onclick={backToConsent} disabled={delegating} class="flex-1 rounded-xl">
              Back
            </Button>
            <Button onclick={confirmSigningWallet} disabled={delegating || !signingWallet} class="flex-1 rounded-xl">
              {#if delegating}
                Signing...
              {:else}
                Continue
              {/if}
            </Button>
          </div>
        </div>

      {:else if step === 'consent' && selectedKey}
        <!-- Consent screen -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">Authorize CLI Access</h1>
          <p class="text-surface-500 text-sm mt-1">Review what the CLI will be able to do</p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-4">
          <!-- Signing key -->
          <div class="p-3 bg-surface-50 border border-surface-200 rounded-xl">
            <div class="text-xs text-surface-400 mb-1">Signing key</div>
            <div class="flex justify-between items-center">
              <span class="font-medium text-sm text-surface-900 flex items-center gap-2">
                {selectedKey.label || `Key ${selectedKey.keyIndex}`}
                {#if selectedKey.keyType === 'EXTERNAL'}
                  <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-100 text-surface-500">(External)</span>
                {/if}
              </span>
              <code class="font-mono text-surface-500 text-xs">{formatAddress(selectedKey.address)}</code>
            </div>
          </div>

          {#if selectedKey.keyType === 'EXTERNAL'}
            <div class="p-3 bg-blue-50 border border-blue-200 rounded-xl text-sm text-blue-700">
              Your browser wallet will prompt you to sign a message to authorize this delegation.
            </div>
          {/if}

          <!-- SIWE message details (parsed from actual message) -->
          {#if siweMessage}
            <SiweMessage message={siweMessage} theme="light" />
          {/if}

          <!-- Actions -->
          <div class="flex gap-3 mt-1">
            <Button variant="secondary" onclick={goBack} disabled={delegating} class="flex-1 rounded-xl">
              Back
            </Button>
            <Button onclick={approveDelegate} disabled={delegating} class="flex-1 rounded-xl">
              {#if delegating}
                Signing...
              {:else}
                Approve
              {/if}
            </Button>
          </div>
        </div>

      {:else}
        <!-- Key selection -->
        <header class="mb-5">
          <h1 class="text-lg font-semibold text-surface-900">TinyCloud CLI Login</h1>
          <p class="text-surface-500 text-sm mt-1">Select a key to authorize the CLI</p>
        </header>

        {#if error}
          <div class="w-full bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            {error}
          </div>
        {/if}

        {#if keys.length === 0}
          <div class="flex flex-col items-center justify-center text-center py-4">
            <p class="text-surface-500 text-sm mb-5">No keys found. Generate your first key to connect.</p>
            <Button onclick={generateAndSelect} class="w-full rounded-xl">
              Generate Key
            </Button>
            <Button variant="secondary" onclick={showLinkWallet} class="w-full rounded-xl mt-3">
              Link External Wallet
            </Button>
          </div>
        {:else}
          <div class="flex flex-col gap-3">
            <p class="text-surface-500 text-sm">Select a key to authorize:</p>
            {#each keys as key}
              <button
                class="flex justify-between items-center p-4 bg-white border border-surface-200 rounded-xl cursor-pointer transition-all hover:border-surface-900 hover:bg-surface-50 group"
                onclick={() => onKeySelect(key)}
              >
                <span class="font-medium flex items-center gap-2">
                  {key.label || `Key ${key.keyIndex}`}
                  {#if key.keyType === 'EXTERNAL'}
                    <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-100 text-surface-500">(External)</span>
                  {/if}
                </span>
                <code class="font-mono text-surface-400 text-sm">{formatAddress(key.address)}</code>
              </button>
            {/each}
            <Button variant="secondary" onclick={generateAndSelect} class="rounded-xl">
              + Generate New Key
            </Button>
            <Button variant="secondary" onclick={showLinkWallet} class="rounded-xl">
              Link External Wallet
            </Button>
          </div>
        {/if}
      {/if}
    </Card>

    {#if $session.data && step !== 'done'}
      <button
        onclick={() => authClient.signOut()}
        class="text-xs text-surface-400 hover:text-surface-600 transition-colors bg-transparent border-none cursor-pointer"
      >
        Sign out
      </button>
    {:else if !$session.data}
      <div class="flex items-center gap-3 text-sm">
        <a href="/auth/register" class="text-surface-500 hover:text-surface-700 transition-colors">Register</a>
        <span class="text-surface-300">|</span>
        <a href="/auth/recover" class="text-surface-500 hover:text-surface-700 transition-colors">Recover account</a>
      </div>
    {/if}

    <!-- Trust badge -->
    <div class="flex items-center gap-1.5 text-surface-400">
      <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
      <span class="text-xs">Protected by TEE hardware security</span>
    </div>
  </div>
</div>
