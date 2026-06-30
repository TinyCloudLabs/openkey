<script lang="ts">
  import { page } from '$app/stores';
  import { authClient, authErrorMessage } from '$lib/auth-client';
  import { api, type EthereumKey } from '$lib/api';
  import { copyText } from '$lib/clipboard';
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

  interface DelegatePermissionAction {
    key: string;
    action: string;
    ability: string;
    required: boolean;
  }

  interface DelegatePermission {
    key: string;
    label: string;
    resourcePath: string;
    actions: DelegatePermissionAction[];
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
  let callbackFailed = $state(false);
  let copied = $state(false);
  let step = $state<'select-key' | 'link-wallet' | 'consent' | 'choose-wallet' | 'done'>('select-key');
  let preparedData = $state<any>(null);
  let siweMessage = $state('');
  let preparing = $state(false);
  let permissionOptions = $state<DelegatePermission[]>([]);
  let selectedActionKeys = $state<string[]>([]);
  let editingPermissions = $state(false);
  let updatingPermissions = $state(false);
  let permissionsEdited = $state(false);
  const delegateReturnTo = $derived($page.url.pathname + $page.url.search + $page.url.hash);
  const registerHref = $derived(`/auth/register?returnTo=${encodeURIComponent(delegateReturnTo)}`);
  let actionRow: HTMLDivElement | null = $state(null);
  let showScrollToApprove = $state(false);

  // Link wallet state
  let wallets = $state<EIP6963ProviderDetail[]>([]);
  let selectedWallet = $state<EIP6963ProviderDetail | null>(null);
  let linking = $state(false);

  // Parse query params
  const did = $page.url.searchParams.get('did') || '';
  const jwkB64 = $page.url.searchParams.get('jwk') || '';
  const callback = $page.url.searchParams.get('callback') || '';
  const host = $page.url.searchParams.get('host') || 'https://node.tinycloud.xyz';
  const permissionsB64 = $page.url.searchParams.get('permissions') || '';
  const reasonParam = $page.url.searchParams.get('reason') || '';
  // Optional caller-supplied delegation lifetime. The CLI encodes this as
  // an ms-format string ("7d", "30m") or a millisecond integer. Validation
  // and clamping are owned by the API to keep the source of truth in one
  // place; we just forward it.
  const expiryParam = $page.url.searchParams.get('expiry') || '';

  // Decode JWK from base64url
  let jwk: object | null = null;
  if (jwkB64) {
    try {
      jwk = JSON.parse(atob(jwkB64.replace(/-/g, '+').replace(/_/g, '/')));
    } catch {
      // Will show error in UI
    }
  }

  // Decode the optional permissions request from base64url JSON. The CLI's
  // `tc auth request` flow encodes a `{ permissions: PermissionEntry[] }`
  // payload here so the user can grant just the missing capabilities — see
  // packages/cli/src/auth/browser-auth.ts in tinycloudlabs/js-sdk.
  interface RequestedPermission {
    service: string;
    space: string;
    path: string;
    actions: string[];
  }
  let requestedPermissions: RequestedPermission[] = [];
  let requestReason = $state(normalizeReason(reasonParam));
  if (permissionsB64) {
    try {
      const payload = JSON.parse(
        atob(permissionsB64.replace(/-/g, '+').replace(/_/g, '/')),
      );
      if (payload && Array.isArray(payload.permissions)) {
        requestedPermissions = payload.permissions as RequestedPermission[];
      }
      const payloadReason = normalizeReason(payload?.reason);
      if (payloadReason) {
        requestReason = payloadReason;
      }
    } catch {
      // Surface as a user-visible error during consent rendering.
      error = 'Could not decode the requested permissions parameter.';
    }
  }

  // Extract the expected owner address from a `tinycloud:pkh:eip155:<chain>:<addr>:<name>`
  // space URI. Returns the address only when every permission resolves to the
  // SAME owner via the pkh form. If any permission's space is missing, malformed,
  // or non-pkh, or addresses disagree, we return null and fall back to the
  // previous unconstrained behavior. This avoids pinning the UI to an address
  // when the request is genuinely unscoped or only partially scoped.
  function extractExpectedAddress(perms: RequestedPermission[]): string | null {
    if (perms.length === 0) return null;
    const addresses = new Set<string>();
    for (const p of perms) {
      if (typeof p.space !== 'string') return null;
      const match = p.space.match(/^tinycloud:pkh:eip155:\d+:(0x[a-fA-F0-9]{40}):/);
      if (!match) return null;
      addresses.add(match[1].toLowerCase());
    }
    return addresses.size === 1 ? [...addresses][0] : null;
  }

  const expectedAddress = extractExpectedAddress(requestedPermissions);
  const expectedAddressShort = $derived(
    expectedAddress
      ? `${expectedAddress.slice(0, 6)}...${expectedAddress.slice(-4)}`
      : '',
  );
  // True once we've completed the auto-select attempt for the expected wallet.
  // Used to avoid showing the "wallet not connected" warning before keys load.
  let preselectAttempted = $state(false);
  // True when the user has explicitly chosen to proceed with a non-matching
  // wallet via the override path on the key picker.
  let overrideMismatch = $state(false);
  const selectedMatchesExpected = $derived(
    !expectedAddress ||
      (selectedKey?.address?.toLowerCase() === expectedAddress),
  );

  function normalizeReason(value: unknown): string {
    if (typeof value !== 'string') return '';
    return value.replace(/\s+/g, ' ').trim().slice(0, 500);
  }

  function shortService(service: string): string {
    return service.startsWith('tinycloud.') ? service.slice('tinycloud.'.length) : service;
  }
  function shortSpace(space: string): string {
    return space.startsWith('tinycloud:') ? space.slice(space.lastIndexOf(':') + 1) : space;
  }
  function shortAction(service: string, action: string): string {
    return action.startsWith(`${service}/`) ? action.slice(service.length + 1) : action;
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

  $effect(() => {
    if (typeof window === 'undefined') return;

    const updateScrollAffordance = () => {
      if (step !== 'consent' || !actionRow) {
        showScrollToApprove = false;
        return;
      }

      const documentElement = document.documentElement;
      const pageCanScroll = documentElement.scrollHeight > window.innerHeight + 8;
      const actionRect = actionRow.getBoundingClientRect();
      showScrollToApprove = pageCanScroll && actionRect.bottom > window.innerHeight - 24;
    };

    const scheduleUpdate = () => requestAnimationFrame(updateScrollAffordance);

    scheduleUpdate();
    window.addEventListener('scroll', scheduleUpdate, { passive: true });
    window.addEventListener('resize', scheduleUpdate);

    return () => {
      window.removeEventListener('scroll', scheduleUpdate);
      window.removeEventListener('resize', scheduleUpdate);
    };
  });

  function scrollToApprove() {
    if (typeof window === 'undefined' || !actionRow) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    actionRow.scrollIntoView({
      behavior: prefersReducedMotion ? 'auto' : 'smooth',
      block: 'end',
    });
  }

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

  // Auto-select the CLI-requested wallet once keys are loaded. Only runs on
  // the initial 'select-key' step so revisiting the picker (Back, link-wallet
  // round-trip) doesn't trap the user in an auto-advance loop.
  $effect(() => {
    if (loading || preselectAttempted) return;
    if (step !== 'select-key') return;
    if (!expectedAddress) {
      preselectAttempted = true;
      return;
    }
    const match = keys.find(
      (k) => k.address.toLowerCase() === expectedAddress,
    );
    preselectAttempted = true;
    if (match) {
      onKeySelect(match);
    }
  });

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
      const data = await prepareDelegation(key);
      applyPreparedDelegation(data);
      editingPermissions = false;
      step = 'consent';
    } catch (e: any) {
      error = e.message || 'Failed to prepare delegation';
      selectedKey = null;
    } finally {
      preparing = false;
    }
  }

  async function prepareDelegation(key: EthereumKey, actionKeys?: string[]) {
    const API_URL = import.meta.env.VITE_API_URL || '';
    const body: Record<string, unknown> = {
      keyId: key.id,
      jwk,
      host,
      prefix: 'default',
    };
    if (actionKeys) {
      body.actionKeys = actionKeys;
    }
    // CLI-driven flow (e.g. tc auth request): forward the requested caps
    // verbatim. The API uses these instead of the default abilities, so the
    // baseline-edit UI surface is bypassed for CLI requests.
    if (requestedPermissions.length > 0) {
      body.permissions = requestedPermissions;
    }
    if (requestReason) {
      body.reason = requestReason;
    }
    if (expiryParam) {
      body.expiry = expiryParam;
    }

    const res = await fetch(`${API_URL}/api/delegate/prepare`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(body.error || `HTTP ${res.status}`);
    }

    return res.json();
  }

  function applyPreparedDelegation(data: any) {
    const permissions = Array.isArray(data.permissions)
      ? (data.permissions as DelegatePermission[])
      : [];

    preparedData = data.prepared;
    siweMessage = data.prepared?.siwe || '';
    permissionOptions = permissions;
    selectedActionKeys = Array.isArray(data.selectedActionKeys)
      ? data.selectedActionKeys.filter((key: unknown): key is string => typeof key === 'string')
      : permissions.flatMap((permission) => permission.actions.map((action) => action.key));
    permissionsEdited = Boolean(data.edited);
  }

  function resetDelegationState() {
    preparedData = null;
    siweMessage = '';
    permissionOptions = [];
    selectedActionKeys = [];
    editingPermissions = false;
    updatingPermissions = false;
    permissionsEdited = false;
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
    resetDelegationState();
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
    if (updatingPermissions) {
      error = 'Permissions are still updating.';
      return;
    }
    if (permissionOptions.length > 0 && selectedActionKeys.length === 0) {
      error = 'At least one permission is required.';
      return;
    }
    // Defense-in-depth: the Approve button is already disabled in this case,
    // but block here too so a stray invocation can't slip through.
    if (!selectedMatchesExpected && !overrideMismatch) {
      error = `This CLI requested wallet ${expectedAddressShort}. Pick that wallet or explicitly override.`;
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

  function isActionSelected(key: string): boolean {
    return selectedActionKeys.includes(key);
  }

  function selectedActions(permission: DelegatePermission): DelegatePermissionAction[] {
    return permission.actions.filter((action) => isActionSelected(action.key));
  }

  async function toggleAction(action: DelegatePermissionAction) {
    if (action.required) return;

    const nextKeys = isActionSelected(action.key)
      ? selectedActionKeys.filter((selectedKey) => selectedKey !== action.key)
      : [...selectedActionKeys, action.key];

    if (nextKeys.length === 0) {
      error = 'At least one permission is required.';
      return;
    }

    await updatePermissions(nextKeys);
  }

  async function updatePermissions(nextKeys: string[]) {
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }

    updatingPermissions = true;
    error = '';

    try {
      const data = await prepareDelegation(selectedKey, nextKeys);
      applyPreparedDelegation(data);
      editingPermissions = true;
    } catch (e: any) {
      error = e.message || 'Failed to update permissions';
    } finally {
      updatingPermissions = false;
    }
  }

  async function resetPermissions() {
    if (!selectedKey || !jwk) {
      error = 'Missing key or JWK parameter.';
      return;
    }

    updatingPermissions = true;
    error = '';

    try {
      const data = await prepareDelegation(selectedKey);
      applyPreparedDelegation(data);
      editingPermissions = false;
    } catch (e: any) {
      error = e.message || 'Failed to reset permissions';
    } finally {
      updatingPermissions = false;
    }
  }

  async function doManagedDelegate() {
    delegating = true;
    error = '';

    try {
      const API_URL = import.meta.env.VITE_API_URL || '';
      const body: Record<string, unknown> = {
        keyId: selectedKey!.id,
        jwk,
        host,
        prefix: 'default',
      };
      if (permissionsEdited) {
        body.actionKeys = selectedActionKeys;
      }
      if (requestedPermissions.length > 0) {
        body.permissions = requestedPermissions;
      }
      if (requestReason) {
        body.reason = requestReason;
      }
      if (expiryParam) {
        body.expiry = expiryParam;
      }

      const res = await fetch(`${API_URL}/api/delegate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(body.error || `HTTP ${res.status}`);
      }

      const data = await res.json();
      if (!data.hostActivated) {
        await activateWithHost(host, data.delegationHeader);
      }
      await finishDelegate(data);
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
          edited: permissionsEdited,
          reason: requestReason || undefined,
        }),
      });

      if (!compRes.ok) {
        const body = await compRes.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(body.error || `HTTP ${compRes.status}`);
      }

      const data = await compRes.json();
      if (!data.hostActivated) {
        await activateWithHost(host, data.delegationHeader);
      }
      await finishDelegate(data);
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
    const payload = permissionsEdited ? { ...data, edited: true } : data;

    if (callback) {
      try {
        const cbRes = await fetch(callback, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });

        if (!cbRes.ok) {
          throw new Error('Failed to send delegation data to CLI');
        }

        done = true;
        step = 'done';
      } catch {
        // Callback unreachable (e.g. CLI on remote machine) — fall back to paste code
        callbackFailed = true;
        pasteCode = btoa(JSON.stringify(payload));
        done = true;
        step = 'done';
      }
    } else {
      pasteCode = btoa(JSON.stringify(payload));
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
        error = authErrorMessage(result.error, 'Passkey sign-in failed');
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
    } finally {
      signingIn = false;
    }
  }

  async function activateWithHost(
    targetHost: string,
    delegationHeader: { Authorization: string }
  ): Promise<void> {
    try {
      const res = await fetch(`${targetHost}/delegate`, {
        method: 'POST',
        headers: delegationHeader,
      });
      if (!res.ok) {
        const errorText = await res.text().catch(() => res.statusText);
        console.warn(`[Delegate] Browser activation warning: ${errorText}`);
      }
    } catch (e) {
      console.warn(`[Delegate] Browser activation failed:`, e);
    }
  }

  async function copyPasteCode() {
    if (!(await copyText(pasteCode))) {
      error = 'Failed to copy code. Select the code and copy it manually.';
      return;
    }

    error = '';
    copied = true;
    setTimeout(() => { copied = false; }, 2000);
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
            {#if callbackFailed}
              <p class="text-surface-500 text-sm mb-4">Could not reach the CLI automatically. Copy this code and paste it into the CLI to complete authentication.</p>
            {:else}
              <p class="text-surface-500 text-sm mb-4">Copy this code and paste it into the CLI:</p>
            {/if}
            <textarea
              readonly
              class="w-full h-24 p-3 bg-surface-50 border border-surface-200 rounded-xl text-xs font-mono resize-none"
              value={pasteCode}
              onfocus={(e) => (e.target as HTMLTextAreaElement).select()}
            ></textarea>
            <button
              class="mt-2 p-1.5 bg-surface-50 border border-surface-200 rounded-lg cursor-pointer hover:opacity-80 transition-opacity"
              onclick={copyPasteCode}
              title="Copy to clipboard"
            >
              {#if copied}
                <svg class="w-4 h-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
              {:else}
                <svg class="w-4 h-4 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9.75a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184" />
                </svg>
              {/if}
            </button>
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

        {#if expectedAddress && !selectedMatchesExpected}
          <div class="w-full bg-amber-50 border border-amber-200 text-amber-800 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            <div class="font-medium mb-1">Wallet mismatch</div>
            <p class="leading-relaxed">
              This CLI requested a delegation from
              <code class="font-mono text-xs">{expectedAddressShort}</code>,
              but you're about to sign with
              <code class="font-mono text-xs">{formatAddress(selectedKey.address)}</code>.
              The CLI will reject the resulting delegation.
            </p>
            <button
              type="button"
              class="mt-2 text-xs text-amber-900 underline bg-transparent border-none cursor-pointer p-0"
              onclick={goBack}
            >
              Choose a different wallet
            </button>
          </div>
        {/if}

        <div class="flex flex-col gap-4">
          <div class="p-3 bg-surface-50 border border-surface-200 rounded-xl">
            <div class="text-xs text-surface-400 mb-1">Reason provided by CLI</div>
            <p class="text-sm text-surface-700 leading-relaxed">
              {requestReason || 'No additional context was provided by the CLI.'}
            </p>
          </div>

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
            <div class="flex flex-col gap-3">
              {#if permissionOptions.length > 0}
                <div>
                  <div class="flex items-center justify-between mb-2">
                    <div class="text-xs text-surface-400">Permissions requested</div>
                    <div class="flex items-center gap-2">
                      <button
                        class="text-xs text-surface-500 hover:text-surface-900 transition-colors bg-transparent border-none cursor-pointer p-0 disabled:opacity-50"
                        onclick={() => editingPermissions = !editingPermissions}
                        disabled={updatingPermissions}
                      >
                        {editingPermissions ? 'Done' : 'Edit'}
                      </button>
                      {#if editingPermissions || permissionsEdited}
                        <button
                          class="text-xs text-surface-500 hover:text-surface-900 transition-colors bg-transparent border-none cursor-pointer p-0 disabled:opacity-50"
                          onclick={resetPermissions}
                          disabled={updatingPermissions || !permissionsEdited}
                        >
                          Reset
                        </button>
                      {/if}
                    </div>
                  </div>

                  {#if editingPermissions}
                    <div class="flex flex-col gap-2">
                      <div class="bg-amber-50 border border-amber-200 text-amber-700 px-3 py-2 rounded-lg text-xs">
                        Editing permissions may result in the application not working as expected.
                      </div>

                      {#each permissionOptions as permission}
                        <div class="p-2.5 bg-surface-50 border border-surface-200 rounded-lg">
                          <div class="min-w-0">
                            <div class="text-sm font-medium text-surface-900">{permission.label}</div>
                            {#if permission.resourcePath}
                              <div class="text-xs text-surface-400 font-mono mt-0.5 break-all">{permission.resourcePath}</div>
                            {/if}
                            <div class="flex flex-wrap gap-2 mt-2">
                              {#each permission.actions as action}
                                <label
                                  class="inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded bg-white border border-surface-200 text-surface-600 cursor-pointer transition-opacity"
                                  class:opacity-60={!isActionSelected(action.key)}
                                  class:cursor-not-allowed={action.required || updatingPermissions}
                                >
                                  <input
                                    type="checkbox"
                                    class="h-3.5 w-3.5 rounded border-surface-300 text-surface-900"
                                    checked={isActionSelected(action.key)}
                                    disabled={updatingPermissions || action.required}
                                    onchange={() => toggleAction(action)}
                                  />
                                  <span>{action.action}</span>
                                  {#if action.required}
                                    <span class="text-surface-400">required</span>
                                  {/if}
                                </label>
                              {/each}
                            </div>
                          </div>
                        </div>
                      {/each}

                      {#if updatingPermissions}
                        <div class="text-xs text-surface-400">Updating permissions...</div>
                      {/if}
                    </div>
                  {:else}
                    <div class="flex flex-col gap-2">
                      {#if permissionsEdited}
                        <div class="bg-amber-50 border border-amber-200 text-amber-700 px-3 py-2 rounded-lg text-xs">
                          Editing permissions may result in the application not working as expected.
                        </div>
                      {/if}

                      {#each permissionOptions as permission}
                        {#if selectedActions(permission).length > 0}
                          <div class="flex items-start gap-2.5 p-2.5 bg-surface-50 border border-surface-200 rounded-lg">
                            <svg class="w-4 h-4 text-surface-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <div class="min-w-0 flex-1">
                              <div class="text-sm font-medium text-surface-900">{permission.label}</div>
                              {#if permission.resourcePath}
                                <div class="text-xs text-surface-400 font-mono mt-0.5 break-all">{permission.resourcePath}</div>
                              {/if}
                              <div class="flex flex-wrap gap-1 mt-1">
                                {#each selectedActions(permission) as action}
                                  <span class="text-xs px-1.5 py-0.5 rounded bg-surface-100 text-surface-500">{action.action}</span>
                                {/each}
                              </div>
                            </div>
                          </div>
                        {/if}
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}

              <SiweMessage message={siweMessage} theme="light" hidePermissions={permissionOptions.length > 0} />
            </div>
          {/if}

          <!-- Actions -->
          <div class="flex gap-3 mt-1" bind:this={actionRow}>
            <Button variant="secondary" onclick={goBack} disabled={delegating} class="flex-1 rounded-xl">
              Back
            </Button>
            <Button onclick={approveDelegate} disabled={delegating || updatingPermissions || selectedActionKeys.length === 0 || (!selectedMatchesExpected && !overrideMismatch)} class="flex-1 rounded-xl">
              {#if delegating}
                Signing...
              {:else if updatingPermissions}
                Updating...
              {:else if !selectedMatchesExpected && !overrideMismatch}
                Wallet mismatch
              {:else}
                Approve
              {/if}
            </Button>
          </div>
        </div>

        {#if showScrollToApprove}
          <button
            type="button"
            onclick={scrollToApprove}
            class="fixed bottom-5 left-1/2 z-40 inline-flex -translate-x-1/2 items-center gap-2 rounded-full bg-surface-900 px-4 py-2.5 text-sm font-medium text-white shadow-lg shadow-surface-900/15 transition-all hover:bg-surface-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-surface-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white"
          >
            <span>Scroll to approve</span>
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 5v14m0 0l-5-5m5 5l5-5" />
            </svg>
          </button>
        {/if}

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

        {#if expectedAddress && preselectAttempted && !keys.some((k) => k.address.toLowerCase() === expectedAddress)}
          <div class="w-full bg-amber-50 border border-amber-200 text-amber-800 px-4 py-3 rounded-xl mb-4 text-sm" role="alert">
            <div class="font-medium mb-1">Wallet not connected</div>
            <p class="leading-relaxed">
              This request is for wallet
              <code class="font-mono text-xs">{expectedAddressShort}</code>.
              That wallet isn't currently connected. Link it below, or switch
              to a profile that uses a wallet you have here.
            </p>
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
              {@const isExpected = !!expectedAddress && key.address.toLowerCase() === expectedAddress}
              {@const isMismatch = !!expectedAddress && !isExpected}
              <button
                class="flex justify-between items-center p-4 bg-white border rounded-xl cursor-pointer transition-all group"
                class:border-surface-900={isExpected}
                class:bg-surface-50={isExpected}
                class:border-surface-200={!isExpected}
                class:hover:border-surface-900={!isMismatch}
                class:hover:bg-surface-50={!isMismatch}
                class:opacity-60={isMismatch && !overrideMismatch}
                disabled={isMismatch && !overrideMismatch}
                onclick={() => onKeySelect(key)}
              >
                <span class="font-medium flex items-center gap-2">
                  {key.label || `Key ${key.keyIndex}`}
                  {#if key.keyType === 'EXTERNAL'}
                    <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-100 text-surface-500">(External)</span>
                  {/if}
                  {#if isExpected}
                    <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-emerald-100 text-emerald-700">Requested</span>
                  {/if}
                </span>
                <code class="font-mono text-surface-400 text-sm">{formatAddress(key.address)}</code>
              </button>
            {/each}
            {#if expectedAddress && !overrideMismatch && !keys.some((k) => k.address.toLowerCase() === expectedAddress)}
              <button
                type="button"
                class="text-xs text-surface-500 hover:text-surface-900 transition-colors bg-transparent border-none cursor-pointer underline self-start"
                onclick={() => (overrideMismatch = true)}
              >
                Continue with a different wallet anyway
              </button>
            {/if}
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
        <a href={registerHref} class="text-surface-500 hover:text-surface-700 transition-colors">Register</a>
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
