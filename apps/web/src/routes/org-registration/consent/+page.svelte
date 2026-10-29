<script lang="ts">
  import { onMount } from 'svelte';
  import { startAuthentication } from '@simplewebauthn/browser';
  import type { AuthenticationResponseJSON, PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
  import { authClient } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  const storageKey = 'openkey.org-registration.intent.v1';
  const path = '/org-registration/consent';
  const session = authClient.useSession();
  interface IntentFields { intentJws: string; registrationId: string; orgId: string; nonce: string; handle: string; orgName: string }
  interface Challenge { challengeNonce: string; challenge: string; expiresAt: string; allowCredentials: PublicKeyCredentialRequestOptionsJSON['allowCredentials'] }
  interface Registration { registrationId: string; orgId: string; handle: string; displayName: string; controllerDid: string; issuerDid: string; tier: string }
  let fields = $state<IntentFields | null>(null);
  let pending = $state<{ fields: IntentFields; challenge: Challenge } | null>(null);
  let registration = $state<Registration | null>(null);
  let loaded = $state(false);
  let started = $state(false);
  let busy = $state(false);
  let retryable = $state(false);
  let error = $state('');
  let expiresAt = 0;

  function clearIntent() {
    try { sessionStorage.removeItem(storageKey); } catch { /* Never fall back to a URL or another storage scope. */ }
    fields = null;
    pending = null;
    retryable = false;
  }

  onMount(() => {
    // An SPA return from login must acquire this document's response headers too.
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
    if (navigation && new URL(navigation.name).pathname !== path) { location.replace(path); return; }
    let timer: number | undefined;
    try {
      if (window.top !== window.self) throw new Error('Open this registration in its own browser tab.');
      const stored = sessionStorage.getItem(storageKey);
      if (!stored || document.documentElement.dataset.orgRegistration !== 'ready') throw new Error('Open a new registration from credentials.org.');
      const input = JSON.parse(stored);
      if (typeof input.intentJws !== 'string' || !Number.isSafeInteger(input.expiresAt) || input.expiresAt <= Date.now()) throw new Error('Registration expired. Start again at credentials.org.');
      const bytes = Uint8Array.from(atob(input.intentJws.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
      const tuple = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (['registrationId', 'orgId', 'nonce', 'handle', 'displayName'].some(field => typeof tuple[field] !== 'string')) throw new Error('Open a new registration from credentials.org.');
      // These fields are not displayed until OpenKey verifies their exact signed intent.
      fields = { intentJws: input.intentJws, registrationId: tuple.registrationId, orgId: tuple.orgId, nonce: tuple.nonce, handle: tuple.handle, orgName: tuple.displayName };
      expiresAt = input.expiresAt;
      timer = window.setTimeout(() => {
        clearIntent();
        if (!registration && !busy) error = 'Registration expired. Start again at credentials.org.';
      }, expiresAt - Date.now());
    } catch (cause) {
      clearIntent();
      error = cause instanceof Error ? cause.message : 'Registration cannot be recovered in this tab. Start again at credentials.org.';
    } finally { loaded = true; }
    return () => { if (timer !== undefined) window.clearTimeout(timer); };
  });

  async function submit(input: IntentFields, consent?: { challengeNonce: string; assertion: AuthenticationResponseJSON }) {
    const response = await fetch('https://api.openkey.so/api/org-keys', {
      method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...input, ...consent }),
    });
    const result = await response.json();
    if (response.status === 401) {
      location.replace('/auth/login?redirect=%2Forg-registration%2Fconsent');
      return;
    }
    if (!response.ok) {
      if ([400, 403, 404, 409, 410].includes(response.status)) clearIntent();
      throw new Error(typeof result.error === 'string' ? result.error : 'Registration could not complete. Retry in OpenKey.');
    }
    if (result.registration) {
      registration = result.registration;
      clearIntent();
    } else if (result.registrationChallenge) {
      pending = { fields: input, challenge: result.registrationChallenge };
    } else throw new Error('OpenKey did not confirm this registration. Retry in OpenKey.');
  }

  async function verify() {
    const input = fields;
    if (!input || busy) return;
    busy = true;
    error = '';
    retryable = false;
    try { await submit(input); }
    catch (cause) {
      error = cause instanceof Error ? cause.message : 'Registration could not complete. Retry in OpenKey.';
      retryable = fields !== null && expiresAt > Date.now();
    } finally { busy = false; }
  }

  $effect(() => {
    if (!loaded || started || !fields || $session.isPending) return;
    started = true;
    if (!$session.data) { location.replace('/auth/login?redirect=%2Forg-registration%2Fconsent'); return; }
    void verify();
  });

  async function approve() {
    const bound = pending;
    if (!bound || busy) return;
    if (expiresAt <= Date.now() || Date.parse(bound.challenge.expiresAt) <= Date.now()) {
      clearIntent();
      error = 'Registration consent expired. Start again at credentials.org.';
      return;
    }
    busy = true;
    error = '';
    try {
      const assertion = await startAuthentication({ optionsJSON: {
        challenge: bound.challenge.challenge, rpId: 'openkey.so', userVerification: 'required',
        allowCredentials: bound.challenge.allowCredentials,
      } });
      await submit(bound.fields, { challengeNonce: bound.challenge.challengeNonce, assertion });
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Passkey approval was not completed. You can retry.';
      retryable = fields !== null && expiresAt > Date.now();
    } finally { busy = false; }
  }

  function cancel() {
    clearIntent();
    error = 'Registration canceled. Any OpenKey key already created for this intent is retained.';
  }
</script>

<svelte:head>
  <title>Register organization · OpenKey</title>
  <meta name="referrer" content="no-referrer" />
</svelte:head>

<div class="mx-auto max-w-lg py-8 sm:py-12">
  <Card>
    {#if registration}
      <h1 class="text-2xl font-semibold text-surface-900">Organization registered</h1>
      <p class="mt-3 text-surface-600">OpenCredentials confirmed your organization.</p>
      <dl class="mt-6 space-y-4 text-sm">
        {#each [['Name', registration.displayName], ['Handle', registration.handle], ['Org ID', registration.orgId], ['Controller', registration.controllerDid], ['Issuer', registration.issuerDid], ['Tier', registration.tier], ['Registration', registration.registrationId]] as [label, value]}
          <div><dt class="font-medium text-surface-600">{label}</dt><dd class="mt-1 break-words whitespace-pre-wrap text-surface-900">{value}</dd></div>
        {/each}
      </dl>
      <Button href="https://credentials.org" class="mt-8 w-full">Return to Credentials</Button>
    {:else}
      <h1 class="text-2xl font-semibold text-surface-900">Register organization</h1>
      {#if pending}
        <p class="mt-4 break-words whitespace-pre-wrap text-surface-900">Create an OWNER key for <strong>{pending.fields.orgName}</strong> (@{pending.fields.handle}).</p>
        <p class="mt-3 text-sm text-surface-600">Your passkey approves this exact registration. OpenKey sends its proof directly to OpenCredentials; no token needs to be copied.</p>
        <p class="mt-3 text-sm text-surface-600">This approval does not enable organization message signing.</p>
      {:else if !error}
        <p class="mt-4 text-surface-600" role="status">{busy ? 'Verifying the registration…' : 'Loading your OpenKey session…'}</p>
      {/if}
      {#if error}<p class="mt-5 break-words text-sm text-red-700" role="alert">{error}</p>{/if}
      {#if pending && !retryable}
        <Button onclick={approve} disabled={busy} class="mt-6 w-full">{busy ? 'Completing registration…' : 'Approve with passkey'}</Button>
      {:else if retryable}
        <Button onclick={verify} disabled={busy} class="mt-6 w-full">{busy ? 'Retrying completion…' : 'Retry registration'}</Button>
      {/if}
      {#if fields}<Button variant="secondary" onclick={cancel} disabled={busy} class="mt-3 w-full">Cancel</Button>
      {:else if error}<Button href="https://credentials.org" class="mt-6 w-full">Return to Credentials</Button>{/if}
    {/if}
  </Card>
</div>
