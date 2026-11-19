<script lang="ts">
  import { page } from '$app/stores';
  import { API_BASE, authClient } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import {
    cleanConsentText,
    deviceRequestDefaultSeconds,
    deviceRequestReason,
    deviceRequestTtlSeconds,
    encodeBase64UrlJson,
    lookupDeviceRequest,
    type DeviceRequestRecord,
  } from '$lib/device-authorization';
  import {
    actionId,
    buildSummaryStatements,
    classifyRecapEntry,
    classifySeverityFromActions,
    permissionId,
    splitStatementCode,
    type CapabilityGrant,
  } from '@openkey/capability-review';

  const session = authClient.useSession();
  let userCode = $state($page.url.searchParams.get('user_code') ?? '');
  // TC-660: a complete code from the link is shown read-only, leaving sign-in
  // as the only action. The editable form returns if that code fails.
  // svelte-ignore state_referenced_locally
  let codeFromLink = $state(normalizedCode(userCode).length === 8);
  let request = $state<DeviceRequestRecord | null>(null);
  let loading = $state(false);
  let error = $state('');
  let expired = $state(false);
  /** The CLI's requested lifetime, fixed when the request is looked up. */
  let maxLifetimeSeconds = $state(0);
  let lifetimeSeconds = $state(0);
  const requestReason = $derived(request ? deviceRequestReason(request) : '');
  const displayReason = $derived(request?.reason ? cleanConsentText(request.reason) : '');
  const summaryRows = $derived.by(() => {
    if (!request) return [];
    const grants: CapabilityGrant[] = request.permissions.map((permission) => {
      const classified = classifyRecapEntry(permission);
      return {
        ...permission,
        ...classified,
        id: permissionId(permission.service, permission.space, permission.path),
        severity: classifySeverityFromActions(classified.family, permission.actions, permission),
        // This preview has no selected signing key. Never invent resource ownership.
        owner: null,
        ownedBySelf: null,
        metadataLabel: null,
        resourceService: null,
        actions: permission.actions.map((ability) => ({
          id: actionId(permission.service, permission.space, permission.path, ability),
          ability,
          verb: ability.slice(ability.indexOf('/') + 1),
          required: false,
          selected: true,
          editable: false,
          caveats: [],
        })),
      };
    });
    return buildSummaryStatements(grants);
  });

  function normalizedCode(value: string): string {
    return value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  }

  function displayedCode(value: string): string {
    const normalized = normalizedCode(value);
    return normalized.length > 4 ? `${normalized.slice(0, 4)}-${normalized.slice(4)}` : normalized;
  }

  const delegateHref = $derived.by(() => {
    if (!request) return '';
    // The delegation may last at most the CLI's requested lifetime.
    const selectedSeconds = Math.min(lifetimeSeconds, maxLifetimeSeconds);
    const params = new URLSearchParams({
      did: request.sessionDid,
      jwk: encodeBase64UrlJson(request.publicJwk),
      relayJwk: encodeBase64UrlJson(request.relayPublicJwk),
      host: request.nodeOrigin,
      permissions: encodeBase64UrlJson({
        permissions: request.permissions,
        ...(requestReason ? { reason: requestReason } : {}),
      }),
      ...(requestReason ? { reason: requestReason } : {}),
      expiry: `${selectedSeconds}s`,
      protocolVersion: '1',
      deviceTransactionId: request.id,
      deviceShareOrigin: request.shareOrigin,
      // /delegate re-reads the request by code and refuses a mismatched link.
      deviceUserCode: displayedCode(request.userCode),
    });
    return `/delegate?${params.toString()}`;
  });

  async function findRequest() {
    loading = true;
    error = '';
    expired = false;
    request = null;
    try {
      const found = await lookupDeviceRequest(API_BASE, displayedCode(userCode));
      if (!found) {
        expired = true;
        codeFromLink = false;
        return;
      }
      maxLifetimeSeconds = deviceRequestTtlSeconds(found);
      lifetimeSeconds = deviceRequestDefaultSeconds(found);
      request = found;
      userCode = displayedCode(found.userCode);
    } catch {
      error = "Couldn't load this request.";
      codeFromLink = false;
    } finally {
      loading = false;
    }
  }

  // Look up a code from the link once on load; a typed code only on submit,
  // so partial codes never hit the API or show an error (TC-660).
  // svelte-ignore state_referenced_locally
  if (codeFromLink) void findRequest();
</script>

<svelte:head>
  <title>Review a sign-in request — OpenKey</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-4 py-6 sm:py-10">
  <Card class="w-full p-6 sm:p-8">
    <h1 class="mb-3 text-2xl font-semibold text-surface-900">Review a sign-in request</h1>
    <svelte:boundary>
      {#if codeFromLink}
        <p class="mb-4 text-surface-600">Check that this code matches your terminal.</p>
        <p class="text-sm text-surface-500" aria-label="Device code">
          Code
          <code class="rounded-md border border-surface-200 bg-surface-50 px-2 py-1 font-mono text-base tracking-widest text-surface-900">{displayedCode(userCode)}</code>
        </p>
      {:else}
        <p class="mb-6 text-surface-600">Enter the code shown in your terminal.</p>
        <form class="flex flex-col gap-3 sm:flex-row" onsubmit={(event) => { event.preventDefault(); void findRequest(); }}>
          <input
            class="min-w-0 flex-1 rounded-lg border border-surface-300 bg-white px-4 py-3 font-mono text-lg uppercase tracking-widest text-surface-900"
            aria-label="Device code"
            autocomplete="one-time-code"
            placeholder="ABCD-EFGH"
            value={displayedCode(userCode)}
            oninput={(event) => { userCode = displayedCode(event.currentTarget.value); error = ''; expired = false; request = null; }}
          />
          <Button type="submit" disabled={loading || normalizedCode(userCode).length !== 8}>Continue</Button>
        </form>
      {/if}

      {#if loading}
        <p class="mt-4 text-sm text-surface-600" role="status">Loading the request…</p>
      {:else if expired}
        <p class="mt-4 rounded-lg bg-red-50 p-3 text-sm text-red-700" role="alert">This request has expired or was already answered. Start again on your device.</p>
      {:else if error}
        <div class="mt-4 flex flex-col gap-3">
          <p class="rounded-lg bg-red-50 p-3 text-sm text-red-700" role="alert">{error}</p>
          <Button onclick={() => void findRequest()}>Try again</Button>
        </div>
      {/if}

      {#if request}
        <section class="mt-6 flex flex-col gap-5">
          <p class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm font-medium text-amber-900" role="note">Approve only if you started this on your own device.</p>
          {#if displayReason}
            <div class="text-sm">
              <blockquote class="break-words text-surface-900">“{displayReason}”</blockquote>
              <p class="mt-1 text-surface-500">This reason comes from the caller and isn't verified.</p>
            </div>
          {/if}
          <ul class="space-y-3" aria-label="Requested access">
            {#each summaryRows as row (row.key)}
              <li class="break-words text-sm text-surface-900">
                {#if row.codeSpans}
                  {#each splitStatementCode(row.primaryText) as part}
                    {#if part.code}<code class="break-all font-mono text-xs">{part.text}</code>{:else}{part.text}{/if}
                  {/each}
                {:else}
                  {row.primaryText}
                {/if}
                {#if row.severity === 'sensitive'}
                  <span class="ml-1 rounded bg-amber-50 px-1.5 py-0.5 text-xs font-medium text-amber-900">Sensitive</span>
                {/if}
              </li>
            {/each}
          </ul>
          <Button href={delegateHref} class="w-full">{$session.data ? 'Continue to review' : 'Sign in to review'}</Button>
          <details class="text-sm">
            <summary class="cursor-pointer text-surface-500">Advanced details</summary>
            <div class="mt-4 flex flex-col gap-4">
              <ul class="divide-y divide-surface-200 rounded-lg border border-surface-200">
                {#each request.permissions as permission}
                  <li class="break-all px-3 py-2 font-mono text-xs">
                    <p>{permission.service} · {permission.space} · {permission.path}</p>
                    <p>{permission.actions.join(', ')}</p>
                  </li>
                {/each}
              </ul>
              <dl class="grid gap-3">
                <div><dt class="text-surface-500">Share origin</dt><dd class="break-all font-mono text-xs">{request.shareOrigin}</dd></div>
                <div><dt class="text-surface-500">Node origin</dt><dd class="break-all font-mono text-xs">{request.nodeOrigin}</dd></div>
              </dl>
            </div>
          </details>
        </section>
      {/if}

      {#snippet failed(_cause, reset)}
        <div class="mt-4 flex flex-col gap-3">
          <p class="rounded-lg bg-red-50 p-3 text-sm text-red-700" role="alert">Couldn't load this request.</p>
          <Button onclick={() => { request = null; reset(); void findRequest(); }}>Try again</Button>
        </div>
      {/snippet}
    </svelte:boundary>
  </Card>
</main>
