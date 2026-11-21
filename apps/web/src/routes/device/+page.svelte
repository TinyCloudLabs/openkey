<script lang="ts">
  import { page } from '$app/stores';
  import { API_BASE, authClient } from '$lib/auth-client';
  import Button from '$lib/components/ui/button.svelte';
  import CodeTiles from '$lib/components/approval/code-tiles.svelte';
  import Icon from '$lib/components/approval/icon.svelte';
  import Slip from '$lib/components/approval/slip.svelte';
  import { focusHeading } from '$lib/components/approval/focus-heading';
  import CloseTabButton from '$lib/components/ui/close-tab-button.svelte';
  import {
    cleanConsentText,
    devicePermissionSummary,
    deviceRequestDefaultSeconds,
    deviceRequestReason,
    deviceRequestTtlSeconds,
    encodeBase64UrlJson,
    formatDeviceUserCode,
    lookupDeviceRequest,
    normalizeDeviceUserCode,
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
    type SummaryStatement,
  } from '@openkey/capability-review';
  import { DEVICE } from '@openkey/sdk/approval-copy';

  const session = authClient.useSession();
  let userCode = $state($page.url.searchParams.get('user_code') ?? '');
  // TC-660: a complete code from the link is shown read-only, leaving the confirm question as the only choice.
  // The editable code returns if that code fails; a typed code that is found is shown read-only too.
  // svelte-ignore state_referenced_locally
  let codeKnown = $state(normalizeDeviceUserCode(userCode).length === 8);
  let request = $state<DeviceRequestRecord | null>(null);
  let loading = $state(false);
  let error = $state('');
  let expired = $state(false);
  /** "No, it's different": nothing is sent, the request runs out by itself. */
  let saidNo = $state(false);
  /** The CLI's requested lifetime, fixed when the request is looked up. */
  let maxLifetimeSeconds = $state(0);
  let lifetimeSeconds = $state(0);
  const requestReason = $derived(request ? deviceRequestReason(request) : '');
  const displayReason = $derived(request?.reason ? cleanConsentText(request.reason) : '');
  const summaryRows = $derived.by(() => {
    if (!request) return [];
    const explicitRows: SummaryStatement[] = [];
    const grants: CapabilityGrant[] = request.permissions.flatMap((permission) => {
      const summary = devicePermissionSummary(permission, Math.min(lifetimeSeconds, maxLifetimeSeconds));
      if (summary !== null) {
        explicitRows.push({ key: summary, primaryText: summary, severity: 'sensitive', unmapped: false, codeSpans: false });
        return [];
      }
      const classified = classifyRecapEntry(permission);
      return [{
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
      }];
    });
    return [...explicitRows, ...buildSummaryStatements(grants)];
  });

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
      deviceUserCode: formatDeviceUserCode(request.userCode),
    });
    return `/delegate?${params.toString()}`;
  });

  async function findRequest() {
    loading = true;
    error = '';
    expired = false;
    request = null;
    try {
      const found = await lookupDeviceRequest(API_BASE, formatDeviceUserCode(userCode));
      if (!found) {
        expired = true;
        codeKnown = false;
        return;
      }
      maxLifetimeSeconds = deviceRequestTtlSeconds(found);
      lifetimeSeconds = deviceRequestDefaultSeconds(found);
      request = found;
      userCode = formatDeviceUserCode(found.userCode);
      codeKnown = true;
    } catch {
      error = DEVICE.loadFailed;
      codeKnown = false;
    } finally {
      loading = false;
    }
  }

  function typed(code: string) {
    userCode = code;
    error = '';
    expired = false;
    request = null;
  }

  // Look up a code from the link once on load; a typed code only on submit,
  // so partial codes never hit the API or show an error (TC-660).
  // svelte-ignore state_referenced_locally
  if (codeKnown) void findRequest();
</script>

<svelte:head>
  <title>{DEVICE.title}</title>
</svelte:head>

{#snippet problem(text: string)}
  <div role="alert" class="mt-2.5 grid w-full grid-cols-[16px_1fr] gap-[9px] rounded-[11px] border border-red-line bg-red-wash px-3 py-[9px] text-left text-[13.5px] leading-[1.45] text-[#7a1a12]">
    <Icon name="alert" class="mt-0.5 h-4 w-4" />
    <span>{text}</span>
  </div>
{/snippet}

<Slip at={$session.data ? 2 : 1} last="terminal" center email={$session.data?.user.email ?? null} onSignOut={() => { void authClient.signOut(); }}>
  {#if saidNo}
    <div class="mt-1 mb-[18px] grid h-[52px] w-[52px] place-items-center rounded-full border border-red-line bg-red-wash text-[#b42318]" aria-hidden="true">
      <Icon name="x" class="h-[26px] w-[26px] [stroke-width:2.2]" />
    </div>
    <h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{DEVICE.noHeading}</h1>
    <p class="m-0 mb-3.5 text-pretty">{DEVICE.noLine}</p>
    <div class="grid w-full gap-2.5">
      <CloseTabButton />
      <Button variant="ghost" class="w-full" onclick={() => { saidNo = false; }}>{DEVICE.noMisread}</Button>
    </div>
  {:else}
    <p class="m-0 mb-2.5 text-[11.5px] font-semibold tracking-[0.09em] text-surface-500 uppercase">{DEVICE.eyebrow}</p>
    {#if codeKnown}
      <h1 use:focusHeading class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{DEVICE.headingCode}</h1>
      <CodeTiles code={userCode} />
    {:else}
      <h1 id="device-code-heading" class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{DEVICE.headingNoCode}</h1>
      <p id="device-code-line" class="m-0 mb-3.5 text-pretty">{DEVICE.lineNoCode}</p>
      <form class="flex w-full flex-col" onsubmit={(event) => { event.preventDefault(); void findRequest(); }}>
        <CodeTiles code={userCode} editable labelledby="device-code-heading" describedby="device-code-line" oninput={typed} />
        {#if expired}
          {@render problem(DEVICE.notFound)}
        {:else if error}
          {@render problem(error)}
        {/if}
        <div class="mt-5 grid">
          {#if error && !loading}
            <Button type="button" class="w-full" onclick={() => void findRequest()}>{DEVICE.tryAgain}</Button>
          {:else}
            <Button type="submit" class="w-full" disabled={loading || normalizeDeviceUserCode(userCode).length !== 8}>{DEVICE.find}</Button>
          {/if}
        </div>
      </form>
    {/if}

    {#if loading}
      <p class="m-0 mt-4 text-[13px] text-surface-500" role="status">{DEVICE.lookingUp}</p>
    {/if}

    <svelte:boundary>
      {#if codeKnown && request}
        <section class="mt-4 w-full text-left">
          <p class="m-0 mb-[9px] text-[11px] font-semibold tracking-[0.09em] text-surface-500 uppercase">{DEVICE.asksLabel}</p>
          {#if displayReason}
            <blockquote class="m-0 mb-1 rounded-xl bg-surface-50 px-3.5 py-3 text-[14.5px] leading-[1.45] break-words text-surface-950 italic">“{displayReason}”</blockquote>
            <p class="m-0 mt-1 mb-2 text-[13px] leading-normal text-surface-500">{DEVICE.reasonNote}</p>
          {/if}
          <ul class="m-0 mb-1 list-none p-0 text-[14.5px] text-surface-950" aria-label={DEVICE.asksList}>
            {#each summaryRows as row (row.key)}
              <li class="border-t border-surface-200 py-[9px] break-words">
                {#if row.codeSpans}
                  {#each splitStatementCode(row.primaryText) as part}
                    {#if part.code}<code class="font-mono text-xs break-all">{part.text}</code>{:else}{part.text}{/if}
                  {/each}
                {:else}
                  {row.primaryText}
                {/if}
                {#if row.severity === 'sensitive'}
                  <span class="ml-1 rounded bg-amber-wash px-1.5 py-0.5 text-xs font-medium text-amber-900">{DEVICE.sensitive}</span>
                {/if}
              </li>
            {/each}
          </ul>
          <div class="mt-[18px] grid gap-2.5">
            <Button href={delegateHref} class="w-full">{$session.data ? DEVICE.yesSignedIn : DEVICE.yesSignedOut}</Button>
            <Button variant="secondary" class="w-full" onclick={() => { saidNo = true; }}>{DEVICE.no}</Button>
          </div>
          <details class="mt-3.5 text-[13px] text-surface-500">
            <summary class="cursor-pointer">{DEVICE.advanced}</summary>
            <div class="mt-4 flex flex-col gap-4 text-surface-700">
              <ul class="divide-y divide-surface-200 rounded-lg border border-surface-200">
                {#each request.permissions as permission}
                  <li class="px-3 py-2 font-mono text-xs break-all">
                    <p>{permission.service} · {permission.space} · {permission.path}</p>
                    <p>{permission.actions.join(', ')}</p>
                  </li>
                {/each}
              </ul>
              <dl class="grid gap-3">
                <div><dt class="text-surface-500">{DEVICE.shareOrigin}</dt><dd class="font-mono text-xs break-all">{request.shareOrigin}</dd></div>
                <div><dt class="text-surface-500">{DEVICE.nodeOrigin}</dt><dd class="font-mono text-xs break-all">{request.nodeOrigin}</dd></div>
              </dl>
            </div>
          </details>
        </section>
      {/if}

      {#snippet failed(_cause, reset)}
        {@render problem(DEVICE.loadFailed)}
        <div class="mt-5 grid w-full">
          <Button class="w-full" onclick={() => { request = null; reset(); void findRequest(); }}>{DEVICE.tryAgain}</Button>
        </div>
      {/snippet}
    </svelte:boundary>
  {/if}
</Slip>
