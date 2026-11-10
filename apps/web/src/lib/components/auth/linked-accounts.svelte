<script lang="ts">
  import { onMount } from 'svelte';
  import { authClient, API_BASE, authErrorMessage } from '$lib/auth-client';
  import { loadConfiguredSocialProviders, signInWithSocialPopup, type SocialProviderId } from '$lib/social-auth';
  import { isAppleRelayEmail, socialProviderName } from '$lib/social-continuation';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';

  // Adding or removing Google or Apple needs a fresh email code on this session
  // (TC-1188 §2): the API refuses `/link-social` and `/account/social/unlink`
  // without one, and refuses an unlink that would leave no usable sign-in (R8).
  type LinkedAccount = { id: string; providerId: SocialProviderId; accountId: string };
  type Owner = { email: string; emailVerified: boolean; passkeys: number; emailUndeliverable: boolean };
  const PROVIDERS: readonly SocialProviderId[] = ['google', 'apple'];

  interface Props {
    /** Settings' own passkey count once loaded; it overrides the count read at mount. */
    passkeyCount?: number | null;
  }
  let { passkeyCount = null }: Props = $props();

  let accounts = $state<LinkedAccount[]>([]);
  let available = $state<SocialProviderId[]>([]);
  let owner = $state<Owner | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state('');
  let notice = $state('');
  let pending = $state<{ action: 'link' | 'unlink'; provider: SocialProviderId } | null>(null);
  let step = $state<'code' | 'verified' | null>(null);
  let code = $state('');

  // Rows: every linked provider, and every configured one that is not linked.
  const rows = $derived(PROVIDERS.filter((provider) =>
    accounts.some((account) => account.providerId === provider) || available.includes(provider)));
  // The same rule the API applies: a passkey, or a verified email Apple still forwards to.
  const passkeys = $derived(passkeyCount ?? owner?.passkeys ?? 0);
  const onlySocial = $derived(owner !== null && passkeys === 0 && (!owner.emailVerified || owner.emailUndeliverable));
  const relayEmail = $derived(owner !== null && isAppleRelayEmail(owner.email));

  async function refreshAccounts() {
    const result = await authClient.listAccounts();
    if (result.error) throw new Error(authErrorMessage(result.error, 'Could not load linked accounts.'));
    accounts = (result.data ?? []).filter((account) =>
      account.providerId === 'google' || account.providerId === 'apple') as LinkedAccount[];
  }

  async function refreshOwner() {
    const response = await fetch(`${API_BASE}/api/account`, { credentials: 'include', headers: { Accept: 'application/json' } });
    if (!response.ok) return;
    const user = (await response.json().catch(() => null))?.user;
    if (!user || typeof user.email !== 'string') return;
    owner = {
      email: user.email,
      emailVerified: user.emailVerified === true,
      passkeys: typeof user._count?.passkeys === 'number' ? user._count.passkeys : 0,
      emailUndeliverable: user.emailUndeliverable === true,
    };
  }

  onMount(() => {
    // Linked rows and the owner's email state reveal together. /providers only
    // adds "Not linked" rows, so a slow answer never hides an Unlink.
    void loadConfiguredSocialProviders().then((providers) => { available = providers; }).catch(() => {});
    void Promise.all([refreshAccounts(), refreshOwner().catch(() => {})]).catch((cause) => {
      error = cause instanceof Error ? cause.message : 'Could not load linked accounts.';
    }).finally(() => { loading = false; });
  });

  function reset() {
    pending = null;
    step = null;
    code = '';
  }

  function unlinkError(status: number, body: { error?: unknown } | null, provider: SocialProviderId): string {
    const name = socialProviderName(provider);
    switch (body?.error) {
      case 'LAST_SIGN_IN_METHOD':
        return `${name} is your only way to sign in. Add a passkey before you remove it.`;
      case 'EMAIL_STEP_UP_REQUIRED':
        return 'Your email code expired. Verify a new code to continue.';
      case 'ACCOUNT_NOT_FOUND':
        return `${name} is no longer linked to this account.`;
      case 'ACCOUNT_CHANGED':
        return 'Your sign-in methods changed while this was in progress. Reload the page and try again.';
      case 'APPLE_TOKEN_UNAVAILABLE':
      case 'APPLE_TOKEN_REVOKE_FAILED':
        return "Apple didn't confirm the removal, so Apple is still linked. Try again in a moment.";
      default:
        return status >= 500 ? `Could not unlink ${name}. Try again in a moment.` : `Could not unlink ${name}.`;
    }
  }

  async function requestCode(action: 'link' | 'unlink', provider: SocialProviderId) {
    busy = true;
    error = '';
    notice = '';
    try {
      const response = await fetch(`${API_BASE}/api/account/step-up/email-otp/send`, {
        method: 'POST', credentials: 'include',
      });
      if (!response.ok) {
        throw new Error(response.status === 503
          ? 'OpenKey could not send email right now. Try again later.'
          : 'Could not send an account verification code. Try again.');
      }
      pending = { action, provider };
      step = 'code';
      code = '';
      notice = relayEmail
        ? `Check your Apple relay inbox (${owner!.email}) for a code to change linked sign-in methods.`
        : 'Check your OpenKey email for a code to change linked sign-in methods.';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Could not send a code.';
    } finally {
      busy = false;
    }
  }

  async function verifyCode() {
    if (!pending || code.length !== 6) return;
    const { action, provider } = pending;
    const name = socialProviderName(provider);
    busy = true;
    error = '';
    try {
      const response = await fetch(`${API_BASE}/api/account/step-up/email-otp/verify`, {
        method: 'POST', credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      if (!response.ok) {
        code = '';
        throw new Error('Incorrect or expired code. Check the email and try again.');
      }
      code = '';
      if (action === 'link') {
        step = 'verified';
        notice = `Email verified. Continue to ${name} within five minutes.`;
        return;
      }
      const account = accounts.find((candidate) => candidate.providerId === provider);
      if (!account) {
        reset();
        throw new Error(`${name} is no longer linked to this account.`);
      }
      const unlink = await fetch(`${API_BASE}/api/account/social/unlink`, {
        method: 'POST', credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ providerId: provider, accountId: account.accountId }),
      });
      if (!unlink.ok) {
        reset();
        throw new Error(unlinkError(unlink.status, await unlink.json().catch(() => null), provider));
      }
      await refreshAccounts();
      reset();
      notice = `${name} was unlinked. You can still sign in with your email or passkey.`;
    } catch (cause) {
      notice = '';
      error = cause instanceof Error ? cause.message : 'Could not update your account.';
    } finally {
      busy = false;
    }
  }

  async function linkProvider() {
    if (!pending) return;
    const provider = pending.provider;
    const name = socialProviderName(provider);
    busy = true;
    error = '';
    try {
      // The popup is opened synchronously by signInWithSocialPopup on this click.
      await signInWithSocialPopup(provider, undefined, 'link');
      await refreshAccounts();
      reset();
      notice = provider === 'apple'
        ? 'Apple is linked to this OpenKey account. Your OpenKey email is unchanged.'
        : `${name} is linked to this OpenKey account.`;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : `Could not link ${name}.`;
    } finally {
      busy = false;
    }
  }
</script>

<Card class="mt-6">
  <div class="mb-5">
    <h2 class="text-xl font-semibold text-surface-900">Linked sign-in methods</h2>
    <p class="mt-1 text-sm text-surface-500">Verify an email code before adding or removing Google or Apple.</p>
  </div>
  {#if error}<p class="mb-4 text-sm text-red-700" role="alert">{error}</p>{/if}
  {#if notice}<p class="mb-4 text-sm text-surface-600" role="status">{notice}</p>{/if}
  {#if loading}
    <p class="text-sm text-surface-500">Loading linked accounts…</p>
  {:else}
    {#if owner?.emailUndeliverable}
      <p class="mb-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900" data-testid="email-undeliverable">
        Apple has stopped forwarding email to {owner.email}, so OpenKey codes can't reach you. Turn forwarding back on in your Apple ID settings, or add a passkey so you can still sign in.
      </p>
    {:else if relayEmail}
      <p class="mb-4 rounded-xl border border-surface-200 bg-surface-50 px-4 py-3 text-sm text-surface-700" data-testid="email-relay">
        Your OpenKey email is an Apple Hide My Email address. Codes reach you only while Apple forwards email to it.
      </p>
    {/if}
    {#if step === 'code' && pending}
      <form class="flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); verifyCode(); }}>
        <label for="link-code" class="text-sm font-medium text-surface-700">
          Email verification code to {pending.action === 'link' ? 'link' : 'unlink'} {socialProviderName(pending.provider)}
        </label>
        <input id="link-code" class="w-full rounded-xl border border-surface-300 px-4 py-3" type="text"
          inputmode="numeric" autocomplete="one-time-code" maxlength="6" bind:value={code} disabled={busy} />
        <div class="flex gap-3">
          <Button type="submit" disabled={busy || code.length !== 6}>{busy ? 'Verifying…' : 'Verify code'}</Button>
          <Button type="button" variant="secondary" onclick={() => { reset(); error = ''; notice = ''; }}>Cancel</Button>
        </div>
      </form>
    {:else if step === 'verified' && pending}
      <Button onclick={linkProvider} disabled={busy}>
        {busy ? 'Connecting…' : `Continue to ${socialProviderName(pending.provider)}`}
      </Button>
    {:else if rows.length === 0}
      <p class="text-sm text-surface-500">No social sign-in method linked.</p>
    {:else}
      <div class="flex flex-col gap-3">
        {#each rows as provider (provider)}
          {@const linked = accounts.some((account) => account.providerId === provider)}
          <div class="flex items-center justify-between gap-3 rounded-xl border border-surface-200 bg-surface-50 p-4" data-testid={`linked-${provider}`}>
            <div class="min-w-0">
              <span class="font-medium text-surface-900">{socialProviderName(provider)}</span>
              <span class="block text-sm text-surface-500">{linked ? 'Linked' : 'Not linked'}</span>
            </div>
            {#if linked}
              <Button variant="secondary" onclick={() => requestCode('unlink', provider)} disabled={busy || onlySocial}>
                Unlink {socialProviderName(provider)}
              </Button>
            {:else}
              <Button onclick={() => requestCode('link', provider)} disabled={busy}>Link {socialProviderName(provider)}</Button>
            {/if}
          </div>
        {/each}
      </div>
      {#if onlySocial && accounts.length > 0}
        <p class="mt-3 text-sm text-surface-500" data-testid="unlink-refused">
          Add a passkey before removing a linked method: it's your only way to sign in{owner?.emailUndeliverable ? ' while Apple is not forwarding your email' : ''}.
        </p>
      {/if}
    {/if}
  {/if}
</Card>
