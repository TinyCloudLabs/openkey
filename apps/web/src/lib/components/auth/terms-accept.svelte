<script lang="ts">
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import NativeShell from '$lib/components/auth/native-shell.svelte';
  import { PRIVACY_URL, TERMS_URL, effectiveDate, type TermsStatus } from '$lib/terms';

  // Required screen: shown after sign-in, before anything else, to any account
  // that has not accepted the CURRENT terms. It has no close and no skip. Agree
  // continues. On the web a small "Other options" box leads to the ways out that
  // need no agreement (sign out, disconnect apps, delete the account); the native
  // sheet has Don't agree (sign out) here instead.
  //   first   - the account has never accepted terms
  //   updated - the account accepted an older version and must accept the new one
  // The date and "What changed" come only from the API; when it has none, nothing is shown.
  interface Props {
    kind: 'first' | 'updated';
    surface: 'web' | 'native';
    release: TermsStatus;
    email: string;
    /** The native sheet's OAuth client, for its branding. */
    clientId?: string | null;
    /** App the user was on their way to (consent / approval link), if any. */
    appName?: string | null;
    busy?: 'accept' | 'decline' | null;
    error?: string | null;
    /** Web: the Other options page (sign out, disconnect apps or delete the account without agreeing). */
    otherOptions?: string | null;
    /** Native: what Don't agree does. */
    declineNote?: string;
    onaccept: () => void;
    ondecline: () => void;
  }

  let { kind, surface, release, email, clientId = null, appName = null, busy = null, error = null, otherOptions = null, declineNote = '', onaccept, ondecline }: Props = $props();

  const title = $derived(
    kind === 'updated'
      ? release.privacyChanged ? 'We’ve updated our Terms and Privacy Policy' : 'We’ve updated our Terms of Service'
      : 'Accept the Terms and Privacy Policy',
  );
  const lede = $derived(
    kind === 'updated'
      ? 'To keep using your OpenKey account, agree to the updated Terms of Service.'
      : 'OpenKey and TinyCloud are run by TinyCloud, Inc. To use your account, agree to our Terms of Service. Our Privacy Policy explains what we collect, why, and your rights.',
  );
  // The version id stays in the stored record, not on screen.
  const effective = $derived(effectiveDate(release.effective));
  const whatChanged = $derived(kind === 'updated' ? release.whatChanged?.trim() || null : null);
  const documents = $derived([
    { label: 'Terms of Service', rest: effective ? `, effective ${effective}` : '', href: TERMS_URL },
    { label: 'Privacy Policy', rest: ': what we collect, why, and your rights', href: PRIVACY_URL },
  ]);
</script>

{#snippet externalIcon()}
  <svg class="doc-out" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M7 17 17 7M8 7h9v9" />
  </svg>
{/snippet}

{#snippet docIcon()}
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
    <path d="M14 3v5h5M9 13h6M9 17h6" />
  </svg>
{/snippet}

{#if surface === 'native'}
  <NativeShell clientId={clientId ?? ''} name="OpenKey" heading={() => title}>
    <p class="nb-lede">{lede}</p>

    {#if appName}
      <p class="nb-note app-note" data-testid="terms-app-note">After you agree, you’ll go back to <strong>{appName}</strong>.</p>
    {/if}
    {#if whatChanged}
      <p class="nb-note changed" data-testid="terms-what-changed"><strong>What changed:</strong> {whatChanged}</p>
    {/if}

    <ul class="docs" aria-label="Documents to read">
      {#each documents as doc}
        <li>
          <a class="doc" href={doc.href} target="_blank" rel="noopener noreferrer">
            <span class="doc-icon">{@render docIcon()}</span>
            <span class="doc-text"><span class="doc-detail"><span class="doc-label">{doc.label}</span>{doc.rest}</span></span>
            {@render externalIcon()}
            <span class="sr-only">(opens in a new tab)</span>
          </a>
        </li>
      {/each}
    </ul>

    {#if error}
      <div class="nb-error" role="alert">{error}</div>
    {/if}
    <div class="nb-stack">
      <button type="button" class="nb-button nb-primary" onclick={onaccept} disabled={busy !== null} aria-busy={busy === 'accept'}>
        {busy === 'accept' ? 'Saving…' : 'Agree and continue'}
      </button>
      <p class="nb-note fine">By selecting Agree and continue, you agree to the Terms of Service and acknowledge the Privacy Policy.</p>
    </div>

    <section class="decline" aria-labelledby="decline-heading">
      <h2 id="decline-heading" class="decline-title">If you don’t agree</h2>
      <p class="nb-note">{declineNote}</p>
      <div class="nb-center">
        <button type="button" class="nb-link" onclick={ondecline} disabled={busy !== null}>
          {busy === 'decline' ? 'Signing out…' : 'Don’t agree and sign out'}
        </button>
      </div>
    </section>
    <p class="nb-note signed-in">Signed in as {email}</p>
  </NativeShell>
{:else}
  <div class="flex min-h-screen items-center justify-center bg-surface-50 px-4 py-12">
    <div class="w-full max-w-md">
      <div class="mb-8 flex justify-center">
        <div class="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-900">
          <svg class="h-6 w-6 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
          </svg>
        </div>
      </div>

      <Card class="w-full p-8 sm:p-10" data-testid="terms-accept">
        <div class="mb-5 flex justify-center">
          <div class="inline-flex h-12 w-12 items-center justify-center rounded-full bg-primary-50 text-primary-700 ring-1 ring-primary-200">
            <svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
              <path d="M14 3v5h5M9 13l2 2 4-4" />
            </svg>
          </div>
        </div>

        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">{title}</h1>
        <p class="mb-6 text-center text-sm text-surface-500">{lede}</p>

        {#if appName}
          <p class="mb-4 rounded-xl border border-surface-200 bg-surface-50 px-3 py-2 text-center text-sm text-surface-700" data-testid="terms-app-note">
            After you agree, you’ll go back to <span class="font-semibold text-surface-900">{appName}</span>.
          </p>
        {/if}
        {#if whatChanged}
          <p class="mb-4 rounded-xl border border-primary-200 bg-primary-50 px-3 py-2 text-sm text-primary-900" data-testid="terms-what-changed">
            <span class="font-semibold">What changed:</span> {whatChanged}
          </p>
        {/if}

        <ul class="mb-6 flex flex-col gap-2" aria-label="Documents to read">
          {#each documents as doc}
            <li>
              <a
                href={doc.href}
                target="_blank"
                rel="noopener noreferrer"
                class="flex min-h-14 items-center gap-3 rounded-xl border border-surface-200 px-4 py-3 no-underline transition-colors hover:border-surface-500 hover:bg-surface-50"
              >
                <span class="text-surface-500">{@render docIcon()}</span>
                <span class="flex min-w-0 flex-1 flex-col">
                  <span class="text-sm text-surface-500"><span class="font-semibold text-surface-900">{doc.label}</span>{doc.rest}</span>
                </span>
                <span class="text-surface-400">{@render externalIcon()}</span>
                <span class="sr-only">(opens in a new tab)</span>
              </a>
            </li>
          {/each}
        </ul>

        {#if error}
          <div class="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">{error}</div>
        {/if}
        <Button onclick={onaccept} disabled={busy !== null} aria-busy={busy === 'accept'} class="w-full">
          {busy === 'accept' ? 'Saving…' : 'Agree and continue'}
        </Button>
        <p class="mt-3 text-center text-xs text-surface-500">
          By selecting Agree and continue, you agree to the Terms of Service and acknowledge the Privacy Policy.
        </p>

        {#if otherOptions}
          <p class="mt-3 text-center">
            <a href={otherOptions} class="inline-block py-3 text-xs text-surface-500 underline underline-offset-2 hover:text-surface-700" data-testid="terms-other-options">Other options</a>
          </p>
        {/if}
      </Card>

      <p class="mt-6 text-center text-xs text-surface-400">Signed in as {email}</p>
    </div>
  </div>
{/if}

<style>
  .docs {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: 0 0 20px;
    padding: 0;
    list-style: none;
  }

  .doc {
    box-sizing: border-box;
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 60px;
    padding: 10px 14px;
    border-radius: 14px;
    border: 1px solid var(--nb-border);
    background: var(--nb-field);
    color: var(--nb-fg);
    text-decoration: none;
  }

  .doc:focus-visible {
    outline: 2px solid var(--nb-ring);
    outline-offset: 2px;
  }

  .doc-icon,
  .doc-out {
    flex: none;
    color: var(--nb-muted);
  }

  .doc-text {
    display: flex;
    flex: 1;
    min-width: 0;
    flex-direction: column;
    gap: 2px;
  }

  .doc-label {
    font-weight: 600;
    color: var(--nb-fg);
  }

  .doc-detail {
    font-size: 15px;
    line-height: 1.35;
    color: var(--nb-muted);
  }

  .app-note.nb-note,
  .changed.nb-note {
    margin: 0 0 16px;
    padding: 10px 14px;
    border-radius: 12px;
    border: 1px solid var(--nb-border);
    background: var(--nb-field);
  }

  .app-note strong,
  .changed strong {
    color: var(--nb-fg);
  }

  .fine {
    text-align: center;
    font-size: 13px;
  }

  .decline {
    margin-top: 28px;
    padding-top: 20px;
    border-top: 1px solid var(--nb-border);
  }

  .decline-title {
    margin: 0 0 4px;
    font-size: 15px;
    font-weight: 600;
  }

  .signed-in {
    margin-top: 20px;
    text-align: center;
    font-size: 13px;
    color: var(--nb-faint);
  }
</style>
