<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { authClient, API_BASE, authErrorMessage } from '$lib/auth-client';
  import { consoleOrigin } from '$lib/console-host';
  import { normalizeAuthReturnTo, safeOAuthAuthorizeQuery } from '$lib/auth-flow';
  import {
    loadConfiguredSocialProviders,
    signInWithSocialPopup,
    signInWithSocialRedirect,
    type SocialProviderId,
  } from '$lib/social-auth';
  import {
    nativeOtpSentKey,
    nativeReentryKey,
    nativeSignIn,
    nativeSocialReturnUrls,
  } from '$lib/native-mode';
  import NativeShell from '$lib/components/auth/native-shell.svelte';
  import { api } from '$lib/api';
  import SocialButtons from '$lib/components/auth/social-buttons.svelte';
  import { passkeysSupportedFromParams } from '$lib/passkey-support';
  import Button from '$lib/components/ui/button.svelte';
  import Card from '$lib/components/ui/card.svelte';
  import Input from '$lib/components/ui/input.svelte';

  // 'passkey' is the enrolment offer; 'passkeySignIn' and 'google' are native-mode landing steps.
  type Step = 'email' | 'otp' | 'passkey' | 'passkeySignIn' | 'google';

  // Native mode: the signed authorize query carries `tinycloud_request`, so the
  // sign-in is running in a system sheet opened by a native app.
  const native = nativeSignIn($page.url.searchParams);
  // `passkeys=false` comes from clients that cannot use WebAuthn.
  const passkeysSupported = passkeysSupportedFromParams($page.url.searchParams);

  function initialStep(): Step {
    if (!native || native.socialError) return 'email';
    if (native.method === 'email' && native.hint) return 'otp';
    if (native.method === 'passkey' && passkeysSupported) return 'passkeySignIn';
    if (native.method === 'google') return 'google';
    return 'email';
  }

  let email = $state(native?.hint ?? '');
  let otp = $state('');
  let step = $state<Step>(initialStep());
  let codeSent = $state(false);
  // A code was requested by an earlier load of this page; delivery is unconfirmed.
  let codeRequested = $state(false);
  let verifying = $state(false);
  let loading = $state(false);
  let error = $state('');
  let providers = $state<SocialProviderId[]>([]);
  let loadingProvider = $state<SocialProviderId | null>(null);
  // In OAuth flows the API answers sign-in/email-otp with its own redirect
  // URL (the consent page, or the client's redirect_uri when consent can be
  // skipped). The URL is captured during the sign-in response and replayed
  // verbatim by handlePostSignIn so the passkey step can run first.
  let oauthRedirectUrl: string | undefined;

  function getOAuthQuery(): string | undefined {
    return safeOAuthAuthorizeQuery($page.url.searchParams);
  }

  /**
   * Navigate to the OAuth redirect URL returned by the server, unchanged.
   * The URL comes from the signed oauth_query the API verified, so the only
   * client-side guard is against script-execution schemes. Returns false when
   * the URL is missing or unsafe so the caller can fall back.
   */
  function navigateToOAuthRedirect(url: string): boolean {
    try {
      const parsed = new URL(url, $page.url.origin);
      if (parsed.protocol === 'javascript:' || parsed.protocol === 'data:') return false;
    } catch {
      return false;
    }
    window.location.assign(url);
    return true;
  }

  function handlePostSignIn() {
    if (oauthRedirectUrl && navigateToOAuthRedirect(oauthRedirectUrl)) return;
    const oauthQuery = getOAuthQuery();
    const redirect = normalizeAuthReturnTo(
      $page.url.searchParams.get('redirect'),
      $page.url.origin,
      undefined,
      { consoleOrigin: consoleOrigin() || undefined },
    );
    if (oauthQuery) {
      window.location.href = API_BASE + '/api/auth/oauth2/authorize?' + oauthQuery;
    } else if (redirect) {
      if (new URL(redirect, $page.url.origin).origin === $page.url.origin) {
        goto(redirect);
      } else {
        window.location.assign(redirect);
      }
    } else {
      goto('/dashboard');
    }
  }

  onMount(() => {
    loadConfiguredSocialProviders().then((loaded) => { providers = loaded; }).catch(() => {});
    if (native) {
      // Coming back from the provider via the browser's back button restores
      // this page mid-redirect; clear the busy state.
      window.addEventListener('pageshow', (event) => {
        if (!event.persisted) return;
        loading = false;
        loadingProvider = null;
        if (step === 'google') step = 'email';
      });
      startNative(native);
    }
  });

  // Automatic first action for the requested login method. It runs once per
  // page load, and the code send is also keyed to the request in sessionStorage
  // so a reload never mails a second code.
  async function startNative(request: NonNullable<typeof native>) {
    if (request.socialError) {
      error = 'Google sign-in did not finish. Continue with your email instead.';
      return;
    }

    const existing = await authClient.getSession();
    if (existing.error) {
      error = authErrorMessage(existing.error, 'Could not check your session');
      step = 'email';
      return;
    }
    if (existing.data) {
      // Already signed in (for example straight back from Google): continue the
      // authorize request instead of signing in again. Once per request, so an
      // authorize that sends us back here cannot loop.
      const key = nativeReentryKey(request.requestId);
      if (!sessionStorage.getItem(key)) {
        sessionStorage.setItem(key, '1');
        handlePostSignIn();
        return;
      }
      step = 'email';
      return;
    }

    if (request.method === 'google') {
      await signInWithSocialTopLevel('google');
    } else if (request.method === 'email' && request.hint && step === 'otp') {
      // Claimed before dispatch, and kept on a failed or unanswered send: a
      // reload while the send is in flight must not mail a second code. Resend
      // is the retry.
      const key = nativeOtpSentKey(request.requestId);
      if (sessionStorage.getItem(key)) {
        codeRequested = true;
        return;
      }
      sessionStorage.setItem(key, '1');
      await sendOTP();
    }
  }

  async function sendOTP(): Promise<boolean> {
    loading = true;
    error = '';
    try {
      const result = await authClient.emailOtp.sendVerificationOtp({ email, type: 'sign-in' });
      if (result.error) {
        error = authErrorMessage(result.error, 'Failed to send code');
        return false;
      }
      codeSent = true;
      step = 'otp';
      return true;
    } catch (e: any) {
      error = e.message || 'Failed to send code';
      return false;
    } finally {
      loading = false;
    }
  }

  async function verifyOTP() {
    loading = true;
    verifying = true;
    error = '';
    try {
      const result = await authClient.signIn.emailOtp(
        {
          email,
          otp,
          oauth_query: getOAuthQuery(),
        },
        {
          // In OAuth flows the server answers { redirect: true, url }. The
          // client's redirect plugin would otherwise navigate in this same
          // onSuccess pass — before the key/passkey check below — so this
          // hook (which better-fetch runs before plugin hooks) keeps the URL
          // and clears the redirect flag to veto that navigation.
          onSuccess(context) {
            const data = context.data as { redirect?: boolean; url?: string } | null;
            if (data?.redirect && typeof data.url === 'string' && data.url) {
              oauthRedirectUrl = data.url;
              data.redirect = false;
            }
          },
        },
      );
      if (result.error) {
        error = authErrorMessage(result.error, 'Invalid code');
        return;
      }

      // Email OTP is also the default account-creation path. The API normally
      // provisions a key in its user hook; this keeps the user moving if that
      // non-critical hook needs to be retried.
      try {
        const { keys } = await api.listKeys();
        if (keys.length === 0) await api.generateKey();
      } catch (keyError) {
        console.error('[Login] Failed to ensure key exists:', keyError);
      }

      // Encourage passkey setup for accounts that do not have one, but never
      // make it a condition of continuing. Passkey discovery is best-effort:
      // any failure (network, API unavailable) falls through to handlePostSignIn()
      // so that OTP sign-in works independently of passkey availability.
      // Clients without WebAuthn skip the prompt entirely.
      // Native mode never offers enrolment: the sheet's job is to return to the app.
      if (passkeysSupported && !native) {
        try {
          const passkeys = await authClient.passkey.listUserPasskeys();
          if (!passkeys.error && Array.isArray(passkeys.data) && passkeys.data.length === 0) {
            step = 'passkey';
            return;
          }
        } catch (passkeyError) {
          console.error('[Login] Failed to check passkeys, continuing without prompt:', passkeyError);
        }
      }
      handlePostSignIn();
    } catch (e: any) {
      error = e.message || 'Invalid code';
    } finally {
      loading = false;
      verifying = false;
    }
  }

  async function signInWithPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.signIn.passkey();
      if (result.error) {
        error = authErrorMessage(result.error, 'Passkey sign-in failed');
      } else {
        handlePostSignIn();
      }
    } catch (e: any) {
      error = e.message || 'Passkey sign-in failed';
    } finally {
      loading = false;
    }
  }

  async function signInWithSocial(provider: SocialProviderId) {
    loading = true;
    loadingProvider = provider;
    error = '';
    try {
      await signInWithSocialPopup(provider);
      handlePostSignIn();
    } catch (e: any) {
      error = e.message || `${provider === 'google' ? 'Google' : 'Apple'} sign-in failed`;
    } finally {
      loading = false;
      loadingProvider = null;
    }
  }

  async function signInWithSocialTopLevel(provider: SocialProviderId) {
    if (!native) return;
    loading = true;
    loadingProvider = provider;
    error = '';
    try {
      await signInWithSocialRedirect(provider, nativeSocialReturnUrls(window.location.origin, native.signedQuery));
    } catch (e: any) {
      error = e.message || `${provider === 'google' ? 'Google' : 'Apple'} sign-in failed`;
      step = 'email';
      loading = false;
      loadingProvider = null;
    }
  }

  async function registerPasskey() {
    loading = true;
    error = '';
    try {
      const result = await authClient.passkey.addPasskey();
      if (result?.error) {
        error = authErrorMessage(result.error, 'Failed to create passkey');
      } else {
        handlePostSignIn();
      }
    } catch (e: any) {
      error = e.message || 'Failed to create passkey';
    } finally {
      loading = false;
    }
  }

  function useDifferentEmail() {
    step = 'email';
    otp = '';
    error = '';
    if (native) email = '';
  }

  function setOtp(value: string) {
    otp = value.replace(/\D/g, '').slice(0, 6);
  }
</script>

{#if native}
  <NativeShell clientId={native.clientId} heading={(name) => `Sign in to ${name}`}>
    {#if error}
      <div class="nb-error" role="alert">{error}</div>
    {/if}

    {#if step === 'otp'}
      <p class="nb-lede">
        {#if codeSent}
          We sent a 6-digit code to <strong>{email}</strong>.
        {:else if loading}
          Sending a 6-digit code to <strong>{email}</strong>…
        {:else if codeRequested}
          A 6-digit code was requested for <strong>{email}</strong>. Enter it below, or resend if it has not arrived.
        {:else}
          We couldn't send a code to <strong>{email}</strong>.
        {/if}
      </p>
      <form onsubmit={(event) => { event.preventDefault(); verifyOTP(); }} class="nb-stack">
        <div class="otp">
          <label for="otp" class="sr-only">Verification code</label>
          <input
            id="otp"
            class="otp-input"
            type="text"
            value={otp}
            oninput={(event) => { setOtp(event.currentTarget.value); event.currentTarget.value = otp; }}
            maxlength={6}
            inputmode="numeric"
            autocomplete="one-time-code"
            required
            disabled={verifying}
            autofocus
          />
          <div class="otp-boxes" aria-hidden="true">
            {#each [0, 1, 2, 3, 4, 5] as index}
              <span class="otp-box" class:otp-box-active={index === otp.length}>{otp[index] ?? ''}</span>
            {/each}
          </div>
        </div>
        <button type="submit" class="nb-button nb-primary" disabled={loading || otp.length < 6}>
          {verifying ? 'Verifying…' : 'Continue'}
        </button>
      </form>
      <div class="nb-center">
        <button type="button" class="nb-link" onclick={useDifferentEmail} disabled={loading}>Use a different email</button>
        <button type="button" class="nb-link nb-quiet" onclick={sendOTP} disabled={loading}>Resend code</button>
      </div>
    {:else if step === 'passkeySignIn'}
      <p class="nb-lede">Use the passkey saved on this device to sign in.</p>
      <div class="nb-stack">
        <button type="button" class="nb-button nb-primary" onclick={signInWithPasskey} disabled={loading}>
          {loading ? 'Waiting for passkey…' : 'Continue with passkey'}
        </button>
      </div>
      <div class="nb-center">
        <button type="button" class="nb-link" onclick={() => { step = 'email'; error = ''; }} disabled={loading}>Use email instead</button>
      </div>
    {:else if step === 'google'}
      <p class="nb-lede" role="status">Connecting to Google…</p>
    {:else}
      <p class="nb-lede">Enter your email and we'll send you a sign-in code.</p>
      <form onsubmit={(event) => { event.preventDefault(); sendOTP(); }} class="nb-stack">
        <label for="email" class="sr-only">Email address</label>
        <input
          id="email"
          class="nb-input"
          type="email"
          bind:value={email}
          placeholder="you@example.com"
          autocomplete="email"
          autocapitalize="none"
          spellcheck={false}
          required
          disabled={loading}
        />
        <button type="submit" class="nb-button nb-primary" disabled={loading}>
          {loading && !loadingProvider ? 'Sending code…' : 'Continue'}
        </button>
      </form>

      {#if providers.length > 0 || passkeysSupported}
        <div class="nb-or" aria-hidden="true">or</div>
        <div class="nb-stack">
          {#each providers as provider}
            <button
              type="button"
              class="nb-button"
              onclick={() => signInWithSocialTopLevel(provider)}
              disabled={loading}
              aria-label={`Continue with ${provider === 'google' ? 'Google' : 'Apple'}`}
            >
              {#if provider === 'google'}
              <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
                <path fill="#4285F4" d="M17.64 9.205c0-.638-.057-1.252-.164-1.841H9v3.482h4.844a4.14 4.14 0 0 1-1.797 2.716v2.258h2.909c1.703-1.568 2.684-3.879 2.684-6.615Z"/>
                <path fill="#34A853" d="M9 18c2.43 0 4.468-.806 5.956-2.18l-2.909-2.258c-.806.54-1.835.859-3.047.859-2.344 0-4.328-1.585-5.037-3.714H.956v2.333A9 9 0 0 0 9 18Z"/>
                <path fill="#FBBC05" d="M3.963 10.707A5.41 5.41 0 0 1 3.682 9c0-.592.102-1.167.281-1.707V4.96H.956A9 9 0 0 0 0 9c0 1.452.347 2.827.956 4.04l3.007-2.333Z"/>
                <path fill="#EA4335" d="M9 3.579c1.321 0 2.507.454 3.441 1.346l2.581-2.581C13.464.892 11.426 0 9 0A9 9 0 0 0 .956 4.96l3.007 2.333C4.672 5.164 6.656 3.579 9 3.579Z"/>
              </svg>
              {/if}
              {loadingProvider === provider ? `Connecting to ${provider === 'google' ? 'Google' : 'Apple'}…` : `Continue with ${provider === 'google' ? 'Google' : 'Apple'}`}
            </button>
          {/each}
          {#if passkeysSupported}
            <button type="button" class="nb-button" onclick={signInWithPasskey} disabled={loading}>
              {loading && !loadingProvider ? 'Waiting for passkey…' : 'Use a passkey'}
            </button>
          {/if}
        </div>
      {/if}
    {/if}
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

    <Card class="w-full p-8 sm:p-10">
      {#if step === 'email'}
        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">Welcome to OpenKey</h1>
        <p class="mb-7 text-center text-sm text-surface-500">Sign in or create an account with your email</p>

        {#if error}
          <div class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
            {error}
          </div>
        {/if}

        <form onsubmit={(event) => { event.preventDefault(); sendOTP(); }} class="flex flex-col gap-4">
          <div>
            <label for="email" class="mb-2 block text-sm font-medium text-surface-700">Email address</label>
            <Input
              id="email"
              type="email"
              bind:value={email}
              placeholder="you@example.com"
              autocomplete="email"
              autocapitalize="none"
              spellcheck={false}
              required
              disabled={loading}
              autofocus
            />
          </div>
          <Button type="submit" disabled={loading} class="w-full">
            {loading ? 'Sending code…' : 'Continue with email'}
          </Button>
        </form>

        {#if providers.length > 0}
          <div class="mt-4">
            <SocialButtons
              {providers}
              {loadingProvider}
              disabled={loading}
              onsignin={signInWithSocial}
            />
          </div>
        {/if}

        {#if passkeysSupported}
        <div class="my-6 flex items-center gap-4 text-surface-400" aria-hidden="true">
          <div class="h-px flex-1 bg-surface-200"></div>
          <span class="text-sm">or</span>
          <div class="h-px flex-1 bg-surface-200"></div>
        </div>

        <Button variant="secondary" onclick={signInWithPasskey} disabled={loading} class="w-full">
          <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" />
            <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
          </svg>
          {loading ? 'Waiting for passkey…' : 'Use a passkey instead'}
        </Button>
        {/if}
      {:else if step === 'otp'}
        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">Check your email</h1>
        <p class="mb-7 text-center text-sm text-surface-500">
          Enter the 6-digit code sent to <span class="font-medium text-surface-900">{email}</span>
        </p>

        {#if error}
          <div class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
            {error}
          </div>
        {/if}

        <form onsubmit={(event) => { event.preventDefault(); verifyOTP(); }} class="flex flex-col gap-4">
          <div>
            <label for="otp" class="sr-only">Verification code</label>
            <Input
              id="otp"
              type="text"
              bind:value={otp}
              placeholder="000000"
              maxlength={6}
              inputmode="numeric"
              autocomplete="one-time-code"
              required
              disabled={loading}
              autofocus
              class="text-center font-mono text-2xl tracking-widest"
            />
          </div>
          <Button type="submit" disabled={loading} class="w-full">
            {loading ? 'Verifying…' : 'Verify and continue'}
          </Button>
        </form>
        <button
          type="button"
          onclick={useDifferentEmail}
          disabled={loading}
          class="mt-4 w-full text-center text-sm font-medium text-surface-600 transition-colors hover:text-surface-900 disabled:opacity-50"
        >
          Use a different email
        </button>
      {:else}
        <div class="mb-5 flex justify-center">
          <div class="inline-flex h-12 w-12 items-center justify-center rounded-full bg-primary-50 text-primary-700 ring-1 ring-primary-200">
            <svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z" />
              <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
            </svg>
          </div>
        </div>
        <h1 class="mb-2 text-center text-2xl font-bold text-surface-900">Secure your account</h1>
        <p class="mb-7 text-center text-sm text-surface-500">
          Create a passkey for faster, phishing-resistant sign-in. You can skip this and keep using email codes.
        </p>

        {#if error}
          <div class="mb-6 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700" role="alert">
            {error}
          </div>
        {/if}

        <div class="flex flex-col gap-3">
          <Button onclick={registerPasskey} disabled={loading} class="w-full">
            {loading ? 'Creating passkey…' : 'Create a passkey'}
          </Button>
          <Button variant="ghost" onclick={handlePostSignIn} disabled={loading} class="w-full">
            Skip for now
          </Button>
        </div>
      {/if}
    </Card>

    <div class="mt-6 flex items-center justify-center gap-2 text-xs text-surface-500">
      <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
      Protected by TEE hardware security
    </div>
  </div>
</div>
{/if}

<style>
  .otp {
    position: relative;
  }

  .otp-input {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    opacity: 0;
    font-size: 16px;
  }

  .otp-boxes {
    display: flex;
    gap: 8px;
    pointer-events: none;
  }

  .otp-box {
    display: flex;
    flex: 1;
    align-items: center;
    justify-content: center;
    height: 56px;
    border-radius: 12px;
    border: 1px solid var(--nb-border);
    background: var(--nb-field);
    font-size: 24px;
    font-weight: 600;
  }

  .otp-box-active {
    border-color: var(--nb-fg);
  }
</style>
