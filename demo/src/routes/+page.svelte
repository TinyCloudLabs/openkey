<script lang="ts">
  import { onMount } from 'svelte';
  import { OpenKey, type AuthResult, type SignResult } from '@openkey/sdk';

  let openkey: OpenKey | undefined;
  let account = $state<AuthResult | null>(null);
  let message = $state('Hello from the OpenKey demo!');
  let signed = $state<{ message: string; result: SignResult } | null>(null);
  let busy = $state<'sign-in' | 'sign' | 'sign-out' | null>(null);
  let error = $state('');
  let notice = $state('');

  onMount(() => {
    openkey = new OpenKey({
      // Production OpenKey (https://openkey.so) unless VITE_OPENKEY_URL is set.
      host: import.meta.env.VITE_OPENKEY_URL || undefined,
      appName: 'OpenKey Demo',
    });
    return () => openkey?.disconnect();
  });

  function begin(action: NonNullable<typeof busy>) {
    busy = action;
    error = '';
    notice = '';
  }

  async function signIn() {
    if (!openkey) return;
    begin('sign-in');
    try {
      account = await openkey.connect();
    } catch (e) {
      if (isCancelled(e)) notice = 'Sign-in cancelled.';
      else error = describe(e);
    } finally {
      busy = null;
    }
  }

  async function signMessage() {
    if (!openkey || !account) return;
    begin('sign');
    signed = null;
    const text = message;
    try {
      const result = await openkey.signMessage({ message: text, keyId: account.keyId });
      signed = { message: text, result };
    } catch (e) {
      if (isCancelled(e)) notice = 'Signing cancelled.';
      else error = describe(e);
    } finally {
      busy = null;
    }
  }

  async function signOut() {
    if (!openkey) return;
    begin('sign-out');
    try {
      const { revoked } = await openkey.signOut();
      notice = revoked
        ? 'Signed out.'
        : 'Signed out of the demo, but OpenKey could not confirm that your session was revoked.';
    } catch (e) {
      // The SDK drops its local session before it asks OpenKey to revoke it,
      // so the demo is signed out either way.
      if (isCancelled(e)) notice = 'Signed out of the demo. Your OpenKey session is still active.';
      else error = describe(e);
    } finally {
      account = null;
      signed = null;
      busy = null;
    }
  }

  function isCancelled(e: unknown) {
    return (e as { code?: string } | null)?.code === 'USER_CANCELLED';
  }

  function describe(e: unknown): string {
    const { code, message } = (e ?? {}) as { code?: string; message?: string };
    if (code === 'POPUP_BLOCKED') return 'Your browser blocked the OpenKey window. Allow pop-ups for this site and try again.';
    return message || 'Something went wrong. Please try again.';
  }
</script>

<svelte:head>
  <title>OpenKey Demo</title>
  <meta name="description" content="Sign in with OpenKey and sign a message using @openkey/sdk." />
</svelte:head>

<main>
  <h1>OpenKey Demo</h1>
  <p class="lede">
    Sign in with OpenKey, then sign a message with your key. This page uses
    <a href="https://www.npmjs.com/package/@openkey/sdk">@openkey/sdk</a>.
  </p>

  {#if account}
    <section aria-labelledby="account-heading">
      <h2 id="account-heading">Signed in</h2>
      <p class="label">Address</p>
      <code class="value">{account.address}</code>
      <p class="label">Key</p>
      <p class="plain">{account.keyType === 'EXTERNAL' ? 'Linked wallet' : 'OpenKey-managed key (TEE-secured)'}</p>
      <button class="secondary" onclick={signOut} disabled={busy !== null}>
        {busy === 'sign-out' ? 'Signing out…' : 'Sign out'}
      </button>
    </section>

    <section aria-labelledby="sign-heading">
      <h2 id="sign-heading">Sign a message</h2>
      <label for="message">Message</label>
      <textarea id="message" rows="3" bind:value={message} disabled={busy !== null}></textarea>
      <button onclick={signMessage} disabled={busy !== null || !message.trim()}>
        {busy === 'sign' ? 'Waiting for approval…' : 'Sign message'}
      </button>

      {#if signed}
        <div class="result">
          <p class="label">Signed message</p>
          <pre class="value">{signed.message}</pre>
          <p class="label">Signature</p>
          <code class="value">{signed.result.signature}</code>
          <p class="label">Signed by</p>
          <code class="value">{signed.result.address}</code>
        </div>
      {/if}
    </section>
  {:else}
    <section aria-labelledby="sign-in-heading">
      <h2 id="sign-in-heading">Sign in</h2>
      <p class="plain">
        OpenKey opens on this page. Sign in with a passkey or an email code, or create an account.
      </p>
      <button onclick={signIn} disabled={busy !== null}>
        {busy === 'sign-in' ? 'Waiting for OpenKey…' : 'Sign in with OpenKey'}
      </button>
    </section>
  {/if}

  {#if error}
    <p class="error" role="alert">{error}</p>
  {/if}
  {#if notice}
    <p class="notice" role="status">{notice}</p>
  {/if}
</main>

<style>
  :global(body) {
    margin: 0;
    background: #fafafa;
    color: #171717;
    font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.5;
  }

  main {
    max-width: 36rem;
    margin: 0 auto;
    padding: 3rem 1.25rem;
  }

  h1 {
    margin: 0 0 0.5rem;
    font-size: 1.75rem;
  }

  h2 {
    margin: 0 0 1rem;
    font-size: 1.125rem;
  }

  a {
    color: inherit;
  }

  .lede {
    margin: 0 0 2rem;
    color: #525252;
  }

  section {
    margin-bottom: 1rem;
    padding: 1.25rem;
    background: #fff;
    border: 1px solid #e5e5e5;
    border-radius: 12px;
  }

  .plain {
    margin: 0;
    color: #404040;
  }

  .label {
    margin: 1rem 0 0.25rem;
    color: #737373;
    font-size: 0.75rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  h2 + .label {
    margin-top: 0;
  }

  .value {
    display: block;
    margin: 0;
    padding: 0.5rem 0.75rem;
    background: #f5f5f5;
    border-radius: 8px;
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 0.85rem;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
  }

  label {
    display: block;
    margin-bottom: 0.5rem;
    font-size: 0.875rem;
    font-weight: 500;
  }

  textarea {
    box-sizing: border-box;
    width: 100%;
    padding: 0.6rem 0.75rem;
    border: 1px solid #d4d4d4;
    border-radius: 8px;
    font: inherit;
    resize: vertical;
  }

  button {
    margin-top: 1rem;
    padding: 0.65rem 1.25rem;
    background: #171717;
    color: #fff;
    border: 1px solid #171717;
    border-radius: 8px;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }

  button.secondary {
    background: #fff;
    color: #171717;
    border-color: #d4d4d4;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .result {
    margin-top: 1.25rem;
    padding-top: 0.25rem;
    border-top: 1px solid #e5e5e5;
  }

  .error {
    padding: 0.75rem 1rem;
    color: #b91c1c;
    background: #fef2f2;
    border: 1px solid #fecaca;
    border-radius: 8px;
  }

  .notice {
    color: #525252;
  }
</style>
