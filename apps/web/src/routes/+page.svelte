<script lang="ts">
  import { authClient } from '$lib/auth-client';

  const session = authClient.useSession();
</script>

<div class="hero">
  <h1>OpenKey</h1>
  <p class="tagline">Passkey-first authentication for Ethereum keys</p>

  <div class="features">
    <div class="feature">
      <h3>Passkey Security</h3>
      <p>No passwords to remember. Your biometrics are your key.</p>
    </div>
    <div class="feature">
      <h3>TEE Protected</h3>
      <p>Private keys secured in a Trusted Execution Environment.</p>
    </div>
    <div class="feature">
      <h3>Easy Integration</h3>
      <p>Simple SDK for any web application.</p>
    </div>
  </div>

  <div class="cta">
    {#if $session.data}
      <a href="/dashboard" class="button primary">Go to Dashboard</a>
    {:else}
      <a href="/auth/login" class="button primary">Get Started</a>
      <a href="/auth/login" class="button secondary">Sign In</a>
    {/if}
  </div>
</div>

<style>
  .hero {
    text-align: center;
    padding: 4rem 0;
  }

  h1 {
    font-size: 4rem;
    margin-bottom: 0.5rem;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .tagline {
    font-size: 1.5rem;
    color: #888;
    margin-bottom: 4rem;
  }

  .features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 2rem;
    margin-bottom: 4rem;
  }

  .feature {
    padding: 2rem;
    border: 1px solid #333;
    border-radius: 12px;
    text-align: left;
  }

  .feature h3 {
    margin-top: 0;
    color: #fafafa;
  }

  .feature p {
    color: #888;
    margin-bottom: 0;
  }

  .cta {
    display: flex;
    gap: 1rem;
    justify-content: center;
  }

  .button {
    padding: 1rem 2rem;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    text-decoration: none;
    transition: all 0.2s;
  }

  .button.primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
  }

  .button.primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
  }

  .button.secondary {
    background: transparent;
    border: 1px solid #333;
    color: #fafafa;
  }

  .button.secondary:hover {
    border-color: #666;
  }
</style>
