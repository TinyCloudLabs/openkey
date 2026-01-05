<script lang="ts">
  import type { Snippet } from 'svelte';

  let { children }: { children: Snippet } = $props();
</script>

<svelte:head>
  <title>OpenKey</title>
  <meta name="description" content="Passkey-first authentication for Ethereum keys" />
</svelte:head>

<div class="app">
  <header>
    <nav>
      <a href="/" class="logo">OpenKey</a>
      <div class="nav-links">
        <a href="/dashboard">Dashboard</a>
      </div>
    </nav>
  </header>

  <main>
    {@render children()}
  </main>

  <footer>
    <p>OpenKey - Your keys, secured by passkeys</p>
  </footer>
</div>

<style>
  :global(*, *::before, *::after) {
    box-sizing: border-box;
  }

  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0a0a0a;
    color: #fafafa;
  }

  .app {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  header {
    border-bottom: 1px solid #333;
    padding: 1rem 2rem;
  }

  nav {
    display: flex;
    align-items: center;
    justify-content: space-between;
    max-width: 1200px;
    margin: 0 auto;
  }

  .logo {
    font-size: 1.5rem;
    font-weight: 700;
    color: #fafafa;
    text-decoration: none;
  }

  .nav-links a {
    color: #888;
    text-decoration: none;
    transition: color 0.2s;
  }

  .nav-links a:hover {
    color: #fafafa;
  }

  main {
    flex: 1;
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
    width: 100%;
  }

  footer {
    border-top: 1px solid #333;
    padding: 2rem;
    text-align: center;
    color: #666;
  }
</style>
