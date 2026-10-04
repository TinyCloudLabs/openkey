# OpenKey Demo

A one-page SvelteKit app that shows the [`@openkey/sdk`](https://www.npmjs.com/package/@openkey/sdk) flow a third-party app uses:

1. **Sign in with OpenKey.** `openkey.connect()` opens OpenKey on the page. The user signs in with a passkey or an email code (or creates an account), and the app gets the address of their key.
2. **Sign a message.** `openkey.signMessage({ message, keyId })` asks the user to approve, then returns the signature and the signing address.
3. **Sign out.** `openkey.signOut()` asks OpenKey to revoke the session.

The app needs no OAuth client registration, API keys, or server. All of the OpenKey code is in [`src/routes/+page.svelte`](src/routes/+page.svelte).

Live: https://openkey-demo.pages.dev

## Run locally

```bash
bun install
bun run dev
```

Open http://localhost:5174. The demo uses production OpenKey (`https://openkey.so`). To use a local OpenKey web app instead, copy `.env.example` to `.env` and set `VITE_OPENKEY_URL`.

`bun run typecheck` runs `svelte-check`.

## Deploy

The `openkey-demo` Cloudflare Pages project builds this directory on every push:

| Setting | Value |
|---|---|
| Root directory | `demo` |
| Build command | `bun run build` |
| Output directory | `.svelte-kit/cloudflare` (`pages_build_output_dir` in `wrangler.toml`) |

Pages installs dependencies with `bun install --frozen-lockfile`, so commit `bun.lock` whenever `package.json` changes. The build is a static site (`@sveltejs/adapter-static`).
