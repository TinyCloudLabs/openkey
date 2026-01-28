# OpenKey OAuth Demo

A minimal SvelteKit app demonstrating OpenKey's OAuth 2.1 flow and message signing.

## Features

- **OAuth 2.1 Login**: Authenticate users via OpenKey with PKCE
- **Identity Verification**: Display user's ID (sub claim from ID token)
- **Message Signing**: Sign arbitrary messages using OpenKey's widget

## Quick Start

```bash
# Install dependencies
bun install

# Start dev server
bun run dev
```

Visit http://localhost:5174

## Configuration

Environment variables (set in `.env` or Cloudflare dashboard):

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_OPENKEY_HOST` | `https://openkey.so` | OpenKey API host |
| `VITE_CLIENT_ID` | `demo_client` | OAuth client ID |

## Deploying to Cloudflare Pages

### Option 1: Wrangler CLI

```bash
# Build the app
bun run build

# Deploy to Cloudflare Pages
bunx wrangler pages deploy .svelte-kit/cloudflare
```

### Option 2: Git Integration

1. Push to GitHub
2. Connect repo to Cloudflare Pages
3. Set build command: `bun run build`
4. Set output directory: `.svelte-kit/cloudflare`

## Registering as OAuth Client

Before the demo works, register it as an OAuth client in OpenKey:

```bash
# From OpenKey repo root
DATABASE_URL=<your-db-url> bun run packages/db/prisma/seed-oauth-clients.ts register
```

Update the script to use your demo's redirect URI:
- Local: `http://localhost:5174/callback`
- Production: `https://your-demo.pages.dev/callback`

## OAuth Flow

```
1. User clicks "Sign in with OpenKey"
2. App generates PKCE code_verifier + code_challenge
3. Redirects to OpenKey /api/auth/oauth2/authorize
4. User logs in and consents
5. OpenKey redirects to /callback with code
6. App exchanges code for tokens
7. App displays user info from ID token
```

## Message Signing Flow

```
1. User enters message text
2. Clicks "Sign with OpenKey"
3. OpenKey widget popup opens
4. User approves signing
5. App receives signature via postMessage
6. Displays signature and signing address
```

## Tech Stack

- [SvelteKit](https://kit.svelte.dev/) - Full-stack framework
- [Cloudflare Pages](https://pages.cloudflare.com/) - Edge deployment
- [Tailwind CSS v4](https://tailwindcss.com/) - Styling
- [OpenKey OAuth 2.1](https://openkey.so) - Authentication
