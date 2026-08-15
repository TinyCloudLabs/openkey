# Development Setup

## Prerequisites

- [Bun](https://bun.sh) 1.1.0+
- PostgreSQL client/server binaries only for the optional isolated
  migration-deploy parity check (`pg_config`, `initdb`, `pg_ctl`, `createdb`)

## Quick Start

```bash
# 1. Install dependencies
bun install

# 2. Set up environment
cp .env.example .env
# Edit .env with your values (see Environment Variables below)

# 3. Push the persistent local PGlite schema
bun db:push

# 4. Start API + web frontend
bun dev
```

- **API** runs at `http://localhost:3001`
- **Web** runs at `http://localhost:5173`

## Running the API

Run the API directly with Bun against the default persistent PGlite database:

```bash
bun db:push
bun dev:api
```

Or start everything together:

```bash
bun dev              # Starts API + Web via Turbo
```

The public local acceptance smoke starts from a fresh disposable PGlite
database and exercises API, OTP/session, device authorization, and the public
TinyCloud CLI artifact:

```bash
bun run smoke:local:pglite
```

PostgreSQL is reserved for migration-deploy parity only. The isolated command
creates and removes a current-user cluster; it does not require Docker, a
`postgres` OS-user switch, or filesystem ACL changes:

```bash
bun run smoke:postgres:migration-parity
```

## Environment Variables

Copy `.env.example` to `.env`. The minimum for local dev:

```env
# Database - persistent local PGlite default
DATABASE_URL=pglite:

# WebAuthn / Passkey
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:5173

# Better Auth
BETTER_AUTH_SECRET=any-random-string-for-local-dev
BETTER_AUTH_URL=http://localhost:3001

# API
API_PORT=3001
CORS_ORIGIN=http://localhost:5173,http://localhost:5174

# TEE (mock mode for local dev)
TEE_MODE=development
DEV_SEALING_KEY=openkey-dev-sealing-key-32bytes!
```

Optional (features degrade gracefully without these):

| Variable | Purpose |
|----------|---------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth sign-in |
| `APPLE_CLIENT_ID` / `APPLE_TEAM_ID` / `APPLE_KEY_ID` / `APPLE_PRIVATE_KEY` | Sign in with Apple (all four are required before the button is shown) |
| `APPLE_APP_BUNDLE_IDENTIFIER` | Optional native-app audience for Apple ID tokens |
| `RESEND_API_KEY` | Email OTP delivery (without it, OTPs print to console) |
| `ADMIN_API_KEY` | Protect admin endpoints (OAuth client registration) |
| `INTERNAL_METRICS_TOKEN` | Protect internal metrics endpoints |
| `TINYCLOUD_BOOTSTRAP_HOST` | TinyCloud node used to bootstrap a user's canonical signer space |
| `VITE_CONSOLE_ORIGIN` | Optional console origin. Leave unset locally to keep the account and console journey on one Vite host; set to `https://console.openkey.so` in production. |
| `VITE_ACCOUNT_ORIGIN` | Set alongside `VITE_CONSOLE_ORIGIN` only when testing the split-host journey locally (the portless example supplies both). |
| `CONSOLE_ORIGIN` | API better-auth allowlist for session-bearing calls from the console origin; the portless example sets it. |

For production-shaped local host boundaries, copy `.env.portless.example` to
`.env.portless` and run `bun dev:portless`. It enables wildcard routing for the
single Vite server, so `openkey.localhost` and `console.openkey.localhost` both
resolve locally; the example API CORS allowlist includes both origins.
If a portless proxy is already running, restart it after enabling
`PORTLESS_WILDCARD=1` so it picks up wildcard host routing.

### Social sign-in callbacks

Register these exact production callback URLs with each provider:

- Google: `https://api.openkey.so/api/auth/callback/google`
- Apple: `https://api.openkey.so/api/auth/callback/apple`

For Apple, `APPLE_CLIENT_ID` is the web Services ID, not the native bundle ID.
OpenKey signs a short-lived ES256 client-secret JWT at runtime using
`APPLE_TEAM_ID`, `APPLE_KEY_ID`, and the `.p8` value in `APPLE_PRIVATE_KEY`;
escaped `\n` sequences are accepted. `APPLE_APP_BUNDLE_IDENTIFIER` is optional
and is only needed for native Apple ID-token audiences. Apple does not accept
`localhost`, plain HTTP, or callbacks without a valid TLS certificate, so local
testing must use an HTTPS domain such as the portless profile and that exact
HTTPS callback must be registered in Apple Developer.

Apple returns an email address only on the first authorization. OpenKey relies
on Better Auth's persisted provider account and account-linking records on
later sign-ins; do not delete those records or require later callbacks to carry
email. If users can choose Apple's private relay, register OpenKey's outbound
sender domain (including the Resend envelope-sender domain) in Certificates,
Identifiers & Profiles → Sign in with Apple for Email Communication, and
configure matching SPF and DKIM records.

## Scripts

### Dev Servers

| Command | Description |
|---------|-------------|
| `bun dev` | Start API + Web together via Turbo (local, no Docker) |
| `bun dev:api` | API only (Hono on port 3001, watch mode) |
| `bun dev:web` | Web only (SvelteKit on port 5173) |

### Database

| Command | Description |
|---------|-------------|
| `bun db:push` | Push schema to local database |
| `bun db:generate` | Regenerate Prisma client |
| `bun db:studio` | Open Prisma Studio GUI |
| `bun db:migrate:dev` | Create a new migration |

### Docker

| Command | Description |
|---------|-------------|
| `bun docker:up` | Start optional PostgreSQL + API containers (not needed for local development or smoke tests) |
| `bun docker:down` | Stop containers |
| `bun docker:restart` | Restart containers |
| `bun docker:logs` | Tail container logs |
| `bun docker:rebuild` | Rebuild and restart API image after code changes |

### OAuth Client Management

| Command | Description |
|---------|-------------|
| `bun oauth:register` | Register a new OAuth client |
| `bun oauth:list` | List registered OAuth clients |

## Project Structure

```
openkey/
├── apps/
│   ├── api/            # Hono API server (bun, port 3001)
│   │   └── src/
│   │       ├── index.ts    # Server entry point
│   │       └── auth.ts     # better-auth configuration
│   └── web/            # SvelteKit frontend (port 5173)
│       └── src/
│           ├── lib/        # Shared utilities, auth client
│           └── routes/     # SvelteKit pages
├── packages/
│   ├── db/             # Prisma schema and client
│   │   └── prisma/
│   │       └── schema.prisma
│   ├── tee/            # TEE/dstack key sealing library
│   ├── types/          # Shared TypeScript types
│   └── sdk/            # OpenKey client SDK
├── docker-compose.yml      # Local dev (PostgreSQL + API)
├── docker-compose.prod.yml # Production (Phala Cloud)
├── Dockerfile              # API Docker image
└── .env.example
```

## Architecture Notes

### API (apps/api)

- Runs TypeScript directly via Bun — **no bundling**. Bundling breaks better-auth's AsyncLocalStorage request tracking.
- Auth is handled by [better-auth](https://better-auth.com) with passkey, email OTP, Google OAuth, and OAuth provider plugins.
- New users automatically get a TEE-sealed Ethereum key on account creation.
- In dev mode (`TEE_MODE=development`), the TEE client uses deterministic mock keys instead of dstack.

### Web (apps/web)

- SvelteKit 5 with Tailwind CSS 4.
- Deployed to Cloudflare Pages.
- `VITE_API_URL` env var points to the API. Defaults to `http://localhost:3001` in dev.

### Database

- PostgreSQL with Prisma ORM (v5.22).
- Schema is at `packages/db/prisma/schema.prisma`.
- Local dev uses `db push` (no migration history). See CLAUDE.md for production migration strategy.

## End-to-End Demo Testing

The demo app (`demo/`) is a sample third-party app that authenticates users via OpenKey's OAuth 2.1 flow with PKCE.

### 1. Start all services

```bash
# Terminal 1: PGlite-backed API
bun db:push
bun dev:api

# Terminal 2: OpenKey web frontend
bun dev:web

# Terminal 3: Register OAuth client + start demo app
bun oauth:register --name "Demo App" --redirect-uri "http://localhost:5174/callback" --env .env
# Copy the outputted clientId into demo/.env:
#   VITE_OPENKEY_HOST=http://localhost:3001
#   VITE_CLIENT_ID=ok_your_client_id_here
cd demo && bun install && bun dev
```

Services:
- **API**: http://localhost:3001 (Docker)
- **Web**: http://localhost:5173 (OpenKey frontend)
- **Demo**: http://localhost:5174 (sample third-party app)

### 3. Create an OpenKey account

1. Go to http://localhost:5173
2. Click **Create an account**
3. Enter your email and verify with the OTP code (printed to API console in dev mode)
4. Register a passkey when prompted (Touch ID, etc.)

An Ethereum key is automatically generated and sealed with the mock TEE.

### 4. Run the OAuth flow

1. Go to http://localhost:5174 (demo app)
2. Click **Sign in with OpenKey**
3. The demo app redirects to the OpenKey authorization endpoint
4. If not logged in, you'll be redirected to the login page — sign in with your passkey
5. The **consent page** appears showing the demo app's name and requested permissions
6. Click **Allow**
7. You're redirected back to the demo app's callback with an authorization code
8. The demo app exchanges the code for tokens (access token, ID token, refresh token)
9. You're now authenticated in the demo app

### 5. Sign a message (optional)

Once authenticated in the demo app, you can sign a message using your OpenKey-managed Ethereum key via the signing widget.

### OAuth flow summary

```
Demo (5174)                    OpenKey Web (5173)            API (3001)
    │                                │                           │
    ├─ "Sign in with OpenKey" ───────────────────────────────────┤
    │  (generates PKCE challenge)    │                           │
    │                                │     /oauth2/authorize     │
    │                                │                           │
    │                                ├── /auth/login (passkey)   │
    │                                ├── /oauth/consent          │
    │                                │   "Allow" / "Deny"        │
    │                                │                           │
    │  /callback?code=xxx ◄──────────────────────────────────────┤
    │                                │                           │
    ├─ POST /oauth2/token ───────────────────────────────────────┤
    │  (code + code_verifier)        │                           │
    │                                │                           │
    │◄─ access_token + id_token ─────────────────────────────────┤
    │                                │                           │
    └─ Authenticated                 │                           │
```

## Troubleshooting

### `bunx prisma` fails with P1012 / datasource error

`bunx prisma` pulls the latest Prisma (v7+) which is incompatible. All `db:*` scripts use the project's local Prisma binary. Always use `bun db:push` instead of `bunx prisma db push`.

### API crashes with AsyncLocalStorage / "No request state found"

The API must run TypeScript directly — not from a bundled `dist/` file. The Dockerfile and `bun dev:api` both handle this correctly. If you see this error, rebuild the Docker image: `docker compose up -d --build api`.
