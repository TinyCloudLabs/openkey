# Development Setup

## Prerequisites

- [Bun](https://bun.sh) 1.1.0+
- [Docker](https://docs.docker.com/get-docker/) (for PostgreSQL and local API)

## Quick Start

```bash
# 1. Install dependencies
bun install

# 2. Set up environment
cp .env.example .env
# Edit .env with your values (see Environment Variables below)

# 3. Start PostgreSQL + API via Docker
bun docker:up

# 4. Push database schema
bun db:push

# 5. Start web frontend
bun dev:web
```

- **API** runs at `http://localhost:3001` (Docker)
- **Web** runs at `http://localhost:5173` (local Vite dev server)

## Running the API

### Option 1: Docker (recommended)

Docker Compose starts both PostgreSQL and the API:

```bash
bun docker:up        # Start db + api
bun docker:logs      # Watch logs
bun docker:restart   # Rebuild and restart
```

To rebuild the API image after code changes:

```bash
bun docker:rebuild
```

### Option 2: Local (without Docker API)

Run the API directly with Bun (still needs PostgreSQL):

```bash
bun docker:up        # Start just db (api will fail to connect to db host, but that's fine)
bun dev:api          # Run API locally with watch mode
```

Or start everything together:

```bash
bun dev              # Starts API + Web via Turbo (requires local PostgreSQL)
```

## Environment Variables

Copy `.env.example` to `.env`. The minimum for local dev:

```env
# Database - matches docker-compose.yml defaults
DATABASE_URL=postgresql://openkey:openkey@localhost:5432/openkey

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
| `OPENKEY_METRICS_READ_TOKEN` | Bearer for `/api/internal/scoreboard/*` (TC-1483); aggregate counts only |
| `NODE_STATS_URL` / `NODE_STATS_READ_TOKEN` | Node `GET /admin/stats` URL and read-only bearer, used by `/api/internal/scoreboard/protocol-users` (TC-1483). Counts owners with data beyond the automatic `account` space; account-only owners are excluded. Must be `https:`; `http://localhost`/`127.0.0.1` allowed only with `NODE_ENV=development` |
| `SCOREBOARD_EXCLUDE_USER_IDS` / `SCOREBOARD_EXCLUDE_CLIENT_IDS` | Comma-separated team/QA/agent user ids and internal OAuth client ids excluded from scoreboard counts |
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
| `bun docker:up` | Start PostgreSQL + API containers |
| `bun docker:down` | Stop containers |
| `bun docker:restart` | Restart containers |
| `bun docker:logs` | Tail container logs |
| `bun docker:rebuild` | Rebuild and restart API image after code changes |

### OAuth Client Management

| Command | Description |
|---------|-------------|
| `bun oauth:register` | Register a new OAuth client |
| `bun oauth:list` | List registered OAuth clients |

Dynamic registration at `POST /api/auth/oauth2/register` supports public PKCE clients.
When `scope` is omitted, the registration allowlist includes `openid`, `email`, `keys`,
`offline_access`, and `tinycloud:mcp`, so MCP clients can request the advertised resource
scope during authorization. Explicitly supplied scope lists stay unchanged. Registration
does not grant a token or bypass user consent; TinyCloud signing/delegation scopes are
never defaults.

Existing clients retain their stored scope allowlists. If a connector created before this
default was added returns `invalid_scope` for `tinycloud:mcp`, recreate the connector after
the API update so it registers a new client. Refreshing tools or signing in again with the
same client ID does not change its scopes.

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
- A verified email code never creates an account by itself (TC-1114). For an email with no account, `POST /api/auth/sign-in/email-otp` answers `403 NEW_ACCOUNT_CONFIRMATION_REQUIRED` with a single-use, five-minute `signupToken` bound to that email; the account is created only when the user confirms and the client posts `{ email, signupToken }` to `POST /api/auth/sign-up/email-otp`.
- Google sign-in uses verified email only. A new verified Google identity returns a five-minute, cookie-bound confirmation instead of creating an account; only `POST /api/auth/social/confirm` creates the account and session. A matching existing email does not link automatically. Sign in to that account, verify an email code through `POST /api/account/step-up/email-otp/send` and `/verify`, then link Google from Settings. The OAuth link state is also bound to that live, recently verified session at callback. Settings unlinks through `POST /api/account/social/unlink`, so an older valid session can use a fresh code without changing Better Auth's freshness policy for other routes. Unlinking is refused without a remaining usable sign-in method. A passkey sign-in does not replace the email-code step-up.
- In dev mode (`TEE_MODE=development`), the TEE client uses deterministic mock keys instead of dstack.

#### Request correlation (TC-959)

- The API accepts a hyphenated RFC UUID version 1–8 `X-Request-Id` (RFC variant `8`, `9`, `a`, or `b`), case-insensitively, and normalizes it to lowercase. Missing, malformed, combined/duplicate, nil, invalid-version, and non-RFC-variant values get a fresh UUID v4. This incoming contract is shared with Tinychat and ptx-dev so a valid v7 ID is not replaced at an OpenKey boundary. The same ID appears in the response header and typed request/error logs, including error responses.
- Typed request events include the boolean `request_id_replaced`: `true` only when a supplied header is rejected, `false` for a valid header or when an absent header causes minting. The rejected header text is never logged.
- This is untrusted correlation metadata, not an identity or authorization claim. It never replaces SIWE nonces, authorization-context tokens, native request IDs, or server-generated signing/audit IDs. Do not put user identifiers or tokens in it.
- `src/log.ts` is loaded before dependencies and wraps native fetch for the two trusted TinyCloud origins and the configured `TINYCLOUD_URL` / `TINYCLOUD_BOOTSTRAP_HOST` origins. This covers SDK-owned HTTP calls as well as direct calls without changing signed authorization headers or request bodies. Other destinations are unchanged. The ID is read from async context on each call, so cached clients and post-response work retain the correct originating request; startup/scheduled work does not send the `startup`/`scheduled` log labels as headers.
- **Redirect compatibility:** when this boundary injects an ID, default or explicit `redirect: 'follow'` becomes `redirect: 'error'`. Both cross-origin and same-origin automatic redirects reject before any second hop; this avoids native fetch forwarding the ID to an untrusted origin and avoids replaying/changing signed methods, authorization, or bodies. Explicit `manual` still returns the redirect response, and explicit `error` is unchanged, respecting init-over-Request precedence. Configure the final node URL rather than a redirecting alias. Calls without an injected ID retain native redirect behavior.
- Keep the logger import first in the API entry point. Do not bundle the API or capture a request ID in a cached client. No Vector shipping, sink configuration, or production rollout is part of this correlation change.

The test corpus `apps/api/src/__tests__/request-id-vectors.json` vendors the exact canonical N0 bytes from [`samgbafa/tinycloud-dev@76bd10752a52f179ac2a49214f488236d02f8192`](https://github.com/samgbafa/tinycloud-dev/blob/76bd10752a52f179ac2a49214f488236d02f8192/ops/logging/request-id-vectors.json), with SHA-256 `d995cd9065a9e1c51bc4d3ed041c3bf2a0363e9a04a90f1d07914437d8dd9a80`. The accompanying [request-ID contract](https://github.com/samgbafa/tinycloud-dev/blob/76bd10752a52f179ac2a49214f488236d02f8192/ops/logging/request-id.md) defines acceptance, typed replacement metadata and redirect isolation.

All 30 canonical cases run against the actual middleware. Cases whose bytes survive Fetch header parsing use loopback HTTP, including repeated/identical fields; padding and trailing-newline cases preserve the corpus's raw application-visible value at the middleware boundary because Fetch trims those bytes before dispatch. HTTP parser normalization/rejection itself is unchanged. Separate tests cover versions 2/3/5/6, raw-token/PII canaries and the actual SDK edge.

Focused regression coverage (no Docker or production services):

```bash
bun run db:generate
bun run build --filter @openkey/db --filter @openkey/tee
bun test apps/api/src/__tests__/structured-logging.test.ts apps/api/src/__tests__/delegate-complete-context-routes.test.ts
```

The tests include a real loopback HTTP `/api/delegate/complete` → pinned SDK → node `/delegate` edge, concurrent accepted/minted IDs, unchanged signed authority, and child-process stdout/stderr leak checks. The complete API suite remains `bun test apps/api/src/__tests__`.


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
# Terminal 1: PostgreSQL + API
bun docker:up
bun db:push

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

### Port 5432 conflict

If Docker can't bind port 5432, you likely have a local PostgreSQL running. Either stop it or point `DATABASE_URL` at it directly and skip `bun docker:up`.

### API crashes with AsyncLocalStorage / "No request state found"

The API must run TypeScript directly — not from a bundled `dist/` file. The Dockerfile and `bun dev:api` both handle this correctly. If you see this error, rebuild the Docker image: `docker compose up -d --build api`.
