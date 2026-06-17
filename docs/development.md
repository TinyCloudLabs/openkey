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
CORS_ORIGIN=http://localhost:5173

# TEE (mock mode for local dev)
TEE_MODE=development
DEV_SEALING_KEY=openkey-dev-sealing-key-32bytes!
```

Optional (features degrade gracefully without these):

| Variable | Purpose |
|----------|---------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth sign-in |
| `RESEND_API_KEY` | Email OTP delivery (without it, OTPs print to console) |
| `ADMIN_API_KEY` | Protect admin endpoints (OAuth client registration) |
| `INTERNAL_METRICS_TOKEN` | Protect internal metrics polling endpoint |

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
