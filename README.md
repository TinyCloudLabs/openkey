# OpenKey

**Sign in with Ethereum keys, secured by TEE**

OpenKey is an OAuth-compatible identity provider that manages Ethereum keys inside a Trusted Execution Environment. Users authenticate with passkeys (email or Google sign-in), and their private keys never leave the TEE.

## Features

- **Passkey-first auth**: Email OTP or Google sign-in, with required passkey for login
- **TEE-secured keys**: Private keys generated and stored in Phala dstack - inaccessible to operators
- **OAuth 2.0 provider**: Third-party apps can use "Sign in with OpenKey"
- **Message signing**: Raw and EIP-191 personal_sign, EIP-712 typed data
- **Multi-key support**: Users can have multiple Ethereum addresses
- **Attestation**: Clients can verify keys are in a real TEE

## License

OpenKey is licensed under the TinyCloud Open Source License (TOSL). See [LICENSE.md](./LICENSE.md) for the full terms.

## Security

Report vulnerabilities privately through the process in [SECURITY.md](./SECURITY.md).

## Quick Start

### For App Developers

Install the SDK:

```bash
npm install @openkey/sdk
```

Add OpenKey sign-in to your app:

```typescript
import { OpenKey } from '@openkey/sdk';

const openkey = new OpenKey({
  clientId: 'your_client_id', // Register at openkey.so/admin
});

// Sign in user
const { user, accessToken } = await openkey.login();
console.log(user.ethAddress); // 0x...

// Request a signature
const { signature } = await openkey.signMessage({
  message: 'Hello from my app',
});
```

Register your app at [openkey.so/admin](https://openkey.so/admin) to get a client ID.

### For Contributors

Prerequisites:
- [Bun](https://bun.sh) 1.1+
- Docker, optional for Postgres prod-parity testing

```bash
# Clone and install
git clone https://github.com/tinycloudlabs/openkey
cd openkey
bun install

# Push database schema
bun db:push

# Start dev servers (API + Web)
bun dev
```

API runs at `http://localhost:3000`, Web at `http://localhost:5173`.

Local development uses PGlite by default, so no Postgres or Docker process is
required. The default local database lives at
`~/.local/share/openkey/dev.pglite`. To test against a real Postgres container,
run `bun docker:up` and set `DATABASE_URL` to
`postgresql://openkey:openkey@localhost:5432/openkey`.

#### HTTPS dev with portless

WebAuthn refuses non-secure origins (other than `http://localhost`). When you
need to test sign-in from a different origin (the TinyCloud CLI, an app under
test, etc.), use [portless](https://github.com/vercel-labs/portless) to expose
both servers under `https://*.localhost`:

```bash
cp .env.portless.example .env.portless
# fill in BETTER_AUTH_SECRET, GOOGLE_CLIENT_ID/SECRET, RESEND_API_KEY, …

bun db:push
bun dev:portless
```

This starts Web at `https://openkey.localhost` and API at
`https://api.openkey.localhost`. The first run will prompt portless to install
its trusted CA into your system keychain so the certificates validate.

## Architecture

```
openkey/
├── apps/
│   ├── api/          # Hono API server
│   └── web/          # SvelteKit frontend
├── packages/
│   ├── db/           # Prisma schema & client
│   ├── sdk/          # @openkey/sdk for third-party apps
│   ├── tee/          # TEE abstraction (dstack wrapper)
│   └── types/        # Shared TypeScript types
└── docs/
    ├── tee-overview.md       # How TEE security works
    └── oauth-admin-spec.md   # OAuth provider spec
```

### How Keys Are Secured

OpenKey uses [dstack](https://dstack.org/) to run inside a TEE (Trusted Execution Environment):

1. **Key generation**: Random private key created inside TEE
2. **Sealing**: Key encrypted with TEE-derived sealing key (AES-256-GCM)
3. **Storage**: Only the encrypted blob is stored in Postgres
4. **Signing**: Key decrypted inside TEE, signature returned, key never exposed

The sealing key is derived deterministically from the TEE hardware and application identity. Even if someone copies the database, they cannot decrypt the keys without running the same code in an attested TEE.

See [docs/tee-overview.md](docs/tee-overview.md) for a deep dive on TEE concepts and how dstack works.

## Authentication Flow

```
User                    OpenKey                     Your App
  │                        │                           │
  │  1. Click "Sign in"    │                           │
  │───────────────────────►│                           │
  │                        │                           │
  │  2. Email OTP or Google│                           │
  │◄──────────────────────►│                           │
  │                        │                           │
  │  3. Passkey challenge  │                           │
  │◄──────────────────────►│                           │
  │                        │                           │
  │  4. OAuth tokens       │  5. User info + address   │
  │◄───────────────────────│──────────────────────────►│
```

Users authenticate once with OpenKey, then your app receives:
- OAuth access/refresh tokens
- User's Ethereum address (`did:pkh:eip155:1:0x...`)
- Ability to request signatures (with user approval)

## API Endpoints

### OAuth

| Endpoint | Description |
|----------|-------------|
| `GET /api/oauth/authorize` | Start OAuth flow |
| `POST /api/oauth/token` | Exchange code for tokens |
| `GET /api/oauth/userinfo` | Get user profile |
| `POST /api/oauth/revoke` | Revoke tokens |

### Keys

| Endpoint | Description |
|----------|-------------|
| `POST /api/keys/generate` | Create new Ethereum key |
| `GET /api/keys` | List user's keys |
| `POST /api/keys/:id/sign` | Sign a message |
| `POST /api/keys/:id/sign-typed-data` | Sign EIP-712 typed data |
| `GET /api/keys/:id/quote` | Get TEE attestation |

## Environment Variables

```env
# Database
DATABASE_URL="pglite:" # local dev; use postgresql://... in production

# Auth (better-auth)
BETTER_AUTH_SECRET="..."
GOOGLE_CLIENT_ID="..."
GOOGLE_CLIENT_SECRET="..."

# Email (Resend)
RESEND_API_KEY="..."

# TEE
TEE_MODE="production"  # or "development" for mock
DEV_SEALING_KEY="..."  # only needed in development

# WebAuthn
WEBAUTHN_RP_ID="openkey.so"
WEBAUTHN_RP_NAME="OpenKey"
```

See `.env.example` for the full list.

## Deployment

OpenKey is designed to run on:
- **API**: Phala dstack (TEE-secured compute)
- **Web**: Cloudflare Pages

See [docs/deployment.md](docs/deployment.md) for deployment instructions.

## Tech Stack

- **Runtime**: Bun
- **API**: Hono
- **Frontend**: SvelteKit + Tailwind v4
- **Database**: PostgreSQL + Prisma
- **Auth**: better-auth (passkeys, email OTP, Google)
- **TEE**: Phala dstack (@phala/dstack-sdk)
- **Crypto**: viem (Ethereum signing)

## License

MIT
