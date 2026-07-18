# OpenKey

## Repository Structure

Monorepo with Bun workspaces and Turbo:
```
openkey/
├── apps/
│   ├── api/          # Hono API server (better-auth, passkeys, TEE)
│   └── web/          # SvelteKit frontend (openkey.so)
├── packages/
│   ├── db/           # Prisma schema and client
│   ├── tee/          # TEE/dstack key sealing
│   ├── types/        # Shared types
│   └── sdk/          # OpenKey client SDK
```

## Database & Migrations

Schema lives at `packages/db/prisma/schema.prisma`.

### Scripts

| Command | Description |
|---------|-------------|
| `bun run db:push` | Push schema to local dev database |
| `bun run db:migrate:dev` | Create a new migration (local dev) |
| `bun run db:migrate:prod` | Deploy and verify pending migrations in prod (uses `.env.prod`) |
| `bun run db:migrate:deploy:production` | Require the reviewed baseline marker, then deploy and verify |
| `bun run db:migrate:verify` | Verify managed-account migrations and raw SQL security guards |
| `bun run db:migrate:verify-schema` | Verify the deployed database matches the Prisma schema |
| `bun run db:baseline:prod` | Verify and record the reviewed legacy baseline (one-time, explicit confirmation required) |
| `bun run db:generate` | Regenerate Prisma client |
| `bun run db:studio` | Open Prisma Studio (local) |
| `bun run db:studio:prod` | Open Prisma Studio (prod, uses `.env.prod`) |

### Migration Strategy

Production uses tracked migrations. The deploy workflow fails if
`DATABASE_URL` is absent, runs `prisma migrate deploy`, and verifies the raw
SQL custody guards before updating the Phala CVM. Never use `db push` in
production: it does not execute triggers, deferred constraints, or other raw
migration SQL.

The production deploy preflight also requires a successful
`20260714_origin_main_schema_catchup` baseline marker and no unresolved failed
migrations. This prevents an automatic deploy from running the historical
migration chain against a non-empty legacy database. Local and fresh-database
migration commands remain ungated.

An existing production database created by `db push` must use the manual
**Baseline Production Migrations** workflow exactly once. It first compares the
database to a checksummed snapshot of the exact origin/main schema used by
`db push`, and refuses to record migration history if it finds drift. See
`docs/deployment.md` for the operator procedure and typed confirmation.

**Important**: `prisma migrate dev` may ask to reset a development database if
it detects drift. `db:push` remains a local-development command only.

## Deployment

### API (Phala Cloud / dstack TEE)
- Docker image: `skgbafa/openkey-api`
- CI: `.github/workflows/deploy-api.yml` triggers on push to `main` (paths: `apps/api/**`, `packages/**`, `Dockerfile`)
- Image tagged with git SHA and `latest`
- Deployed to Phala Cloud CVM named `openkey-api`
- Manual deploy: `bun run phala:env` (uses `.env.prod`)

### Web (Cloudflare Pages)
- SvelteKit app at `apps/web/`
- Deploys automatically on push

## Auth Architecture (better-auth)

- **Version**: `^1.5.5` (across monorepo, except `@better-auth/cli` which is at `1.5.0-beta.13`)
- **Plugins**: passkey, emailOTP, jwt, oauthProvider
- **Important**: API runs TypeScript directly with Bun (no bundling) to preserve AsyncLocalStorage context. Bundling breaks better-auth's request state tracking.

### OAuth callback URLs
When using `authClient.signIn.social()`, always use absolute URLs for `callbackURL` since the auth client's `baseURL` points to the API (`api.openkey.so`), not the web frontend:
```typescript
// Correct - absolute URL
callbackURL: `${window.location.origin}/auth/register?step=passkey`

// Wrong - resolves to api.openkey.so
callbackURL: '/auth/register?step=passkey'
```

### Environment Detection
`isDev` checks both `NODE_ENV` and `TEE_MODE`:
```typescript
const isDev = process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';
```

## Environment Files

- `.env` - Local development
- `.env.prod` - Production secrets (not committed). Required keys: `DATABASE_URL`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `RESEND_API_KEY`, `BETTER_AUTH_SECRET`, `ADMIN_API_KEY`, `CORS_ORIGIN`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, `BETTER_AUTH_URL`, `TEE_MODE`, `CLOUDFLARE_API_TOKEN`

## Common Commands

```bash
bun run dev              # Start all services
bun run dev:api          # API only
bun run dev:web          # Web only
bun run oauth:register   # Register an OAuth client
bun run oauth:list       # List OAuth clients
```
