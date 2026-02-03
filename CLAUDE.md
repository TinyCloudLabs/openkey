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
| `bun run db:push:prod` | Push schema to prod (uses `.env.prod`) - **use for quick schema sync** |
| `bun run db:migrate:dev` | Create a new migration (local dev) |
| `bun run db:migrate:prod` | Deploy pending migrations to prod (uses `.env.prod`) |
| `bun run db:baseline` | Baseline existing prod DB for migration history (one-time setup) |
| `bun run db:generate` | Regenerate Prisma client |
| `bun run db:studio` | Open Prisma Studio (local) |
| `bun run db:studio:prod` | Open Prisma Studio (prod, uses `.env.prod`) |

### Migration Strategy

**Current state**: Using `db push` for both dev and prod (no migration history).

**Moving to production migrations**:
1. Run `bun run db:baseline` once to create initial migration from current schema and mark it as applied in prod
2. After baselining, use `bun run db:migrate:dev` to create new migrations locally
3. Use `bun run db:migrate:prod` to deploy migrations to prod
4. Never use `db push` on prod after baselining - it bypasses migration history

**Important**: `prisma migrate dev` will ask to reset the database if it detects drift. Use `db push` if you just need to sync schema without migration history. Only use `migrate dev` when you're ready to track migrations properly.

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

- **Version**: `1.5.0-beta.10` (pinned across monorepo)
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
