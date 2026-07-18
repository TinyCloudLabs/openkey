# Deployment Guide

OpenKey is deployed as two services:
- **API**: Runs on Phala dstack (TEE-secured compute)
- **Web**: Runs on Cloudflare Pages

## API Deployment (Phala dstack)

The API must run inside a TEE to secure private keys. Phala dstack provides AMD SEV-SNP enclaves with the `@phala/dstack-sdk`.

### CI/CD (Recommended)

The API deploys automatically via GitHub Actions when changes are pushed to `main`.

#### Required GitHub Secrets

Set these in your repo's **Settings > Secrets and variables > Actions**:

| Secret | Description |
|--------|-------------|
| `DOCKER_REGISTRY_USERNAME` | Docker Hub username (e.g., `skgbafa`) |
| `DOCKER_REGISTRY_PASSWORD` | Docker Hub [access token](https://docs.docker.com/docker-hub/access-tokens/) |
| `PHALA_CLOUD_API_KEY` | From [Phala Cloud Dashboard](https://cloud.phala.network/dashboard) > Avatar > API Tokens |
| `DATABASE_URL` | Production PostgreSQL connection string used by the migration job |

The deploy fails closed when `DATABASE_URL` is absent or a migration or
security-guard verification fails. The database is migrated before the Phala
CVM is updated. Production deploys must not use `prisma db push`: schema push
does not execute the raw SQL triggers and deferred custody checks in the
managed-account migrations. Both manual deploys and the one-time baseline
workflow refuse non-`main` refs and use the protected `production` environment.

#### One-time migration baseline for the legacy production database

Use this procedure only for the existing production database that was created
with `prisma db push` and therefore has no Prisma migration history. Do not run
it for a new database or one that already records managed-account migrations.

1. Take and verify a production database backup.
2. Confirm that no API deployment or schema change is running.
3. In GitHub Actions, run **Baseline Production Migrations** against the
   protected `production` environment from the `main` branch. The workflow
   refuses every other source ref.
4. Enter `baseline-origin-main-44305b4` exactly when prompted.
5. Wait for schema comparison, baseline recording, migration deployment, and
   raw SQL guard verification to finish.
6. Rerun **Deploy API to Phala Cloud** if the merge-triggered deploy previously
   stopped because the database was not baselined.

The baseline job compares production with a checksummed snapshot of the exact
Prisma schema that origin/main commit `44305b4` deployed using `db push`. A
checksummed inventory marks only migrations whose complete effects are already
present. In particular, the absent `user_encryption_key` migration remains
pending and is applied normally by `prisma migrate deploy`. An idempotent
reconciliation migration aligns the one physical index name that differs
between the historical SQL and db-push schemas.

Schema drift, a changed snapshot or inventoried migration, an unexpected or
incomplete migration record, or a mismatched confirmation stops the job. The
baseline itself does not modify application tables; after it is recorded,
`prisma migrate deploy` applies every pending migration and a final schema diff
plus raw SQL guard verification must pass.

#### Required Phala Environment Variables

Set these in the Phala Cloud Dashboard under your CVM's **Encrypted Env**:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `BETTER_AUTH_SECRET` | 32+ character random secret for session encryption |
| `REGISTRATION_INTENT_SECRET` | Separate 32+ character secret for signing short-lived managed-registration intents |
| `BETTER_AUTH_URL` | `https://api.openkey.so` |
| `WEBAUTHN_RP_ID` | `openkey.so` |
| `WEBAUTHN_ORIGIN` | `https://openkey.so` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `TEE_MODE` | `production` |
| `RESEND_API_KEY` | Resend API key for emails |
| `API_PORT` | `3001` |
| `CORS_ORIGIN` | `https://openkey.so` |
| `ADMIN_API_KEY` | Bearer token for organization plan fixtures, server credentials, and app registration |
| `INTERNAL_METRICS_TOKEN` | Bearer token for internal metrics and the revocation/webhook workers |
| `TINYCLOUD_BOOTSTRAP_HOST` | Trusted TinyCloud node used for account bootstrap and tenant-parent delegation revocation |
| `CLOUDFLARE_API_TOKEN` | For SSL certificate management |
| `DSTACK_GATEWAY_DOMAIN` | Phala gateway domain |
| `CERTBOT_EMAIL` | Email for Let's Encrypt |

#### Managed-account workers

Schedule authenticated POST requests to these internal endpoints. They are
idempotent and may run repeatedly; without them, custody transfer still commits
but TinyCloud revocation and lifecycle webhook delivery remain pending.

- `/api/internal/metrics/managed-account-revocations/run`
- `/api/internal/metrics/webhooks/run`

Use `Authorization: Bearer $INTERNAL_METRICS_TOKEN` for both. Do not expose the
token to tenant applications or the web frontend.

#### Trigger Conditions

Deployments trigger on pushes to `main` that modify:
- `apps/api/**`
- `packages/**`
- `Dockerfile`
- `docker-compose.prod.yml`
- the production migration scripts

Or manually via **Actions > Deploy API to Phala Cloud > Run workflow**.

### Manual Deploy

1. Build the Docker image:
   ```bash
   docker build -t skgbafa/openkey-api:v1.0.x .
   docker push skgbafa/openkey-api:v1.0.x
   ```

2. Deploy and verify pending migrations from a trusted operator machine:
   ```bash
   bun run db:migrate:prod
   ```

3. Update `docker-compose.prod.yml` with the image tag

4. Deploy via Phala CLI:
   ```bash
   phala deploy -c docker-compose.prod.yml -n openkey-api
   ```

5. Verify TEE attestation is working:
   ```bash
   curl https://api.openkey.so/api/keys/YOUR_KEY_ID/quote
   # Should return { "quote": "...", "isInTee": true }
   ```

6. Verify internal metrics are available to trusted callers:
   ```bash
   curl -H "Authorization: Bearer $INTERNAL_METRICS_TOKEN" \
     https://api.openkey.so/api/internal/metrics
   # Should return account and key totals plus 24h deltas.
   ```

## Web Deployment (Cloudflare Pages)

The SvelteKit frontend deploys to Cloudflare Pages using the `@sveltejs/adapter-cloudflare` adapter.

### Prerequisites

- Cloudflare account
- Wrangler CLI or Cloudflare dashboard access

### Deploy

1. Connect your repository to Cloudflare Pages

2. Configure build settings:
   - Build command: `bun run build --filter @openkey/web`
   - Build output: `apps/web/.svelte-kit/cloudflare`
   - Root directory: `/`

3. Set environment variables:
   - `PUBLIC_API_URL`: URL of your deployed API (e.g., `https://api.openkey.so`)

4. Deploy

## DNS Configuration

| Domain | Points To |
|--------|-----------|
| `openkey.so` | Cloudflare Pages (web) |
| `api.openkey.so` | Phala dstack (API) |
| `auth.openkey.so` | CNAME to `openkey.so` (for WebAuthn RP ID) |

## Verifying TEE Security

After deployment, verify the API is running in a real TEE:

```bash
# Get attestation quote
curl https://api.openkey.so/api/keys/test/quote

# Response should include:
# - "isInTee": true
# - "quote": a valid TDX quote (base64 encoded)
```

The quote can be verified against Intel/AMD attestation services to prove:
1. The code is running in a real TEE (not emulated)
2. The code hash matches the expected OpenKey image
