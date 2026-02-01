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

#### Required Phala Environment Variables

Set these in the Phala Cloud Dashboard under your CVM's **Encrypted Env**:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `BETTER_AUTH_SECRET` | 32+ character random secret for session encryption |
| `BETTER_AUTH_URL` | `https://api.openkey.so` |
| `WEBAUTHN_RP_ID` | `openkey.so` |
| `WEBAUTHN_ORIGIN` | `https://openkey.so` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `TEE_MODE` | `production` |
| `RESEND_API_KEY` | Resend API key for emails |
| `API_PORT` | `3001` |
| `CORS_ORIGIN` | `https://openkey.so` |
| `CLOUDFLARE_API_TOKEN` | For SSL certificate management |
| `DSTACK_GATEWAY_DOMAIN` | Phala gateway domain |
| `CERTBOT_EMAIL` | Email for Let's Encrypt |

#### Trigger Conditions

Deployments trigger on pushes to `main` that modify:
- `apps/api/**`
- `packages/**`
- `Dockerfile`
- `docker-compose.prod.yml`

Or manually via **Actions > Deploy API to Phala Cloud > Run workflow**.

### Manual Deploy

1. Build the Docker image:
   ```bash
   docker build -t skgbafa/openkey-api:v1.0.x .
   docker push skgbafa/openkey-api:v1.0.x
   ```

2. Update `docker-compose.prod.yml` with the image tag

3. Deploy via Phala CLI:
   ```bash
   phala deploy -c docker-compose.prod.yml -n openkey-api
   ```

4. Verify TEE attestation is working:
   ```bash
   curl https://api.openkey.so/api/keys/YOUR_KEY_ID/quote
   # Should return { "quote": "...", "isInTee": true }
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
