# Deployment Guide

OpenKey is deployed as two services:
- **API**: Runs on Phala dstack (TEE-secured compute)
- **Web**: Runs on Cloudflare Pages

## API Deployment (Phala dstack)

The API must run inside a TEE to secure private keys. Phala dstack provides AMD SEV-SNP enclaves with the `@phala/dstack-sdk`.

### Prerequisites

- Docker image of the API
- Phala dstack account

### Environment Variables

```env
DATABASE_URL="postgresql://..."
BETTER_AUTH_SECRET="..."
TEE_MODE="production"
WEBAUTHN_RP_ID="openkey.so"
```

### Deploy

1. Build the Docker image:
   ```bash
   docker build -t openkey-api .
   ```

2. Push to a container registry accessible by Phala

3. Deploy via Phala dstack dashboard or CLI

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
