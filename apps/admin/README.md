# OpenKey Admin Dashboard

SvelteKit admin application for managing OAuth applications and developer billing.

## Features

- View and manage registered OAuth clients
- Monitor developer accounts and Stripe subscriptions
- Built with SvelteKit 2.x + Svelte 5
- Deployed on Cloudflare Pages
- Uses Neon serverless driver for database access

## Development

```bash
# Install dependencies (from monorepo root)
bun install

# Run dev server
bun run dev --filter @openkey/admin

# Build for production
bun run build --filter @openkey/admin
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

- `DATABASE_URL` - Neon database connection string
- `API_URL` - OpenKey API URL (default: https://api.openkey.so)
- `STRIPE_SECRET_KEY` - Stripe API key
- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret
- `PUBLIC_API_URL` - Public API URL for client-side requests
- `PUBLIC_APP_URL` - Main OpenKey app URL (default: https://openkey.so)

## Database Access

The admin app uses Prisma with the Neon serverless driver for Cloudflare Pages compatibility. Database client is configured in `src/lib/server/db.ts`.

The Prisma schema is shared from `packages/db/prisma/schema.prisma`.

## Deployment

Deploys automatically to Cloudflare Pages on push to main branch.

## Routes

- `/` - Dashboard home
- `/apps` - OAuth applications list
- `/billing` - Developer billing and subscriptions
- `/api/*` - Server API endpoints (placeholder)
