# OpenKey API Dockerfile
FROM oven/bun:1.2-alpine AS base
WORKDIR /app

# Install dependencies
FROM base AS deps
# Install build tools for native modules (better-sqlite3)
RUN apk add --no-cache python3 make g++
COPY package.json bun.lock ./
COPY apps/api/package.json ./apps/api/
COPY packages/tee/package.json ./packages/tee/
COPY packages/db/package.json ./packages/db/
COPY packages/db/prisma ./packages/db/prisma
COPY packages/types/package.json ./packages/types/
RUN bun install --ignore-scripts
# Generate Prisma client (skipped by --ignore-scripts)
RUN bun node_modules/.bin/prisma generate --schema=./packages/db/prisma/schema.prisma

# Build packages
FROM deps AS builder
COPY . .
RUN bun run build --filter @openkey/db
RUN bun run build --filter @openkey/tee
RUN bun run build --filter @openkey/api

# Production image
FROM base AS runner
ENV NODE_ENV=production
ENV TEE_MODE=production

# Copy source files - no bundling to preserve AsyncLocalStorage
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/api/src ./apps/api/src
COPY --from=builder /app/apps/api/package.json ./apps/api/
COPY --from=builder /app/packages/tee/dist ./packages/tee/dist
COPY --from=builder /app/packages/tee/package.json ./packages/tee/
COPY --from=builder /app/packages/db/dist ./packages/db/dist
COPY --from=builder /app/packages/db/src/generated ./packages/db/src/generated
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma
COPY --from=builder /app/packages/db/package.json ./packages/db/
COPY --from=builder /app/package.json ./

EXPOSE 3001

CMD ["bun", "run", "apps/api/src/index.ts"]
