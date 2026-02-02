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
RUN bunx prisma generate --schema=./packages/db/prisma/schema.prisma

# Build packages
FROM deps AS builder
COPY . .
RUN bun run build --filter @openkey/tee
RUN bun run build --filter @openkey/api

# Production image
FROM base AS runner
ENV NODE_ENV=production
ENV TEE_MODE=production

# Copy built files and package.json for module resolution
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/apps/api/package.json ./apps/api/
COPY --from=builder /app/packages/tee/dist ./packages/tee/dist
COPY --from=builder /app/packages/tee/package.json ./packages/tee/
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma
COPY --from=builder /app/packages/db/package.json ./packages/db/
COPY --from=builder /app/package.json ./

# Generate Prisma client
RUN bunx prisma generate --schema=./packages/db/prisma/schema.prisma

EXPOSE 3001

CMD ["bun", "run", "apps/api/dist/index.js"]
