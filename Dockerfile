# OpenKey API Dockerfile
FROM oven/bun:1.1-alpine AS base
WORKDIR /app

# Install dependencies
FROM base AS deps
COPY package.json bun.lockb ./
COPY apps/api/package.json ./apps/api/
COPY packages/tee/package.json ./packages/tee/
COPY packages/db/package.json ./packages/db/
COPY packages/types/package.json ./packages/types/
RUN bun install --frozen-lockfile

# Build packages
FROM deps AS builder
COPY . .
RUN bun run build --filter @openkey/tee
RUN bun run build --filter @openkey/api

# Production image
FROM base AS runner
ENV NODE_ENV=production
ENV TEE_MODE=production

# Copy built files
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/packages/tee/dist ./packages/tee/dist
COPY --from=builder /app/packages/db/prisma ./packages/db/prisma
COPY --from=builder /app/package.json ./

# Generate Prisma client
RUN bunx prisma generate --schema=./packages/db/prisma/schema.prisma

EXPOSE 3001

CMD ["bun", "run", "apps/api/dist/index.js"]
