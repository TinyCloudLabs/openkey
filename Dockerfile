# OpenKey API Dockerfile
FROM oven/bun:1.2-alpine@sha256:0841c588f6304300baf1d395ae339ce09a6e18c4b6a7cdd4fddcbdb87a2f096a AS base
WORKDIR /app

# Install dependencies
FROM base AS deps
# Install build tools for native modules (better-sqlite3)
RUN apk add --no-cache python3 make g++
COPY package.json bun.lock ./
COPY apps/api/package.json ./apps/api/
COPY packages/tee/package.json ./packages/tee/
COPY packages/db/package.json ./packages/db/
COPY packages/capability-review/package.json ./packages/capability-review/
COPY packages/delegation-code-fields/package.json ./packages/delegation-code-fields/
COPY packages/db/prisma ./packages/db/prisma
COPY scripts/generate-prisma.ts ./scripts/generate-prisma.ts
COPY packages/types/package.json ./packages/types/
# prisma.config.ts (root + packages/db) supplies datasource.url from
# DATABASE_URL for `prisma migrate deploy` — omitting them makes the
# `deps` target unusable for `bun run db:migrate:apply` (openkey-migrate
# in docker-compose.openkey.yml), which needs only this stage.
COPY prisma.config.ts ./
COPY packages/db/prisma.config.ts ./packages/db/
RUN bun install --ignore-scripts
# Generate Prisma client (skipped by --ignore-scripts)
RUN bun run scripts/generate-prisma.ts

# Build packages
FROM deps AS builder
COPY . .
# Keep the runtime fingerprint synchronized with committed migration files.
RUN bun test packages/db/src/schema-contract.test.ts
# Prisma's schema engine occasionally panics on a schema it has just parsed
# ("panicked at psl/parser-database/..."). Retry that panic only, up to 3
# attempts; any other failure, including a real schema error, fails at once.
RUN attempt=1; \
    while :; do \
      if bun run build --filter @openkey/db >/tmp/db-build.log 2>&1; then cat /tmp/db-build.log; break; fi; \
      echo "db build attempt $attempt of 3 failed:"; cat /tmp/db-build.log; \
      if ! grep -q -E 'psl/parser-database|panicked at' /tmp/db-build.log; then echo "not the prisma panic; not retrying"; exit 1; fi; \
      if [ "$attempt" -ge 3 ]; then echo "prisma panic on all 3 attempts"; exit 1; fi; \
      attempt=$((attempt + 1)); \
    done; \
    rm -f /tmp/db-build.log
RUN bun run build --filter @openkey/tee
RUN bun run build --filter @openkey/capability-review
# The runtime image ships this stage's node_modules and packages/tee/dist.
# Refuse to build it if sealed-key derivation would change (TC-964).
RUN OPENKEY_KAT_REQUIRE_DIST=1 bun test packages/tee/tests/dstack-key-derivation.kat.test.ts
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
COPY --from=builder /app/packages/capability-review/dist ./packages/capability-review/dist
COPY --from=builder /app/packages/capability-review/package.json ./packages/capability-review/
COPY --from=builder /app/packages/delegation-code-fields/src ./packages/delegation-code-fields/src
COPY --from=builder /app/packages/delegation-code-fields/package.json ./packages/delegation-code-fields/
COPY --from=builder /app/package.json ./

# Commit the image was built from; reported by GET /health as `commit`.
ARG GIT_SHA=
ENV GIT_SHA=${GIT_SHA}

EXPOSE 3001

CMD ["bun", "run", "apps/api/src/index.ts"]
