# OpenKey web (SvelteKit) — local/Compose-only image.
#
# Production deploys this app to Cloudflare Pages (see CLAUDE.md); there is
# no standalone Node server for it there. This Dockerfile exists only so a
# fully local Docker Compose stack (e.g. the Buzz Nostr-signing integration
# harness) can serve the same build output with SvelteKit's own
# adapter-agnostic `vite preview` server — it reads `.svelte-kit/output`
# directly, independent of what `svelte.config.js`'s adapter does with it
# afterwards, so this works unmodified against the Cloudflare adapter.
# Debian (glibc), not -alpine (musl): `vite preview` on the Cloudflare
# adapter spins up the local Workers runtime (`workerd`, via miniflare),
# whose prebuilt `@cloudflare/workerd-linux-*` binary is glibc-linked.
# Under musl/Alpine, spawning it fails with a misleading `ENOENT` (the ELF
# interpreter it needs isn't present, not the file itself).
FROM oven/bun:1.2-slim AS base
WORKDIR /app

FROM base AS deps
COPY package.json bun.lock ./
COPY apps/web/package.json ./apps/web/
RUN bun install --ignore-scripts

FROM deps AS builder
COPY apps/web ./apps/web
# Baked into the client bundle at build time (see apps/web/src/lib/api.ts,
# apps/web/src/lib/auth-client.ts). Must point at wherever the OpenKey API
# container is reachable from the *browser*, not the Docker network.
ARG VITE_API_URL
ENV VITE_API_URL=${VITE_API_URL}
RUN cd apps/web && bun run build

FROM base AS runner
ENV NODE_ENV=production
RUN groupadd --system --gid 1001 openkey \
    && useradd --system --uid 1001 --gid 1001 --home-dir /home/openkey \
               --create-home --shell /usr/sbin/nologin openkey
COPY --from=builder --chown=openkey:openkey /app/node_modules ./node_modules
COPY --from=builder --chown=openkey:openkey /app/apps/web ./apps/web
WORKDIR /app/apps/web
EXPOSE 5173
USER openkey
CMD ["bunx", "vite", "preview", "--host", "0.0.0.0", "--port", "5173", "--strictPort"]
