# Agent Development Notes

This document gives coding agents enough local context to work in OpenKey without guessing about
repo boundaries, test expectations, deployment assumptions, or cross-repo integration impact.

## Project Context

`TinyCloudLabs/openkey` is an OAuth-compatible identity provider for Ethereum keys secured by TEE.
Users authenticate with passkeys or social/email flows, and OpenKey signs messages with keys that
are generated and sealed inside the TEE path.

Important areas:

- `apps/api`: Hono API server.
- `apps/web`: SvelteKit web app.
- `packages/db`: Prisma schema and database client.
- `packages/sdk`: `@openkey/sdk` for app developers.
- `packages/tee`: TEE abstraction and dstack integration.
- `packages/types`: shared TypeScript types.
- `docs`: deployment, OAuth, and TEE documentation.

Auth, key custody, OAuth, WebAuthn, and TEE behavior are security-sensitive. Treat these as
production protocol concerns, not demo flows.

## Related Repositories

- `TinyCloudLabs/tinycloud-node`
  - Local path in the tinycloud-dev workspace: `repositories/tinycloud-node`.
  - Related through TinyCloud identity, DID, signing, and protocol integration behavior.
  - Check TinyCloud Node when OpenKey changes affect TinyCloud auth, SIWE, passkeys, sessions, or
    client-facing identity behavior.
- `TinyCloudLabs/js-sdk`
  - Local path in the tinycloud-dev workspace: `repositories/js-sdk`.
  - Contains TinyCloud SDK packages and OpenKey example apps.
  - Check the SDK when OpenKey changes affect app integration, OAuth client behavior, or examples.

## Build And Testing

Install dependencies with Bun from the repo root:

```bash
bun install
```

Common checks:

```bash
bun run build
bun run lint
bun run typecheck
```

Local development:

```bash
bun db:push
bun dev
```

Local development uses PGlite by default. Use Postgres only when production-parity database behavior
matters:

```bash
bun docker:up
DATABASE_URL=postgresql://openkey:openkey@localhost:5432/openkey bun db:push
```

For WebAuthn flows from non-localhost origins, use the portless setup documented in `README.md`:

```bash
bun dev:portless
```

## Debugging

- Check `.env.example` and `.env.portless.example` before inventing new env names.
- Keep PGlite, Postgres, API, web, and browser logs separate so failures can be tied to one layer.
- Confirm `TEE_MODE` before debugging signing or sealing behavior.
- For production-like TEE work, verify the Phala/dstack path instead of relying only on development
  mocks.
- For OAuth bugs, capture the authorize, token, userinfo, and revoke paths independently.
- For WebAuthn bugs, verify the origin, RP ID, HTTPS/localhost requirements, and passkey state.
- Never print or commit production secrets, OAuth credentials, private keys, deploy keys, or
  `.env.prod` values.

## Additional Context

- Keep changes narrow and security-focused.
- Public auth or SDK behavior needs compatibility thinking: docs, SDK examples, OAuth clients, and
  TinyCloud integration should move together.
- Database schema changes should include Prisma migration or push guidance and production impact.
- Deployment changes should explicitly call out whether they affect Phala API deployment,
  Cloudflare Pages web deployment, or local-only development.
- When agent-facing context changes, update this document's additional notes and append a concise
  entry to `agent.changelog.md` so future agents can see what changed and why.
- PR descriptions should list security implications, env changes, deployment impact, tests run, and
  cross-repo dependencies.
