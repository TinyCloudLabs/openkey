# OpenKey

## Repository Structure

Monorepo with Bun workspaces and Turbo:
```
openkey/
├── apps/
│   ├── api/          # Hono API server (better-auth, passkeys, TEE)
│   └── web/          # SvelteKit frontend (openkey.so)
├── packages/
│   ├── db/           # Prisma schema and client
│   ├── tee/          # TEE/dstack key sealing
│   ├── types/        # Shared types
│   └── sdk/          # OpenKey client SDK
```

## Database & Migrations

Schema lives at `packages/db/prisma/schema.prisma`.

### Scripts

| Command | Description |
|---------|-------------|
| `bun run db:push` | Push schema to local dev database |
| `bun run db:migrate:dev` | Create a new migration (local dev) |
| `bun run db:migrate:prod` | Deploy and verify pending migrations in prod (uses `.env.prod`) |
| `bun run db:migrate:deploy:production` | Require the reviewed baseline marker, then deploy and verify |
| `bun run db:migrate:verify` | Verify the TC-488 cutover and schema drift guards |
| `bun run db:migrate:verify-schema` | Verify the deployed database matches the Prisma schema |
| `bun run db:baseline:prod` | Verify and record the reviewed legacy baseline (one-time, explicit confirmation required) |
| `bun run db:generate` | Regenerate Prisma client |
| `bun run db:studio` | Open Prisma Studio (local) |
| `bun run db:studio:prod` | Open Prisma Studio (prod, uses `.env.prod`) |

### Migration Strategy

Production uses tracked migrations. The deploy workflow fails if
`DATABASE_URL` is absent, runs `prisma migrate deploy`, and verifies the raw
SQL custody guards before updating the Phala CVM. Never use `db push` in
production: it does not execute triggers, deferred constraints, or other raw
migration SQL.

The production deploy preflight also requires a successful
`20260714_origin_main_schema_catchup` baseline marker and no unresolved failed
migrations. This prevents an automatic deploy from running the historical
migration chain against a non-empty legacy database. Local and fresh-database
migration commands remain ungated.

An existing production database created by `db push` must use the manual
**Baseline Production Migrations** workflow exactly once. It first compares the
database to a checksummed snapshot of the exact origin/main schema used by
`db push`, and refuses to record migration history if it finds drift. See
`docs/deployment.md` for the operator procedure and typed confirmation.

**Important**: `prisma migrate dev` may ask to reset a development database if
it detects drift. `db:push` remains a local-development command only.

## Deployment

### API (Phala Cloud / dstack TEE)
- Docker image: `ghcr.io/tinycloudlabs/openkey-api` (public GHCR package; images deployed before TC-3837 are on Docker Hub as `skgbafa/openkey-api`)
- The release coordinator dispatches `.github/workflows/deploy-api.yml` manually from `main`.
- Image tagged with git SHA and `latest`, but the compose sent to Phala names it only by digest (`ghcr.io/tinycloudlabs/openkey-api@sha256:…`); `scripts/compose-image-digests.ts` fails a deploy whose compose has any tag-only or `${VAR}` image, the deploy checks the digest pulls without credentials, and the push carries a GitHub build provenance attestation (TC-3837)
- After each deploy, `.github/workflows/publish-api-compose.yml` publishes the app-compose the CVM measured as `app-compose.<compose_hash>.json` on the release `openkey-api-<commit>` (TC-3837)
- Deployed to Phala Cloud CVM named `openkey-api`
- Manual deploy: `bun run phala:env` (uses `.env.prod`)

### Web (Cloudflare Pages)
- SvelteKit app at `apps/web/`
- Deploys automatically on push

### Post-deploy: Share sender sign-in
- `.github/workflows/share-sender-smoke.yml` runs `scripts/share-sender-smoke.sh` after every web deploy and every successful API deploy. A new throwaway mail.tm OpenKey account signs in to production Share, creates a share and opens it (TC-994). Run the script by hand as part of any manual deploy smoke. A failure means OpenKey broke an embedding app; its JSON report names the failing request.

## Auth Architecture (better-auth)

- **Version**: `^1.5.5` (across monorepo, except `@better-auth/cli` which is at `1.5.0-beta.13`)
- **Plugins**: passkey, emailOTP, jwt, oauthProvider
- **Important**: API runs TypeScript directly with Bun (no bundling) to preserve AsyncLocalStorage context. Bundling breaks better-auth's request state tracking.

### OAuth callback URLs
When using `authClient.signIn.social()`, always use absolute URLs for `callbackURL` since the auth client's `baseURL` points to the API (`api.openkey.so`), not the web frontend:
```typescript
// Correct - absolute URL
callbackURL: `${window.location.origin}/auth/register?step=passkey`

// Wrong - resolves to api.openkey.so
callbackURL: '/auth/register?step=passkey'
```

### Environment Detection
`isDev` checks both `NODE_ENV` and `TEE_MODE`:
```typescript
const isDev = process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';
```

## API Tests

`.github/workflows/api-tests.yml` runs `bun test apps/api/src/__tests__` in one process on every PR and push to `main` (after `bun run db:generate` and building `@openkey/db` and `@openkey/tee`). bun's `mock.module()` is process-wide and `mock.restore()` does not undo it, so never call it directly in an API test: use `mockModules()` or `replaceModules()` from `apps/api/src/__tests__/mock-module.ts`, and import a route under test with a file-specific query string (`'../routes/keys?my-test' as string`) (TC-928).

The same workflow's `renewal-lease-postgres` job runs `apps/api/src/__tests__/renewal-lease-stop.integration.test.ts` and `apps/api/src/__tests__/email-otp-verify-race.integration.test.ts` with `OPENKEY_TEST_POSTGRES_URL` pointing at a throwaway Postgres service, so their lock and race cases (which PGlite's single connection cannot show) run in CI. Locally, set `OPENKEY_TEST_POSTGRES_URL` to a server where the test may create and drop a database (TC-2946). Both files run on PGlite in the main job as well; each spawns itself in a child process per engine, because they load `@openkey/db` and Better Auth for real.

The order of files in that run differs between machines, so state one file leaves behind can break whichever file runs after it (TC-2969). `bunfig.toml` preloads `apps/api/src/__tests__/end-background-work.ts`, which after every test ends the TinyCloud setup that test left running in the background (a late result, or a retry 5, 15 or 45 seconds on), so none of it can log, call the background observer or start a retry during a later test. Assert on background work inside the test that started it. Process-wide counters, such as the origin refusal counts in `log.ts`, hold every earlier file's entries: a test that asserts on all of them gives the code under test its own instance, loaded under a file-specific query (`'../log?my-test' as string`).

## Environment Files

- `.env` - Local development
- `.env.prod` - Production secrets (not committed). Required keys: `DATABASE_URL`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `RESEND_API_KEY`, `BETTER_AUTH_SECRET`, `ADMIN_API_KEY`, `CORS_ORIGIN`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, `BETTER_AUTH_URL`, `CLOUDFLARE_API_TOKEN`. `TEE_MODE` is hardcoded to `production` in `docker-compose.prod.yml`; the API refuses to start unless it is `production`, or `development` with `NODE_ENV` unset, `development` or `test` (TC-966)

## Common Commands

```bash
bun run dev              # Start all services
bun run dev:api          # API only
bun run dev:web          # Web only
bun run oauth:register   # Register an OAuth client
bun run oauth:list       # List OAuth clients
```

## Versioning

Classify compatibility accurately. For stable packages (1.0.0 and later), incompatible public API changes require a `major` changeset with migration notes, or a compatibility path. Use `minor` for compatible features and `patch` for compatible fixes. Follow the documented pre-1.0 policy for 0.x packages. Preparing a changeset does not authorize publishing: actual major version bumps and releases retain maintainer sign-off. Agents do not manufacture `approve-major-release` commits. See `agent.dev.md`.
## Agent clients

No Claude bias in what we build: products must not assume one AI vendor. The CLI, skills, guides and SDKs work the same in every agent client (Claude Code, Codex, Gemini CLI, Cursor and others). Install skills, configs and instructions where each client expects them, following its conventions, never only under Claude paths such as `~/.claude`. Test with more than one client.

## Evidence and delivery

Check the working commit and current upstream before declaring a feature absent or blocked. Saved memory and historical plans are context, not new authorization requirements. Cite the applicable code or active requirement, its scope, and what would resolve a blocker. Honor authorization already given for the task; continue independent authorized work when one step cannot proceed.

Review test updates with the behavior change in the same PR. Explain changed expectations and replacement coverage; do not duplicate obsolete tests to avoid a line-edit gate. Separate storage encryption, key scope, execution trust and outbound authorization. A limitation in one layer does not prohibit unrelated work. Distinguish implemented, merged, released and deployed.
