# Deployment Guide

OpenKey is deployed as two services:
- **API**: Runs on Phala dstack (TEE-secured compute)
- **Web**: Runs on Cloudflare Pages

## API Deployment (Phala dstack)

The API must run inside a TEE to secure private keys. Phala dstack provides AMD SEV-SNP enclaves with the `@phala/dstack-sdk`.

### CI/CD (Recommended)

The release coordinator starts the API deployment manually from `main` using
`gh workflow run deploy-api.yml --ref main`; merging does not start this workflow.

#### Required GitHub Secrets

Set these in your repo's **Settings > Secrets and variables > Actions**:

| Secret | Description |
|--------|-------------|
| `DOCKER_REGISTRY_USERNAME` | Docker Hub username (e.g., `skgbafa`) |
| `DOCKER_REGISTRY_PASSWORD` | Docker Hub [access token](https://docs.docker.com/docker-hub/access-tokens/) |
| `PHALA_CLOUD_API_KEY` | From [Phala Cloud Dashboard](https://cloud.phala.network/dashboard) > Avatar > API Tokens |
| `DATABASE_URL` | Production PostgreSQL connection string used by the migration job |

Only a manual dispatch from `main` starts the serialized production API workflow;
there is no path filter that can skip a migration or runtime contract change.
The deploy fails closed when `DATABASE_URL` is absent or a migration or
security-guard verification fails. The database is migrated before the Phala
CVM is updated. Production deploys must not use `prisma db push`: schema push
does not execute tracked cutover migrations. The production deploy and one-time
baseline workflows refuse non-`main` refs and use the protected `production` environment.
Normal production deploys require the reviewed
`20260714_origin_main_schema_catchup` marker and no unresolved failed migration
rows before Prisma may apply anything.

The API container's `/health` endpoint is also its Docker health check. The
probe uses the container's `API_PORT` (default `3001`), so it checks the
actual configured listener rather than a hard-coded alternate port. Before
returning HTTP 200 it independently verifies every checksum-pinned committed
migration from the reviewed `20260714_origin_main_schema_catchup` baseline
through the candidate Prisma client, excluding only the explicitly parked
destructive TC-488 migration. A missing, unfinished, rolled-back, or
checksum-mismatched required record returns HTTP 503 with only
`{ "status": "not_ready" }`; it never exposes migration names, checksums,
database URLs, or error details. The destructive
`20260806_0002_remove_organization_key_custody` TC-488 migration is
deliberately not part of this runtime prerequisite and remains governed by its
existing explicit operator gate.

A ready response is `{ "status": "ok", "tee_mode": "production", "os_image": "unknown" }`
(or `"tee_mode": "development"` for the explicitly configured local mock).
`tee_mode` describes the configured client path: `production` selects dstack;
it does **not** establish the guest OS image, production hardening, verified
attestation, or dstack reachability. The API currently has no independently
trusted OS-image identity, so `os_image` remains `unknown` in both modes.
A known image requires trusted guest metadata and a reviewed identity mapping,
not `TEE_MODE`, the SDK version, a past CVM observation, or HTTP query/header
values. The legacy `tee` response field is removed; JSON-body consumers must
migrate to `tee_mode` with these configuration-only semantics. HTTP-status
health probes and the not-ready response are unchanged.

A ready `/health` response also reports `version` (the `@openkey/api` package version) and `commit` (the `GIT_SHA` build argument, `unknown` when unset).

While the separately authorized TC-488 destructive custody cutover remains
pending, production deploy permits these reviewed additive migrations:
`20260814_0001_share_device_authorization`,
`20261005_0001_delegation_code_broker`,
`20261007_0001_tinycloud_native_foundation`, and
`20261007_0002_native_preparation_host`,
`20261007_0003_tinycloud_native_token_guard`,
`20261012_0001_signin_polish_hints_branding`,
`20261012_0002_native_session_proof_jti`,
`20261015_0001_google_link_step_up`, and
`20261016_0001_prepared_siwe_handoff`. The last migration only adds a table,
indexes, and a foreign key; it does not alter existing tables. The deploy verifies their frozen
SQL checksums, the exact pending set, the baseline marker, and the physical
pre-cutover custody table before temporarily excluding only the destructive
TC-488 migration from a normal `prisma migrate deploy`. It then verifies
the recorded checksums and physical schema, including the native preparation
host column, sign-in hint and branding columns, and consent-withdrawal
triggers. Any other pending migration fails closed. Once TC-488 is applied,
deployments return to the full migration and schema-drift verification path.

The `20261015_0001_google_link_step_up` migration runs as one transaction. It
adds `session.lastEmailOtpAt` and the unique index
`account_providerId_accountId_key` on `account("providerId", "accountId")`.
Before `prisma migrate deploy`, the deploy script counts duplicate
`("providerId", "accountId")` groups in `account` and stops when the count is
above zero; the message carries only the count. Before the deploy window, run
the same count against production:

```sql
SELECT count(*) FROM (
  SELECT 1 FROM "account" GROUP BY "providerId", "accountId" HAVING count(*) > 1
) AS duplicate_groups;
```

If the migration fails with `P3018`, nothing was applied: count the duplicate
groups with the query above, resolve them, run
`prisma migrate resolve --rolled-back 20261015_0001_google_link_step_up`, and
redeploy. Never use `--applied`. The history then holds two rows for this
migration (the rolled-back attempt and the finished one); the post-deploy check
uses the finished row.

A failed history row can still occur when `prisma migrate deploy` is run by
hand without the count, or when a duplicate is inserted between the count and
the index build. The previous image keeps serving and the schema is unchanged,
and `P3009` stops every later deploy until that row is resolved as above.

Rollback is an image-only redeploy: the previous image does not read the added
column and ignores it. Redeploying an older commit stops at the migration step
with "Production contains migration history absent from this checkout",
because `_prisma_migrations` already records this migration. To revert the
schema, together with a code revert that removes the migration directory:

```sql
BEGIN;
DROP INDEX IF EXISTS "account_providerId_accountId_key";
ALTER TABLE "session" DROP COLUMN IF EXISTS "lastEmailOtpAt";
UPDATE "_prisma_migrations" SET rolled_back_at = now()
  WHERE migration_name = '20261015_0001_google_link_step_up' AND rolled_back_at IS NULL;
COMMIT;
```

The public native PAR endpoint validates the full request before allocating a
row. An alert records when valid PAR volume reaches 10,000 requests per minute
per API process; it never rejects a PAR request. There is no per-client rate limit:
`client_id` is public and could let an anonymous caller deny sign-in to that
client. Unresolved PAR rows are deleted shortly after their 90-second
`request_uri` window closes. Anonymous resolved rows are deleted after their
10-minute request expiry; user-bound rows remain available for consent and
audit. Authorize re-entry and consent prepare, approve,
and deny instead have separate per-process budgets keyed by the verified OpenKey
session's user ID. The Phala gateway and ingress path has no authenticated HTTP client-IP
header in this deployment; `CF-Connecting-IP` and `X-Forwarded-For` can be
supplied by a caller, so PAR does not use either for rate limiting. Per-source
fairness requires an authenticated network source at the ingress boundary.

The token-protected `/api/internal/metrics` response includes `originRefusals`, a process-local count by route template and refusal reason. Counts reset when the API process restarts and contain no Origin values.

Organization OAuth applications are owned by the organization, not their
creator. Organization administrators manage them through the tenant console,
including confidential-client secret rotation; personal OAuth clients remain
manageable by their creating user.

The canonical-key/organization-custody cutover is governed by the
[TC-492 release runbook](./tc-492-canonical-key-cutover.md). It requires a
read-only deterministic pre/post report and separate deployment authority; it
must not be inferred from approval or merge of the implementation PR.

#### One-time migration baseline for the legacy production database

Use this procedure only for the existing production database that was created
with `prisma db push` and therefore has no Prisma migration history. Do not run
it for a new database or one that already records the tracked migrations.

1. Take and verify a production database backup.
2. Confirm that no API deployment or schema change is running.
3. In GitHub Actions, run **Baseline Production Migrations** against the
   protected `production` environment from the `main` branch. The workflow
   refuses every other source ref.
4. Enter `baseline-origin-main-44305b4` exactly when prompted.
5. Wait for schema comparison, baseline recording, migration deployment, and
   raw SQL guard verification to finish.
6. Rerun **Deploy API to Phala Cloud** if the merge-triggered deploy previously
   stopped because the database was not baselined.

The baseline job compares production with a checksummed snapshot of the exact
Prisma schema that origin/main commit `44305b4` deployed using `db push`. A
checksummed inventory marks only migrations whose complete effects are already
present. In particular, the absent `user_encryption_key` migration remains
pending and is applied normally by `prisma migrate deploy`. An idempotent
reconciliation migration aligns the one physical index name that differs
between the historical SQL and db-push schemas.

The inventory recognizes both reviewed `0_init` record checksums committed by
OpenKey: the current migration checksum and the earlier checksum from commit
`9c9ce4f`. This exception applies only to the stored `0_init` history row; the
current on-disk migration must still match its current checksum. No arbitrary or
additional historical checksums are accepted.

The recovery path also accepts exactly one reviewed interrupted state: a
successful `0_init`, a successful `20260303_add_user_encryption_key`, and an
unresolved `20260628_add_auto_sign_enabled` failure with zero applied steps.
Before changing migration history it verifies a separate checksummed physical
schema snapshot containing the newly created encryption-key table and the
already-existing auto-sign column. It then resolves only that failed migration
as applied, records the remaining db-push-equivalent migrations, and writes the
catchup completion marker. Any other history or physical schema is rejected.

Schema drift, a changed snapshot or inventoried migration, an unexpected or
incomplete migration record, or a mismatched confirmation stops the job. The
baseline itself does not modify application tables; after it is recorded,
`prisma migrate deploy` applies every pending migration and a final schema diff
plus raw SQL guard verification must pass.

Both production workflows generate the Prisma client before running database
inspection scripts. `bun install` alone does not generate the gitignored client.

#### Required Phala Environment Variables

Set these in the Phala Cloud Dashboard under your CVM's **Encrypted Env**:

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `BETTER_AUTH_SECRET` | 32+ character random secret for session encryption |
| `BETTER_AUTH_URL` | `https://api.openkey.so` |
| `APPROVAL_RESULT_RETENTION_SECONDS` | `600` (10 min, Sam 2026-10-29), fixed in production compose for collecting approved CLI results. The result deadline is capped by the signed grant expiry. |
| `OAUTH_DYNAMIC_CLIENT_REGISTRATION` | Keep `true` for MCP clients that register automatically; set `false` only as an emergency disable |
| `OAUTH_VALID_AUDIENCES` | Comma-separated additional OAuth resource URLs; code includes the exact broad `https://mcp.tinycloud.xyz/mcp` and public `https://mcp.tinycloud.xyz/chatgpt/mcp` audiences. Preserve any additional configured resources. |
| `WEBAUTHN_RP_ID` | `openkey.so` |
| `WEBAUTHN_ORIGIN` | `https://openkey.so` |
| `CONSOLE_ORIGIN` | `https://console.openkey.so` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `APPLE_SIGN_IN_ENABLED` | Hardcoded `true` in production Compose; Apple is offered only when the four Apple credentials below are also set (TC-1188) |
| `APPLE_NATIVE_SIGN_IN_ENABLED` | Hardcoded `false`; stock native ID-token sign-in is permanently disabled |
| `APPLE_CLIENT_ID` | Apple web Services ID (not a bundle identifier) |
| `APPLE_TEAM_ID` | Apple Developer Team ID |
| `APPLE_KEY_ID` | Sign in with Apple private-key ID |
| `APPLE_PRIVATE_KEY` | Apple `.p8` ES256 private key (literal or escaped newlines) |
| `APPLE_APP_BUNDLE_IDENTIFIERS` | Reserved comma-separated audiences for a future PAR-bound native flow; not active |
| `APPLE_WEBHOOK_AUDIENCE` | Primary App ID (`so.openkey`) that Apple addresses server-to-server notifications to; the webhook is not found while it is unset or Apple sign-in is disabled |
| `TEE_MODE` | Not read from the env: `docker-compose.prod.yml` hardcodes `production`, and the API refuses to start otherwise (TC-966) |
| `RESEND_API_KEY` | Resend API key for emails |
| `API_PORT` | `3001` |
| `CORS_ORIGIN` | `https://openkey.so,https://console.openkey.so` |
| `ADMIN_API_KEY` | Bearer token for organization plan fixtures and app registration |
| `INTERNAL_METRICS_TOKEN` | Bearer token for `/api/internal/metrics`, including counts-only `/native-renewals` by public OAuth client ID; unset = 503, missing/wrong bearer = 401. `GET /api/internal/metrics` also returns a counts-only `users` block (TC-2356): total accounts, one count per exclusive bucket in precedence order (`team_by_wallet`, `qa_prefix` (local part starts with `tcqa-` or the older `qa-`), `internal_team_domain`, `disposable_mail_domain`, `internal_agent_or_qa`, `test_or_throwaway_domain`, `plus_addressed`, `test_like_name`, `never_completed_signup`, `explicit_exclusions`, `bot_like`), `real` (what is left), `realActive` (`d1`/`d7`/`d30`, by last session update), `realNew7d`, and `apps` (`{name, real7d, real30d}`: distinct real accounts with an OAuth access token in the window, by client display name); `users` is `null` if that query fails. |
| `OPENKEY_METRICS_READ_TOKEN` | Separate bearer for `/api/internal/scoreboard/*`. Grants **aggregate counts only** (`GET /protocol-users` -> `{count}`, `GET /app-users` -> `{total, active7d}`); neither endpoint takes input, so the token cannot be used to look up addresses or accounts. `/protocol-users` is capped at 30 calls/min per process (429) and audit-logged (status and count only). Unset = 503 |
| `NODE_STATS_URL` / `NODE_STATS_READ_TOKEN` | Full URL of the node's read-only `GET /admin/stats` (TC-1482) and its read-only bearer. OpenKey fetches the owner addresses from it for `/protocol-users` (owners with data beyond the automatic `account` space; account-only owners are excluded). The URL must be `https:`; the response is capped at 16 MiB and concurrent calls share one node request; unset or failing node = 503, never a partial count. Expected response: `200 {"owners": ["0x<40 hex>", ...]}` |
| `SCOREBOARD_EXCLUDE_USER_IDS` / `SCOREBOARD_EXCLUDE_CLIENT_IDS` | Comma-separated team/QA/agent user ids and internal OAuth client ids excluded from scoreboard counts. The user-id list also feeds the `explicit_exclusions` bucket of `/api/internal/metrics` `users`. |
| `SCOREBOARD_EXCLUDE_ADDRESSES` | Comma-separated EVM wallet addresses of team members (compared lowercase; invalid entries are ignored). Each is mapped through `ethereum_keys.address` to its account, so every key of that person is excluded: the `team_by_wallet` bucket of `/api/internal/metrics` `users`, checked first. Addresses are never returned or logged. |
| `SCOREBOARD_DISPOSABLE_DOMAINS` | Comma-separated extra disposable-mail domains (a leading `@` or `*.` is accepted; subdomains match; entries that are not domains are ignored), added to the built-in list (mailinator, guerrillamail family, sharklasers, mail.tm/mail.gw and our mail.tm domains fldubai.com and maxxspace.com, maildrop, 10minutemail, yopmail, temp-mail/tempmail, trashmail, getnada, Mailpit/MailHog/MailCatcher). Feeds the `disposable_mail_domain` bucket. Mail.tm rotates domains: add the new one here, no code deploy needed; applies after the API container is recreated with the new environment. |
| `OPENKEY_NATIVE_RENEW_DISABLED` | `true` or `1` refuses native delegation renewals with HTTP 400 `consent_required`; unset, empty, or any other value leaves renewals enabled. Changes apply after the API container is recreated with the new environment. |
| `TINYCLOUD_BOOTSTRAP_HOST` | Trusted TinyCloud node used for canonical user-key bootstrap |
| `CLOUDFLARE_API_TOKEN` | For SSL certificate management |
| `DSTACK_GATEWAY_DOMAIN` | Phala gateway base domain (e.g. `dstack-pha-prod5.phala.network`); the ingress CNAMEs `api.openkey.so` to `gateway.<base>` (never `_.<base>`, which Android cannot resolve) |
| `CERTBOT_EMAIL` | Email for Let's Encrypt |

`WEBAUTHN_ORIGIN` is the account browser origin and is required in production.
Browser requests to sensitive account routes require an `Origin` matching that
account origin, whether authenticated by cookie or bearer. Bearers without an
`Origin` remain refused; cookie requests without an `Origin` retain their
existing behavior. Sensitive authentication routes require an account origin.
Native delegation preparation, approval, denial, and delegation-code creation
also require the account origin. Organization and tenant-console routes continue
to accept the configured console origin.
If `CONSOLE_ORIGIN` is unset in production, it defaults to
`https://console.openkey.so`; that console origin remains accepted only on
console-facing organization routes, unless it is also `WEBAUTHN_ORIGIN`.

TC-2212 request IDs, sealed-body digests and request deadlines are bound by
OpenKey's server-side consent context. The owner's signature covers the canonical
delegation's target, permissions and grant expiry, not the server-authored result
wrapper. The approval-request content key goes to OpenKey's own API to verify the
sealed request; it is not forwarded to the links store.

Google and Apple must be configured with these exact production return URLs:

- `https://api.openkey.so/api/auth/callback/google`
- `https://api.openkey.so/api/auth/callback/apple`

Google's explicit account-linking and new-account confirmation change the API
and web together. Deploy both in one window after the reviewed migration is
ready; the migration adds the session email-code timestamp and a unique
provider/account identity index. This change does not enable Apple sign-in.

Apple web sign-in is enabled in production (TC-1188). The production Compose
file pins `APPLE_SIGN_IN_ENABLED=true`; the provider is still offered only when
`APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID` and `APPLE_PRIVATE_KEY` are
all set in the encrypted env. To turn Apple off, set the Compose value back to
`false` and redeploy, or remove a credential from the encrypted env.

The API mints an ES256 client-secret JWT for each Apple token exchange or
revocation, valid for at most five minutes. The `.p8` key remains API-only and
must never be set as a `VITE_` variable. The web callback trusts only the
exchanged ID token's verified email, issuer, audience and lifetime; Apple's
unsigned `user.email` is ignored. Returning identities use `(apple, sub)`,
including callbacks without an email claim. New accounts need the existing
cookie-bound social confirmation; linking and unlinking need current-session
email OTP step-up. Apple refresh tokens are encrypted with their issuing
Services ID. A confirmed Apple account sends a mailbox notice; its first
email-OTP sign-in requires a separate linked-provider review before a session.
Google accounts retain the existing email-OTP behavior while Apple is off.
Refusing Apple review locks the account. A locked account's existing sessions
(cookie and bearer), OAuth refresh and access tokens, native grant renewals
and signing routes are refused (TC-1231).

Account deletion needs a fresh step-up: a verification by a passkey that counts
for step-up when the user has one, otherwise a deletion-purpose email code
(`POST /api/account/step-up/email-otp/{send,verify}` with
`purpose: "delete_account"`). After the deletion commits, each stored Apple
refresh token is revoked with its issuing client ID, retried three times; a
revoke that still fails logs `auth_apple_revoke_failed` and never restores the
account.

Apple server-to-server notifications arrive at
`POST https://api.openkey.so/api/webhooks/apple` (register it on the primary App
ID `so.openkey`). The endpoint is not found unless Apple sign-in is enabled and
`APPLE_WEBHOOK_AUDIENCE` is set to the primary App ID. Notifications are
verified against Apple's cached JWKS (RS256, issuer, audience, `iat` within 24
hours) and applied once per `jti`, recorded in `apple_notification`. Only an
invalid notification is answered 400; an unavailable Apple key set or a
processing failure is answered 503 with nothing recorded, so Apple's retry is
applied. `consent-revoked` and `account-deleted` end the user's sessions,
native grants and OAuth tokens and wipe the stored Apple tokens, but keep the
OpenKey account, keys and Apple link. A non-MCP JWT access token already issued
has no stored row and stays valid until its own expiry (at most five minutes);
MCP tokens end with their session. `email-disabled` and `email-enabled` only
flag a relay address as undeliverable.

Pending Apple confirmations and failed revocations use the OpenKey-owned
`apple_social_continuation` table, not Better Auth's OTP verification table.
The expiry/revocation worker starts even when Apple sign-in is disabled. If
disabling Apple after use, retain the issuing Services ID, Team ID, key ID,
private key, and Better Auth decryption secrets until pending grants are
revoked or safely linked; removing them leaves encrypted retry rows uncleared.

Apple rejects localhost, non-HTTPS domains and invalid TLS, so live provider
testing requires a registered HTTPS hostname. Before production, register
the outbound sender and envelope-sender domains used by Resend in Apple's
private email relay settings, with matching SPF and DKIM.

#### Passkey enrolment and removal (TC-1198)

A session alone can't add or remove a passkey. Better Auth's
`/api/auth/passkey/generate-register-options`, `verify-registration` and
`delete-passkey` (and the embed proxy under `/api/passkey/*`) answer 403
`PASSKEY_STEP_UP_REQUIRED`, with the accepted `methods`, unless the current
session has one of these:

- a fresh (five-minute) assertion by one of the user's passkeys that counts for
  step-up, through `POST /api/account/step-up/passkey/{options,verify}`;
- for enrolment, a single-use email proof: a `passkey_register` code on the
  email step-up endpoints, or the session's own creation by a verified email
  code (email sign-in, email sign-up, the Apple mailbox review) or by a
  confirmed social sign-up, within five minutes;
- for removing a passkey that doesn't count, a single-use `passkey_remove` code.

Each passkey records `enrolledVia` (`legacy`, `account_creation`,
`email_sign_in`, `email_step_up`, `passkey_step_up`), `enrolledStepUpAt` and
`countsForStepUp`. A passkey enrolled under a passkey assertion counts. One
enrolled under an email proof counts only when the user has no passkey that
counts yet, so an email inbox alone never adds step-up authority to a passkey
user. Removing a passkey that counts needs a passkey assertion. Passkey
freshness (deletion, and any future link or unlink step-up) is accepted only
from a passkey that counts. Migration
`20261110_0002_passkey_enrolment_provenance` marks every existing passkey
`legacy` with `countsForStepUp = true`.

**Support path: a user who lost every passkey that counts.** They can still
sign in with an email code and enrol new passkeys, but those don't count, so
they can't delete the account or remove the old passkeys themselves. Support
verifies the owner out of band first. Then, in one transaction, support deletes
the lost passkey rows (`DELETE FROM "passkey" WHERE "userId" = $1 AND id = ANY($2)`).
With no passkey that counts, the user can delete with an email code, and the
next passkey they enrol under an email proof counts again. Apart from the
post-deploy step below, never set `countsForStepUp` by hand.

A user whose Apple relay address Apple reports undeliverable is offered no
email method; until they turn forwarding back on, only a passkey that counts
can authorize a passkey change.

**Deploy window.** `deploy-api.yml` applies migrations before the new image is
live, so passkeys the old image enrols in between get `enrolledVia = NULL` and
don't count. That fails closed. To give them the same treatment as the
backfill, run this once the new image serves traffic, with the time it went live:
`UPDATE "passkey" SET "countsForStepUp" = true, "enrolledVia" = 'legacy' WHERE "enrolledVia" IS NULL AND "createdAt" < $1`.

#### Trigger Conditions

The release coordinator manually dispatches **Actions > Deploy API to Phala Cloud >
Run workflow** from `main` (`gh workflow run deploy-api.yml --ref main`).
The `production-api` concurrency group serializes runs; non-`main` refs are refused.
Run `gh workflow run deploy-api.yml --ref main -f preflight_only=true` first.
This uses the same production environment and concurrency guard but performs
only provider reads and a read-only database transaction. Its output records
the complete app CVM inventory, immutable rollback image, changed environment
key names, public audience expressions, and reviewed pending migrations. No
encrypted environment values or user records are printed. The existing
single-CVM deployment requires exactly one stable running app instance.
Resolve unexpected live configuration differences before the deploy; do not
overwrite operator changes. Re-run this inspection after rollout to confirm
the image and migration state and check `unclassified_passkeys`. A zero count
means the passkey deploy-window backfill above is unnecessary.

The 2026-11-13 preflight found the Courier canary audience
`https://courier-canary-1e7fgu.tinycloud.xyz/mcp` appended to the live compose.
The tracked compose preserves that existing audience, including when
`OAUTH_VALID_AUDIENCES` is supplied through the encrypted environment. Removing
it belongs to a separately authorized canary retirement, not this release.

For a combined web/API prepared-handoff release, merging to `main` can publish
the Pages `/delegate` page before the manual API deployment. The v2 page first
checks the authenticated, non-cached `/api/delegate/handoffs/available` route;
against an older API, it displays "not available yet" without submitting a
claim or using v1 signing. The existing v1 flow is unaffected. Immediately
dispatch `deploy-api.yml` after the merge: its migration step runs
`bun run db:migrate:deploy:production` before deploying the Phala CVM. Confirm
`/health` is ready and verify the v2 claim flow before relying on v2 sign-in.
To require API-before-web with this main-only workflow, split the API/database
and web changes into separate merges.

### Manual Deploy

1. Build the Docker image:
   ```bash
   docker build -t skgbafa/openkey-api:v1.0.x .
   docker push skgbafa/openkey-api:v1.0.x
   ```
   The API image includes the built `@openkey/capability-review` workspace
   package in its runtime stage. Details: TC-2005

2. Deploy and verify pending migrations from a trusted operator machine:
   ```bash
   bun run db:migrate:prod
   ```

3. Update `docker-compose.prod.yml` with the image tag

4. Deploy via Phala CLI:
   ```bash
   phala deploy -c docker-compose.prod.yml -n openkey-api --no-public-logs --no-public-sysinfo
   ```

5. Verify TEE attestation is working, with a signed-in session for a managed key you own:
   ```bash
   curl -H "Cookie: $OPENKEY_SESSION_COOKIE" \
     https://api.openkey.so/api/keys/YOUR_KEY_ID/quote
   # Should return 200 with "quote", "eventLog", "binding", "bindingSha256" and "inTee": true.
   # 503 {"error":"quote_unavailable"} means the TEE could not produce a quote.
   ```

6. Verify internal metrics are available to trusted callers:
   ```bash
   curl -H "Authorization: Bearer $INTERNAL_METRICS_TOKEN" \
     https://api.openkey.so/api/internal/metrics
   # Should return account and key totals plus 24h deltas.
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
   - `VITE_API_URL`: URL of your deployed API (e.g., `https://api.openkey.so`)
   - `VITE_CONSOLE_ORIGIN=https://console.openkey.so`
   - Optional, for deployments outside production (staging MCP, extra
     TinyCloud nodes): `VITE_DELEGATE_CALLBACK_URLS` (comma-separated app
     callback endpoints such as `https://mcp.staging.example/connect/callback`)
     and `VITE_DELEGATE_NODE_ORIGINS` (comma-separated HTTPS node origins).
     Production needs neither for the first-party MCP services: the exact
     `/connect/callback` and `/chatgpt/connect/callback` endpoints on
     `https://mcp.tinycloud.xyz` and the `node`/`tee.node.tinycloud.xyz` nodes
     are built in. The public ChatGPT candidate needs both this web registration
     and the API audience update deployed; neither establishes ChatGPT acceptance. See
     `docs/share-device-authorization.md` ("Ordinary `/delegate` links").

4. Deploy

Attach both `openkey.so` and `console.openkey.so` custom domains to this Pages
deployment. The console hostname only serves the `/console` route tree, while
account-host console URLs redirect permanently to the console hostname.

## DNS Configuration

| Domain | Points To |
|--------|-----------|
| `openkey.so` | Cloudflare Pages (account web) |
| `console.openkey.so` | Cloudflare Pages (same web deployment; `/console` routes only) |
| `api.openkey.so` | Phala dstack (API) |
| `auth.openkey.so` | CNAME to `openkey.so` (for WebAuthn RP ID) |

## Verifying TEE Security

After deployment, verify the API is running in a real TEE. The quote route
needs a signed-in session for a managed key you own; send a fresh nonce:

```bash
curl -H "Cookie: $OPENKEY_SESSION_COOKIE" \
  "https://api.openkey.so/api/keys/YOUR_KEY_ID/quote?nonce=$(openssl rand -hex 32)"
```

A 200 response has `quote` (hex TDX quote), `eventLog`, `binding`,
`bindingSha256`, `address` and `"inTee": true`. The API only checks that the
binding is present in the quote; you must verify the quote. Follow all eight
steps in `docs/tee-overview.md` ("Attestation Endpoint"): quote signature and
TCB status, TDATTRIBUTES with the debug bit clear, OS image measurements,
RTMR3 replay (hash of the full app-compose manifest, app id, key provider),
REPORTDATA read from the verified quote, and the binding's type, version,
nonce and address.
