# TC-492 canonical TinyCloud key cutover

This is the release gate for replacing organization-managed TinyCloud accounts
with one canonical, user-owned OpenKey identity. It is deliberately not part of
a routine deploy. Production execution requires separate deployment authority,
a verified backup, and an operator-maintained change freeze.

## Reviewed dependency order

1. Publish the reviewed js-sdk change from TinyCloudLabs/js-sdk#393. Confirm the
   generic `tinycloud:manage-key` tests, two-reference-client identity test, and
   real TinyCloud HTTP smoke at the exact release commit.
2. Promote the reviewed OpenKey commit from TinyCloudLabs/openkey#170. Do not
   start the API deployment until the pre-cutover report and caller gate below
   are accepted.
3. Apply and verify the OpenKey migrations. The ordered expand migrations are
   `20260805_0001_canonical_tinycloud_key`,
   `20260805_0002_tinycloud_manage_key_app_preferences`,
   `20260805_0003_tinycloud_manage_key_global_preference`, and
   `20260806_0001_tinycloud_manage_key_lifecycle`. The destructive contract
   migration is `20260806_0002_remove_organization_key_custody`.
4. Deploy the reviewed OpenKey API and web commits, then run the manage-key
   OAuth/claim/signing/control smoke.
5. Promote TinyCloudLabs/coordinationOS#15 only after the OpenKey smoke is green.
   Run fresh login, invite write/read, shared/exclusive denial, and persisted
   restore before declaring the cutover complete.

Record the exact commit, container/image digest, migration checksums, database
report, and smoke output for every step. A branch name or `latest` tag is not a
release identifier.

## Pre-cutover gates

1. Freeze OpenKey database writes that create or archive keys and freeze OAuth
   client configuration changes.
2. Take a restorable database backup and perform a restore rehearsal.
3. Capture the read-only deterministic report:

   ```bash
   DATABASE_URL="$PRODUCTION_DATABASE_URL" bun run db:cutover:report > tc492-pre.json
   ```

   The report contains counts plus a SHA-256 digest, never user IDs, key IDs, or
   addresses. On a pre-expand database, `phase` is `pre-expand`; after the
   canonical column is present it is `expanded`. The same unchanged database
   must produce the same `candidateDigestSha256`.
4. Stop if `selectionConflictCount`, `predictedAddressChangeCount`, or
   `canonicalWithoutEligibleKeyCount` is non-zero. After the expand migration,
   also stop unless `unassignedCandidateCount` is zero and
   `existingCanonicalCount` equals `deterministicCandidateCount`.
5. Run `bun test scripts/tc-488-caller-inventory.test.ts`. Review production
   route-hit telemetry for managed-account, tenant-account, management-
   credential, eject, `keys`, and `tinycloud:session` traffic over the agreed
   compatibility window. Repository search cannot discover external callers;
   any active hit blocks the destructive migration.
6. Export counts of tenant-custody rows and attach the disposition approval.
   `tenantCustodyKeyCount` is expected to be deleted by the contract migration;
   it must never include a user's selected canonical personal key.

## Compatibility window

The generic SDK retains the legacy `establishOpenKeySession` export for one SDK
release so existing browser builds continue to load while consumers move to
`establishManageKeySession`. New authorization requests must use
`tinycloud:manage-key`; `tinycloud:session` is not a fallback authority. The
removed organization custody and eject APIs have no post-cutover compatibility
mode. Their external caller count must be zero before the contract migration.

## Migration and verification

Only a separately authorized operator may run the migration command. The
production preflight intentionally blocks automatic migration until this
runbook has been completed. Apply the reviewed migration chain during the
freeze, then run:

```bash
DATABASE_URL="$PRODUCTION_DATABASE_URL" bun run db:migrate:verify-guards
DATABASE_URL="$PRODUCTION_DATABASE_URL" bun run db:cutover:report > tc492-post.json
DATABASE_URL="$PRODUCTION_DATABASE_URL" bun run db:migrate:verify-schema
```

The post report must have zero unassigned candidates, selection conflicts,
predicted address changes, canonical-without-eligible-key rows, and tenant
custody keys. Its candidate digest and eligible-user count must match the
accepted pre-cutover selection. Separately verify that OAuth clients,
redirect URIs, consent rows, developer organizations, and memberships remain;
only organization key custody is removed.

The protected internal metrics endpoint reports aggregate canonical-resolution,
app-grant, and signing-decision counts. It must not emit bearer tokens, SIWE
messages, user IDs, key IDs, or addresses. Alert on missing canonical identities,
signing denial spikes, and any non-zero migration conflict report.

## Promotion smoke

Use two distinct OAuth clients and one user. Both clients must receive the same
canonical DID and `applications` space, while using distinct client IDs,
redirect URIs, authorization codes, tokens, and session stores. Confirm:

- one consented, cookie-free signing request creates each fresh TinyCloud
  session without showing a signature;
- byte-accurate KV write/read succeeds from both apps in the same canonical
  space;
- disabling an app and exclusive mode prevent new signing immediately;
- shared mode resumes only after the user's explicit app grant/consent;
- CoordinationOS reads existing canary and invite paths after login and after a
  reload, with no signer call during a valid restore.

## Rollback boundary

Before the destructive contract migration, roll back application commits and
leave the canonical column/data in place; it is additive and the partial unique
index continues preventing a second canonical key.

After `20260806_0002_remove_organization_key_custody`, never deploy old code or
recreate tenant custody tables as a partial rollback. Use a forward fix. If a
full rollback is unavoidable, restore the entire verified pre-cutover database
backup and the matching pre-cutover OpenKey image together while writes remain
frozen, then re-run the deterministic report. A rollback is invalid if it
creates a second canonical key, changes a canonical address, or silently grants
an organization signing authority.
