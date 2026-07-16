# Managed accounts schema migration note

The managed-account foundation is additive and intentionally keeps the current
user-owned records usable during the transition from `DeveloperAccount` to
`Organization`.

- `EthereumKey.sealingContext` is nullable for existing rows. A null value is
  an explicit legacy marker and must resolve to
  `openkey/user/{userId}/keys`; it must not be backfilled from a custodian ID.
  New keys must persist an opaque per-key context before sealing.
- `OauthClient.organizationId` and `DeveloperAccount.organizationId` are
  nullable because existing production rows may not yet have an audited tenant
  assignment. New organization-managed clients must set the organization.
- `Plan.SCALE` remains in the Prisma enum so an existing database can be
  inspected safely. It is not a public v1 plan. A production migration must
  inventory every `SCALE` organization/developer row and explicitly map it to
  `PRO` or `ENTERPRISE` with an operator-reviewed decision before removing the
  legacy enum value.
- The schema does not make legacy OAuth ownership or key ownership disappear
  implicitly. A deploy must first backfill and verify organization membership,
  organization-scoped client ownership, and any token subject bindings before
  tightening nullable fields or adding production-only constraints.
- `ManagedAccount.custodyHeadId` is the only active-custody source of truth.
  `KeyCustody` rows are append-only history; a row is current only when it is
  the account head and has not been revoked. The Phase A fix migration adds a
  composite head foreign key, deferred PostgreSQL head checks, and an epoch
  trigger. The transition service is still the only supported writer and must
  use its serializable row-lock transaction.
- New managed keys use `keyPurpose = MANAGED_ACCOUNT`; personal routes and
  OAuth claims explicitly query `keyPurpose = PERSONAL`. The composite
  managed-account key foreign key and migration trigger reject an account/key
  owner mismatch.
- Organization registration intents reference the public OAuth `clientId`
  together with the organization. The internal OAuth row `id` is never used as
  the public registration identifier.

This note is migration guidance, not evidence that the production database has
been migrated or that custody is rollback-resistant.
