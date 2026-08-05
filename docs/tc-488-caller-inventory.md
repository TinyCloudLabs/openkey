# TC-488 deleted-surface caller inventory

Recorded 2026-08-05 before the TC-488 source deletion.

Static repository inventory searched `apps/`, `packages/`, `scripts/`, deployment workflows, and documentation for the deleted managed-account routes and SDK client: `/v1/accounts`, `/v1/credentials`, `/api/managed-accounts`, managed-account registration, tenant accounts, custody, eject, broker DID, and `OpenKeyManagementClient`.

Result: the only first-party production callers were the OpenKey API routes, the OpenKey web console/dashboard pages, and the published SDK implementation removed in this change. No retained API, CLI, React Native SDK, deployment workflow, or cron worker imports the removed surfaces after the cutover scan.

Residual risk: `@openkey/sdk` 0.9.0 publicly exported `OpenKeyManagementClient`; external consumers cannot be proven absent from repository search. This change is a breaking SDK removal. Production route-hit evidence and managed-key disposition must be reviewed before applying the destructive migration; no production migration was run for this PR.
