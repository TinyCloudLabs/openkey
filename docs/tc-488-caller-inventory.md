# TC-488 deleted-surface caller inventory

Recorded 2026-08-05 after the TC-488 source deletion.

The executable inventory in `scripts/tc-488-caller-inventory.test.ts` searches API and web sources, SDKs, CLI, CI scripts, and deployment workflows for deleted custody routes, SDK types, tenant-account symbols, and compatibility modes.

Result: the only first-party production callers were the OpenKey API routes, console/dashboard pages, and published SDK implementation removed in this change. The executable scan proves no retained API, CLI, React Native SDK, CI script, or deployment workflow imports the removed surfaces.

Residual risk: external consumers of the removed SDK surface cannot be discovered by repository search. This is a breaking SDK removal. Production route-hit evidence and managed-key disposition must be reviewed before applying the destructive migration; no production migration was run for this PR.
