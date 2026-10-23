---
"@openkey/api": patch
---

Consolidated dependency update: `dotenv` 17.4.2 → 18 (lock: 18.0.8), `@tinycloud/node-sdk` 2.6.1 → 2.11.0, `@tinycloud/node-sdk-wasm` 1.7.4 → 1.7.6, `@tinycloud/sdk-core` 2.6.1 → 2.11.0. Dev tooling: `@changesets/cli` 2.31.1 → 3.0.3, `portless` 0.14.0 → 0.15 (lock: 0.15.8). `typescript` stays on ^6 (7.x is not supported by tsup's declaration build). node-sdk 2.11 would add the `account` space to the sign-in recap the managed key signs for the `openkey` and `secrets` sessions; `TinyCloudService` passes `includeAccountRegistryPermissions: false` so their scope is unchanged.
