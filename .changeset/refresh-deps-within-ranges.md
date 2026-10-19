---
"@openkey/api": patch
"@openkey/web": patch
---

Refresh dependencies within their existing semver ranges (hono, viem, resend, dotenv, bits-ui, tailwind, turbo, typescript, changesets). `better-auth` and `nanostores` stay at their current versions. A type-only guard for a possibly-missing `organizationId` param is added in the tenant console overview route.
