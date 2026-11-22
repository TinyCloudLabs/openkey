---
"@openkey/api": patch
---

OpenKey asks every account to agree to the Terms of Service and acknowledge the Privacy Policy. `apps/api/src/terms-release.json` sets version 2026-11-22 and the SHA-256 of `src/content/Terms.md` in the landing repo at the live commit. Until an account agrees, its session requests get 403 `terms_required` and its token refreshes are refused with `invalid_grant` and a `terms_url`. Signing out, disconnecting apps, stopping renewals and deleting the account stay open.

Details: TC-3766
