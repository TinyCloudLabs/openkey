---
"@openkey/api": minor
"@openkey/web": patch
---

OpenKey now asks every account to agree to the Terms of Service and acknowledge the Privacy Policy (TC-3232). `apps/api/src/terms-release.json` sets version 2026-11-22, the effective date on the published Terms, and the SHA-256 of `src/content/Terms.md` in the landing repo at the commit that is live. Until an account agrees, its sessions and tokens get 403 `terms_required`, with the way out (sign out, disconnect apps, stop renewals, delete the account) open. App-review accounts are recorded as accepting at API start. To roll back, set `version` and the other fields back to null and redeploy.

The Terms leave page no longer says that disconnecting an app stops its renewals: it withdraws the app's consent, and renewals already approved keep going until the owner stops them under Renewing permissions.

API tests run with the Terms release pinned to no version, except the Terms suites and one that boots the API on the shipped release.
