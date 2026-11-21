---
"@openkey/api": minor
"@openkey/web": patch
---

OpenKey asks every account to agree to the Terms of Service and acknowledge the Privacy Policy. `apps/api/src/terms-release.json` sets version 2026-11-22, the effective date on the published Terms, and the SHA-256 of `src/content/Terms.md` in the landing repo at the live commit. Until an account agrees, its session requests get 403 `terms_required` and its token refreshes are refused with `invalid_grant` and a `terms_url`. Signing out, disconnecting apps, stopping renewals and deleting the account stay open. Until it agrees, an account can list its secrets' names and read its variables with its browser session (`GET /api/secrets`, `GET /api/variables`, `GET /api/secrets/status`), so it can see what it holds before deleting the account. Writes are refused. App-review accounts are recorded as accepting when the API starts.

The Terms leave page says disconnecting stops an app getting new access and that permissions the owner set to renew keep renewing until stopped under Renewing permissions. It also says a phone app signs the owner out the next time it renews, unless the owner agrees to the Terms.

Details: TC-3232
