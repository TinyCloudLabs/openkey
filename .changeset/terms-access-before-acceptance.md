---
"@openkey/api": minor
"@openkey/db": minor
---

Access an account already granted waits for Terms acceptance too (TC-3232). With a Terms release set, an account that hasn't accepted it:
- can't sign through `/api/delegate/sign` with an app's OAuth token; the refusal is the audited denial `terms_required` (403). A browser session gets the usual 403 `terms_required` instead of 401 `missing_authorization`, so the page can open the Terms screen.
- doesn't get its web session extended by an MCP token refresh that is refused.

`POST /api/account/terms/accept` records an acceptance only from the browser: a request with an Authorization header is refused (403). A Terms acceptance row can't be deleted while its account exists; deleting the account still removes it.
