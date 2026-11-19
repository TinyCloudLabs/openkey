---
"@openkey/api": patch
---

`/api/delegate` and `/api/delegate/complete` refusals on approval now include a `code`, `POST /api/delegate/prepare` answers a missing key with `code: "key_not_found"`, and a requested space owned by a different wallet is refused with `requestedSpaceOwner` naming that wallet. The `error` text of each reply is unchanged.

Details: TC-3441
