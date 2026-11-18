---
"@openkey/web": patch
---

The OAuth consent page now says "After you allow, you'll return to <host>", using the host of the signed `redirect_uri` (never its path or query; nothing is shown if it is missing or unusable). When `tinycloud:mcp` is requested the header reads "wants to connect to your TinyCloud" and a row says "Connect to TinyCloud. You approve access to your data separately."; when `offline_access` is requested a row says "Stay connected for up to 30 days, or until you disconnect it." (without `tinycloud:mcp`: "Stay connected until the connection expires or you disconnect it."); every other granted scope gets its own row (email, keys, reading and saving the app's data for up to an hour, or the scope's name for any other; the note under the list is dropped when a scope has no plain description) (Settings now uses the same 30-day wording). The note under the list reads "This app gets only the access listed above." for non-identity-only requests. TC-3188.

A time longer than two days now reads in whole days ("expires in 29 days", never "700 hours"), on the approval screen and the app sign-in consent page.
