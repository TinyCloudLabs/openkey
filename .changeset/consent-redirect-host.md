---
"@openkey/web": patch
---

The OAuth consent page now says "After you allow, you'll return to <host>", using the host of the signed `redirect_uri` (never its path or query; nothing is shown if it is missing or unusable). When `tinycloud:mcp` is requested the header reads "wants to connect to your TinyCloud" and a row says "Connect to TinyCloud. You approve access to your data separately."; when `offline_access` is requested a row says "Stay connected for up to 30 days, or until you disconnect it." (Settings now uses the same 30-day wording). The note under the list reads "This app gets only the access listed above." for non-identity-only requests. TC-3188.
