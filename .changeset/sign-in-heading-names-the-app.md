---
"@openkey/web": patch
---

The approval screen for a sign-in is headed "Sign in to {app}" with the app's verified name, or the origin host when the name isn't verified. A wildcard or missing origin, a recap that hosts a space and a requester OpenKey cannot name keep the heading "Authorize capabilities". The Manifest ID tag reads "from the app's request, unverified; the manifest doesn't name one" when the matched manifest names no id, and "caller-supplied, unverified" for an id with no matched manifest.

Details: TC-3921
