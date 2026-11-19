---
"@openkey/capability-review": patch
---

Permission text is one short line. The delegation list reads "See who has access to your data"; named-key, app-key, schema, encryption-setup, hint and callout lines are shortened the same way. A request the catalog does not recognize now names its known actions in plain words ("Read and delete your data") instead of "Perform tinycloud.kv/get, … on tinycloud.kv", and shows any other action as "Unknown action: <ability>". Every such fallback row is marked `literalEscaped`, with its raw text escaped and capped. Display text only: the signed request and the delegation content are unchanged. Details: TC-2216
