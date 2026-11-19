---
"@openkey/capability-review": patch
---

Named-key encryption resources (`urn:tinycloud:encryption:<owner>:<network>/<path>`) are parsed strictly and worded in the consent copy. Exact keys and prefixes each get one sentence per verb (create, decrypt, block, unblock, delete). Every `key.delete` is never approvable and renders the refusal line, including when its resource does not parse. Other malformed key paths fall back to the generic statement. Details: TC-1783
