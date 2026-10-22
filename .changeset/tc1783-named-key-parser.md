---
"@openkey/capability-review": patch
---

Named-key encryption resources (`urn:tinycloud:encryption:<owner>:<network>/<path>`) are parsed strictly and worded in the consent copy. Exact keys and prefixes each get one sentence per verb (create, decrypt, block, unblock, delete). Delete rows are marked never approvable. Malformed key paths fall back to the generic statement. Details: TC-1783
