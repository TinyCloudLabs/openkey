---
"@openkey/web": patch
---

The "known node" check on a host approval no longer asks every production node. It asks only the node the request names: a known node (or a configured extra) is asked alone; any other host (a local node, an unknown or look-alike address) is not contacted at all and the node reads "not confirmed" at once; a request that names no node asks one default node, `https://node.tinycloud.xyz`. A request-supplied address is never fetched unless it is exactly a known origin. Display only: nothing that is signed changes, and no wording or screen changes.
