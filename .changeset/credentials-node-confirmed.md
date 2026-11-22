---
"@openkey/web": patch
---

A request to host the `credentials` space is approved only on a node OpenKey confirms as a TinyCloud node (TC-3853). If the node isn't confirmed, or the request names no single node key, Approve stays disabled and the reason is shown. If the node lookup gets no answer, the screen says so and offers "Try again". Other spaces keep the warning and an enabled Approve. A lookup that gets no key back is now reported as its own `failed` state, separate from `other`.
