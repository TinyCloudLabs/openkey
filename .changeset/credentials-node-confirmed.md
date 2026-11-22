---
"@openkey/web": patch
---

A request to host the `credentials` space can be approved only on a node OpenKey confirms as a TinyCloud node. If the node isn't confirmed, or the request names no single node key, Approve is disabled and the reason shows under it. If OpenKey gets no answer from the node, the screen says so and offers Try again. Other spaces keep their warning, with Approve enabled.

Details: TC-3853
