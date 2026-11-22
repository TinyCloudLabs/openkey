---
"@openkey/web": patch
---

On OpenKey's approval screens, Approve for a request to host the `credentials` space is disabled unless OpenKey confirms the node. If the node isn't confirmed, the request names no single node key or the page can't check the node, the reason shows under Approve. If OpenKey gets no answer from the node, the screen says so and offers Try again. Other spaces keep their warning, with Approve enabled.

Details: TC-3853
