---
"@openkey/web": patch
---

Approve for a request to host the `credentials` space stays disabled unless OpenKey confirms the node (an approval-screen check). If the node isn't confirmed, the request names no single node key, or the screen has no node check, the reason shows under Approve. If OpenKey gets no answer from the node, the screen says so and offers Try again. Other spaces keep their warning, with Approve enabled.

Details: TC-3853
