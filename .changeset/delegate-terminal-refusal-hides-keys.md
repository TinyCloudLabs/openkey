---
"@openkey/web": patch
---

When a delegation request is refused for a reason that is the same for every key, such as a request that has ended or one that asks to delete keys, the page now shows that message without the key buttons. Refusals that another key could change still keep the list.

Details: TC-3343
