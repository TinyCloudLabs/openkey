---
"@openkey/api": patch
"@openkey/web": patch
---

A signed grant lasts exactly the length the owner chose, counted from when the request was made, to the second. The approval screen's end day is counted the same way. If that length has run out by the time the owner approves, OpenKey refuses the request and asks for a new one.

Details: TC-3920
