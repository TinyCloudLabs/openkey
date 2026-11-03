---
"@openkey/web"
---

A click on Approve made by a script inside the framed approval is no longer dropped for not coming from the browser. The button is still disabled, and a click on it does nothing, while the frame is still moving (the settle gate), before the host has acknowledged the layout, or while the node is being checked. Details: TC-2310
