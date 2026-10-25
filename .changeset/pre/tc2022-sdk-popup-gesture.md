---
"@openkey/sdk": patch
---

In popup mode `authorizeTinyCloud` opens its popup window in the call itself, blank, before the first await, and navigates it to the widget once the key is routed. The key list request and the routing that run first could outlast the click that asked for the popup, and a browser opens a popup only inside that click. The window is closed if the flow fails or takes the external-wallet route before the widget is shown. Iframe mode, `connect`, `signMessage` and the other flows are unchanged.
