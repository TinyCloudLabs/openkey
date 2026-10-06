---
"@openkey/web": patch
---

The sign-out widgets (embedded and popup) now accept the same `?origin=` values as the connect widget. They used an http(s)-only parser, so an app embedding OpenKey from an app-scheme origin such as `tauri://localhost` (Tauri / WKWebView desktop apps) could connect but never got `openkey:ready` from the embedded sign-out widget. The SDK then fell back to a popup that the webview blocks, and sign-out failed with "Popup was blocked". Origin and source checks are unchanged: messages still go only to the exact origin, never `*`.
