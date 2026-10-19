---
"@openkey/web": minor
---

One shared key picker (`KeyPicker`) now serves `/delegate` and both connect widgets (popup and embedded). With several keys and no wallet named, the connect widgets lead with the primary key (Primary badge), keep other keys behind "Use a different key" with a warning that each key is a separate account owner, and return the chosen key's `keyId` to the app. `/delegate` behaviour is unchanged. OAuth consent and manage-key signing stay primary-only.
