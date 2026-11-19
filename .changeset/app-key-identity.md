---
"@openkey/web": patch
---

The approval view for a request with app keys shows the app's name, then its app id in monospace, then "Requested by" the verified origin, and "<name> is requesting:" above the rows; without a usable name it shows the app id alone and "This app is requesting:". The name is the verified manifest's `name` after the display rules in `app-identity.ts` (no control, bidi or format characters, no Latin mixed with Cyrillic or Greek, 48 characters at most). The app key rows say "this app" and no longer show the key path; an exact key is named by its last segment.
