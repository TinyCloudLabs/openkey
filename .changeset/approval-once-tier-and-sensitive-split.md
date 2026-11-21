---
"@openkey/web": minor
---

The approval expiry starts at one hour for broad secret and decryption access, and follows the app's requested length for a single named secret or an app-scoped `apps/<appId>/` encryption grant. For any approval that reaches secret data or decryption, the renewal checkbox is unticked by default and the "Renew sensitive access?" confirm appears. The Sensitive warning on the summary and the row count are unchanged.
