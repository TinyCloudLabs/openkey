---
"@openkey/web": patch
---

The Terms step is a checked state of every signed-in page. A window or pop-up reads `GET /api/account/terms` once per account alongside the page and shows the Terms in place of the page while they are owed; Agree shows the page at the same address. The embedded frame reads the status with its session token after sign-in and shows a compact Terms card in the frame, with Agree held until the frame has settled; the frame never navigates to `/auth/login` or `/auth/terms`. The Nostr frame stays hidden while the status is read and shows only when the Terms are owed or the status can’t be read. A `terms_required` reply reads the status again and shows the Terms in place. A status that can’t be read within 8 seconds shows “Couldn’t check whether you’ve agreed to the Terms.” with Try again and never the page. A build whose `terms-release.json` has no release reads no status first and waits on nothing; a `terms_required` reply shows the Terms in place. A frame sign-in older than 10 minutes signs in again to agree.

Details: TC-3766
