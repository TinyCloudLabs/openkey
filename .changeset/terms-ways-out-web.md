---
"@openkey/web": minor
---

The ways out of the Terms screen (TC-3232).

- On the web, the Terms screen has one button, Agree and continue, and a small "Other options" link that leads to the ways out that need no agreement, over two pages:
  - Other options (`/auth/terms/options`): sign out without agreeing, or delete the account.
  - Disconnect apps (`/auth/terms/leave`): disconnect TinyCloud signing, MCP and identity apps, stop renewing permissions, or delete the account.
  An account that has agreed is sent to Settings, which has the same controls. Each page leads back to the one before, and to the same Terms request.
- Delete account from either page opens the delete page before the account has agreed: no call made there sends it to the Terms. Leaving it without deleting (the back link, Keep my account, Cancel) goes back to the page it came from.
- Signing out without agreeing first turns down the request that brought the account to the Terms: an OAuth sign-in is denied (the app receives `access_denied` and the browser returns to it), an approval link or device sign-in is declined. It then signs out. Turning the request down never stands in the way of signing out.
- The native sheet keeps Don't agree on the Terms screen, which does the same, and says that the app is told no.
