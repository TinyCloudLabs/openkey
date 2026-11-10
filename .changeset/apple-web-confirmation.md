---
"@openkey/web": minor
---

Sign in with Apple web steps, ready for when Apple is enabled. The popup callback shows provider-specific copy for every Apple and Google return: the new-account confirmation (Create, passkey, email or recovery) with Apple's Hide My Email notice, the account-exists step that sends the user to sign in and add Apple after an email code, and the `apple_email_required` explanation. `/auth/register` creates a confirmed account without asking again unless Apple hides the email. Settings lists Google and Apple, links either after an email-code step-up, unlinks after a fresh code, and explains when an unlink would leave no usable sign-in or when Apple has stopped forwarding a relay address. Apple stays off until `/api/auth/providers` lists it. Details: TC-1232
