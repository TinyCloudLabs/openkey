---
"@openkey/api": patch
---

A CLI prepared handoff that opts in (`request.expiryChangeable: true`, strictly the boolean true, stored with the handoff) lets the owner choose a longer approval time than the CLI asked for: `/authorize-sign-preview` no longer answers `expiry_exceeds_handoff` for that handoff, still bounded by the latest time a signed message can carry. A handoff without the opt-in keeps the shorter-only ceiling. A Nostr signing grant asking for more than 24 hours, or for a lifetime that is not a whole number of seconds of at least 1, is refused with a clear error instead of being shortened or rounded up. The unused 30-day device maximum and the 30-day clamp on lifetimes derived for older device rows are removed. Details: TC-2276
