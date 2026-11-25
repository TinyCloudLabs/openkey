---
"@openkey/api": patch
---

An email sign-in code is now graded in one atomic database operation, so simultaneous verifications of one code create a single session and every wrong guess counts against the code's attempt limit.

Details: red-team #30
