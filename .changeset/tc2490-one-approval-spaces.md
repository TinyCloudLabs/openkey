---
"@openkey/api": minor
---

Prepare one delegation across multiple owner spaces using the existing per-space ReCap builder and shared permission narrowing. Keep the primary `spaceId` for routing, and return `requestedSpaces` with per-space readiness from preparation and completion. Managed automatic setup confirms every granted requested space before reporting it ready. Details: TC-2490.
