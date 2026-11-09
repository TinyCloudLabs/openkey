---
"@openkey/web": patch
---

On a CLI prepared handoff that opts in to a longer time, the approval-time picker offers the 30-day preset and accepts a typed time beyond what the CLI asked for, with the note "This app asked for 7d. You can choose a longer time." Handoffs without the opt-in keep the shorter-only picker. The 30-day clamp on a lifetime derived for an older device request is removed. Details: TC-2276
