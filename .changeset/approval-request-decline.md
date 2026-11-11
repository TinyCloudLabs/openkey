---
"@openkey/web": minor
"@openkey/api": patch
---

The approval-request review page (`/a/<id>`) now has a Decline button, left of Approve. It calls `POST /api/approval-requests/:id/deny` once with the complete link in the body, then shows "Declined. You can close this page." If the decline cannot be sent the page says nothing was changed and the owner can try again; an already-approved request says it cannot be declined. The old Cancel on this page is now a "Back" link above the buttons: it still returns to key selection and sends nothing. The widget popup and iframe sign pages keep their Cancel button and get no Decline. `/api/approval-requests/:id/load` adds a `denied` field (false when open), so reopening a declined link shows the declined page; older pages ignore the field. The review's dismiss control carries `data-testid="signing-dismiss"`, and tests find it by that instead of its label. Details: TC-2459
