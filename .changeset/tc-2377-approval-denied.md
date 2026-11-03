---
"@openkey/api": minor
"@openkey/db": minor
---

An approval request now has an explicit DENIED state. `POST /api/approval-requests/:id/deny` (signed in, with `{ "reference": "/a/<id>#v=4&k=...&c=..." }`, the same reference `/load` takes; idempotent) declines a pending request. Requests carry no owner account (the owner is whoever signs at approval), so the capability is the complete link, as for approving: OpenKey re-resolves the reference with its key and checks it opens to this request, so a signed-in caller who only knows the request id, or who holds another request's link, is refused with `403 link_required` and the request stays open. The reference is never logged or echoed. An approved request answers `409 already_approved`, an expired one `410 expired_request`, an unknown one `404 not_found`. A denied request can never be approved or signed, in the store or on the signing path.

The requester's poll (`POST /api/approval-requests/:id/result`) on a denied request answers HTTP 410 with the existing code `expired_request`, plus the additive `status: "denied"` and `deniedAt`: `{ "error": "Approval request was denied", "code": "expired_request", "status": "denied", "deniedAt": "<ISO>" }`. Released CLIs already treat `expired_request` as terminal and drop their keys, so none of them loops on a denied request; clients that know about denial can read `status`. The answer is returned even after the request's own expiry, and only after the requester's proof is verified.

Adds the nullable `deniedAt` column to `approval_request` and widens its result-state check (migration `20261103_0002_approval_request_denied`); deploy it before this API image. There is no Deny button on `/a/<id>` yet; that is a visible change for Sam to approve first, so the endpoint is only reachable by API until then.

js-sdk half (TC-2377, not part of this change): the CLI and Courier map `status: "denied"` to a terminal denial, drop the pending entry and its keys, and exit with a code that is not the retry code 8.
