// The Terms status of an account that has agreed to the current release: every signed-in page reads
// GET /api/account/terms before it shows, so a spec about something else answers it with this.
export const TERMS_ACCEPTED = {
  version: '2026-11-22',
  effective: '2026-11-22',
  whatChanged: null,
  privacyChanged: false,
  requiresAcceptance: false,
  previouslyAccepted: true,
};
