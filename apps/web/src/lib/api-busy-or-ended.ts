// The owner's wording for two server states. A 409 means the request already
// has work in flight, whatever `code` or `error` the reply carries; a 410 on a
// sign path means it was already answered or ended. The owner revocation page
// names its own action. Every other status keeps the server's own message:
// null, and the caller falls back.
export function apiBusyOrEndedMessage(status: number, surface?: 'revoke'): string | null {
  if (status === 409) return surface === 'revoke' ? 'This permission is already being revoked. Wait a moment.' : 'This request is already being approved. Wait a moment.';
  if (status === 410) return 'This request has already been answered or has ended.';
  return null;
}
