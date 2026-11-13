import { createHash } from 'node:crypto';

export interface ShareAuthSessionState {
  token: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  lastPasskeyAt?: Date | null;
  lastPasskeyId?: string | null;
  lastEmailOtpAt?: Date | null;
}

/** Ignore updatedAt-only refreshes; bind identity, authority lifetime and security markers. */
export function shareSessionGeneration(session: ShareAuthSessionState): string {
  const hash = createHash('sha256').update('openkey/share-auth-session-generation/v1\0');
  for (const value of [session.token, session.userId, session.createdAt.toISOString(), session.expiresAt.toISOString(),
    session.lastPasskeyAt?.toISOString() ?? '', session.lastPasskeyId ?? '', session.lastEmailOtpAt?.toISOString() ?? '']) {
    const bytes = Buffer.from(value, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest('hex');
}
