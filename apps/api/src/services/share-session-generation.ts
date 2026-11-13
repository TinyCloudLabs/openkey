import { createHash } from 'node:crypto';

/** Internal binding only; neither the token nor this generation is returned to the app. */
export function shareSessionGeneration(session: { token: string; updatedAt: Date }): string {
  const hash = createHash('sha256').update('openkey/share-auth-session-generation/v1\0');
  for (const value of [session.token, session.updatedAt.toISOString()]) {
    const bytes = Buffer.from(value, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest('hex');
}
