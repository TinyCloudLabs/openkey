import { generateRandomString } from 'better-auth/crypto';
import { base64Url } from '@better-auth/utils/base64';
import { createHash } from '@better-auth/utils/hash';
export function hasOAuthClientId(clientId: unknown): clientId is string {
  return typeof clientId === 'string';
}

export function generateOAuthClientSecret(): string {
  return generateRandomString(32, 'a-z', 'A-Z');
}

export async function hashOAuthClientSecret(secret: string): Promise<string> {
  const digest = await createHash('SHA-256').digest(new TextEncoder().encode(secret));
  return base64Url.encode(new Uint8Array(digest), { padding: false });
}
