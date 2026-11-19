import { symmetricDecrypt } from 'better-auth/crypto';
import { log } from '../log';
import { revokeAppleToken } from './social-confirmation';

/** Failed revokes are retried this many times after the first attempt (plan TC-1188 §6). */
export const APPLE_REVOKE_RETRIES = 3;
const RETRY_BASE_DELAY_MS = 100;

export type StoredAppleToken = { refreshToken: string | null; appleClientId: string | null };

type RevokeOptions = {
  revoke?: typeof revokeAppleToken;
  decrypt?: (data: string) => Promise<string>;
  sleep?: (ms: number) => Promise<void>;
};

async function decryptStoredToken(data: string): Promise<string> {
  // Not a static import: loading ../auth builds Better Auth, which route unit
  // tests with a stand-in client must not do (see routes/account.ts unlink).
  const { auth } = await import('../auth');
  return symmetricDecrypt({ key: (await auth.$context).secretConfig, data });
}

/**
 * Revokes each stored Apple refresh token with the Services or App ID that
 * issued it. Runs after the caller's change has committed and never undoes it:
 * a token that still fails after the retries is logged as
 * `auth_apple_revoke_failed`, without the token or its owner.
 */
export async function revokeStoredAppleTokens(tokens: StoredAppleToken[], options: RevokeOptions = {}): Promise<number> {
  const revoke = options.revoke ?? revokeAppleToken;
  const decrypt = options.decrypt ?? decryptStoredToken;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let failures = 0;
  for (const stored of tokens) {
    if (!stored.refreshToken) continue;
    let token: string | undefined;
    try {
      token = await decrypt(stored.refreshToken);
    } catch {
      token = undefined;
    }
    let revoked = false;
    if (token && stored.appleClientId) {
      for (let attempt = 0; attempt <= APPLE_REVOKE_RETRIES && !revoked; attempt += 1) {
        if (attempt > 0) await sleep(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1));
        revoked = await revoke(token, stored.appleClientId);
      }
    }
    if (!revoked) {
      failures += 1;
      log('error', 'auth_apple_revoke_failed');
    }
  }
  return failures;
}
