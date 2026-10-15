import { createHash, createPrivateKey, sign, type KeyObject } from 'node:crypto';
import { decodeJwt, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { defineRequestState, hasRequestState } from '@better-auth/core/context';
import { google } from '@better-auth/core/social-providers';
import { resolveConsoleOrigin, type OriginPolicyEnvironment } from './origin-policy';

export type SocialProviderId = 'google' | 'apple';
export type GoogleCallbackProfile = {
  id: string;
  email: string;
  name: string;
  image?: string;
  tokens: {
    accessToken?: string;
    refreshToken?: string;
    idToken?: string;
    accessTokenExpiresAt?: Date;
    refreshTokenExpiresAt?: Date;
    scope?: string;
  };
};
export const googleCallbackProfile = defineRequestState<GoogleCallbackProfile | undefined>(() => undefined);

export type AppleCallbackProfile = GoogleCallbackProfile & {
  isPrivateEmail: boolean;
  clientId: string;
};
export const appleCallbackProfile = defineRequestState<AppleCallbackProfile | undefined>(() => undefined);

type ProviderEnvironment = OriginPolicyEnvironment;
type PersistedAppleUser = {
  email: string;
  name: string | null;
  image: string | null;
};
type FindPersistedAppleUser = (
  providerAccountId: string,
) => Promise<PersistedAppleUser | null>;
type AppleTokenSet = GoogleCallbackProfile['tokens'] & {
  scopes?: string[];
  user?: {
    email?: string;
    name?: {
      firstName?: string;
      lastName?: string;
    };
  };
};
type AppleIdTokenClaims = {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  sub?: string;
  email?: string;
  email_verified?: boolean | string;
  is_private_email?: boolean | string;
  name?: string;
};

const APPLE_AUDIENCE = 'https://appleid.apple.com';
const APPLE_CLIENT_SECRET_TTL_SECONDS = 300;

function hasGoogleConfiguration(env: ProviderEnvironment): boolean {
  return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
}

function hasAppleConfiguration(env: ProviderEnvironment): boolean {
  return Boolean(
    env.APPLE_SIGN_IN_ENABLED === 'true'
    && env.APPLE_CLIENT_ID
    && env.APPLE_TEAM_ID
    && env.APPLE_KEY_ID
    && env.APPLE_PRIVATE_KEY,
  );
}

export function configuredSocialProviderIds(
  env: ProviderEnvironment = process.env,
): SocialProviderId[] {
  const providers: SocialProviderId[] = [];
  if (hasGoogleConfiguration(env)) providers.push('google');
  if (hasAppleConfiguration(env)) providers.push('apple');
  return providers;
}

function mintAppleClientSecret(
  clientId: string,
  teamId: string,
  keyId: string,
  signingKey: KeyObject,
  now: number,
): string {
  const encodedHeader = Buffer.from(JSON.stringify({ alg: 'ES256', kid: keyId })).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify({
    iss: teamId,
    sub: clientId,
    aud: APPLE_AUDIENCE,
    iat: now,
    exp: now + APPLE_CLIENT_SECRET_TTL_SECONDS,
  })).toString('base64url');
  const message = `${encodedHeader}.${encodedPayload}`;
  const signature = sign('sha256', Buffer.from(message), {
    key: signingKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${message}.${signature.toString('base64url')}`;
}

export async function generateAppleClientSecret(
  clientId: string,
  teamId: string,
  keyId: string,
  privateKey: string,
  now = Math.floor(Date.now() / 1000),
): Promise<string> {
  const signingKey = createPrivateKey(privateKey.replace(/\\n/g, '\n').trim());
  return mintAppleClientSecret(clientId, teamId, keyId, signingKey, now);
}

export async function resolveAppleUserInfo(
  tokens: AppleTokenSet,
  findPersistedUser: FindPersistedAppleUser,
  clientId: string,
) {
  if (!tokens.idToken) return null;

  let profile: AppleIdTokenClaims;
  try {
    profile = decodeJwt(tokens.idToken) as AppleIdTokenClaims;
  } catch {
    return null;
  }
  const now = Math.floor(Date.now() / 1000);
  if (
    profile.iss !== APPLE_AUDIENCE
    || profile.aud !== clientId
    || typeof profile.exp !== 'number'
    || profile.exp <= now
    || typeof profile.iat !== 'number'
    || profile.iat > now
    || profile.iat < now - 600
    || typeof profile.sub !== 'string'
    || !profile.sub.trim()
  ) return null;

  const verifiedEmail = (profile.email_verified === true || profile.email_verified === 'true')
    && typeof profile.email === 'string' && profile.email.trim()
    ? profile.email.trim()
    : undefined;
  const persistedUser = !verifiedEmail
    ? await findPersistedUser(profile.sub)
    : null;
  const email = verifiedEmail || persistedUser?.email;
  const suppliedName = [
    tokens.user?.name?.firstName,
    tokens.user?.name?.lastName,
  ].filter(Boolean).join(' ').trim();

  return {
    user: {
      id: profile.sub,
      ...(email ? { email } : {}),
      emailVerified: Boolean(verifiedEmail),
      name: suppliedName || profile.name || persistedUser?.name || '',
      image: persistedUser?.image || undefined,
    },
    data: {
      ...profile,
      is_private_email: profile.is_private_email === true || profile.is_private_email === 'true',
    },
  };
}

export async function verifyAppleNativeIdToken(
  token: string,
  options: {
    jwks: JWTVerifyGetKey;
    audience: string;
    serverNonce: string;
    requestUri: string;
    consumeNonce: (requestUri: string, nonceHash: string) => Promise<boolean>;
  },
): Promise<{ sub: string; email?: string }> {
  if (!options.audience || !options.serverNonce || !options.requestUri) {
    throw new Error('Missing Apple native token binding');
  }
  const { payload } = await jwtVerify(token, options.jwks, {
    algorithms: ['RS256'],
    issuer: APPLE_AUDIENCE,
    audience: options.audience,
    requiredClaims: ['sub', 'iat', 'exp', 'nonce'],
    maxTokenAge: '10m',
  });
  const now = Math.floor(Date.now() / 1000);
  const nonceHash = createHash('sha256').update(options.serverNonce).digest('hex');
  if (
    payload.aud !== options.audience
    || typeof payload.sub !== 'string'
    || !payload.sub.trim()
    || typeof payload.exp !== 'number'
    || payload.exp <= now
    || typeof payload.iat !== 'number'
    || payload.iat > now
    || payload.iat < now - 600
    || payload.nonce_supported === false
    || payload.nonce !== nonceHash
  ) throw new Error('Invalid Apple native identity token');
  if (!await options.consumeNonce(options.requestUri, nonceHash)) {
    throw new Error('Apple native nonce already consumed or not bound to request');
  }
  return {
    sub: payload.sub,
    ...((payload.email_verified === true || payload.email_verified === 'true')
      && typeof payload.email === 'string' && payload.email.trim()
      ? { email: payload.email.trim() }
      : {}),
  };
}

export function createSocialProviders(
  env: ProviderEnvironment = process.env,
  findPersistedAppleUser: FindPersistedAppleUser = async () => null,
) {
  const providers: Record<string, unknown> = {};

  if (hasGoogleConfiguration(env)) {
    const options = {
      clientId: env.GOOGLE_CLIENT_ID!,
      clientSecret: env.GOOGLE_CLIENT_SECRET!,
      disableImplicitSignUp: true,
      disableSignUp: true,
      disableIdTokenSignIn: true,
    };
    const defaultGoogle = google(options);
    providers.google = {
      ...options,
      async getUserInfo(tokens: Parameters<typeof defaultGoogle.getUserInfo>[0]) {
        const result = await defaultGoogle.getUserInfo(tokens);
        const user = result?.user;
        if (user?.emailVerified === true && typeof user.email === 'string' && user.id) {
          await googleCallbackProfile.set({
            id: String(user.id),
            email: user.email.toLowerCase(),
            name: user.name || '',
            image: user.image,
            tokens: {
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken,
              idToken: tokens.idToken,
              accessTokenExpiresAt: tokens.accessTokenExpiresAt,
              refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
              scope: tokens.scopes?.join(','),
            },
          });
        }
        return result;
      },
    };
  }

  if (hasAppleConfiguration(env)) {
    const clientId = env.APPLE_CLIENT_ID!;
    const teamId = env.APPLE_TEAM_ID!;
    const keyId = env.APPLE_KEY_ID!;
    const signingKey = createPrivateKey(env.APPLE_PRIVATE_KEY!.replace(/\\n/g, '\n').trim());
    providers.apple = async () => ({
      clientId,
      // Better Auth captures this options object once, but reads clientSecret
      // synchronously when it constructs each authorization-code token request.
      get clientSecret() {
        return mintAppleClientSecret(
          clientId, teamId, keyId, signingKey, Math.floor(Date.now() / 1000),
        );
      },
      disableImplicitSignUp: true,
      disableSignUp: true,
      disableIdTokenSignIn: true,
      // Native ID-token sign-in is permanently disabled. A future PAR-bound
      // endpoint will use verifyAppleNativeIdToken with its own audience set.
      async getUserInfo(tokens: AppleTokenSet) {
        const result = await resolveAppleUserInfo(tokens, findPersistedAppleUser, clientId);
        const user = result?.user;
        if (result && user?.emailVerified && user.email && await hasRequestState()) {
          await appleCallbackProfile.set({
            id: user.id,
            email: user.email.toLowerCase(),
            name: user.name,
            image: user.image,
            isPrivateEmail: result.data.is_private_email,
            clientId,
            tokens: {
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken,
              idToken: tokens.idToken,
              accessTokenExpiresAt: tokens.accessTokenExpiresAt,
              refreshTokenExpiresAt: tokens.refreshTokenExpiresAt,
              scope: tokens.scopes?.join(','),
            },
          });
        }
        return result;
      },
    });
  }

  return providers;
}

export function socialProviderTrustedOrigins(
  webOrigin: string,
  env: ProviderEnvironment = process.env,
): string[] {
  // Better Auth's redirect/CSRF trust boundary follows the web origin and its
  // console counterpart, rather than the broader API CORS allowlist.
  const browserOrigins = [webOrigin, resolveConsoleOrigin(env)]
    .filter((origin): origin is string => Boolean(origin));
  return hasAppleConfiguration(env)
    ? [...new Set([...browserOrigins, APPLE_AUDIENCE])]
    : browserOrigins;
}
