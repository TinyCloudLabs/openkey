import { decodeJwt, importPKCS8, SignJWT } from 'jose';
import { resolveOriginPolicy, type OriginPolicyEnvironment } from './origin-policy';

export type SocialProviderId = 'google' | 'apple';

type ProviderEnvironment = OriginPolicyEnvironment;
type PersistedAppleUser = {
  email: string;
  name: string | null;
  image: string | null;
};
type FindPersistedAppleUser = (
  providerAccountId: string,
) => Promise<PersistedAppleUser | null>;
type AppleTokenSet = {
  idToken?: string;
  user?: {
    email?: string;
    name?: {
      firstName?: string;
      lastName?: string;
    };
  };
};
type AppleIdTokenClaims = {
  sub?: string;
  email?: string;
  email_verified?: boolean | 'true' | 'false';
  name?: string;
};

const APPLE_AUDIENCE = 'https://appleid.apple.com';
const APPLE_CLIENT_SECRET_TTL_SECONDS = 180 * 24 * 60 * 60;

function hasGoogleConfiguration(env: ProviderEnvironment): boolean {
  return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
}

function hasAppleConfiguration(env: ProviderEnvironment): boolean {
  return Boolean(
    env.APPLE_CLIENT_ID
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

export async function generateAppleClientSecret(
  clientId: string,
  teamId: string,
  keyId: string,
  privateKey: string,
  now = Math.floor(Date.now() / 1000),
): Promise<string> {
  const normalizedPrivateKey = privateKey.replace(/\\n/g, '\n').trim();
  const signingKey = await importPKCS8(normalizedPrivateKey, 'ES256');

  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: keyId })
    .setIssuer(teamId)
    .setSubject(clientId)
    .setAudience(APPLE_AUDIENCE)
    .setIssuedAt(now)
    // 180 days stays safely below Apple's six-month maximum.
    .setExpirationTime(now + APPLE_CLIENT_SECRET_TTL_SECONDS)
    .sign(signingKey);
}

export async function resolveAppleUserInfo(
  tokens: AppleTokenSet,
  findPersistedUser: FindPersistedAppleUser,
) {
  if (!tokens.idToken) return null;

  const profile = decodeJwt(tokens.idToken) as AppleIdTokenClaims;
  if (!profile.sub) return null;

  const firstAuthorizationEmail = tokens.user?.email?.trim();
  const tokenEmail = profile.email?.trim();
  const persistedUser = tokenEmail || firstAuthorizationEmail
    ? null
    : await findPersistedUser(profile.sub);
  const email = tokenEmail || firstAuthorizationEmail || persistedUser?.email;
  if (!email) return null;

  const suppliedName = [
    tokens.user?.name?.firstName,
    tokens.user?.name?.lastName,
  ].filter(Boolean).join(' ').trim();

  return {
    user: {
      id: profile.sub,
      email,
      emailVerified:
        profile.email_verified === true
        || profile.email_verified === 'true'
        || Boolean(persistedUser),
      name: suppliedName || profile.name || persistedUser?.name || '',
      image: persistedUser?.image || undefined,
    },
    data: profile,
  };
}

export function createSocialProviders(
  env: ProviderEnvironment = process.env,
  findPersistedAppleUser: FindPersistedAppleUser = async () => null,
) {
  const providers: Record<string, unknown> = {};

  if (hasGoogleConfiguration(env)) {
    providers.google = {
      clientId: env.GOOGLE_CLIENT_ID!,
      clientSecret: env.GOOGLE_CLIENT_SECRET!,
    };
  }

  if (hasAppleConfiguration(env)) {
    providers.apple = async () => ({
      clientId: env.APPLE_CLIENT_ID!,
      clientSecret: await generateAppleClientSecret(
        env.APPLE_CLIENT_ID!,
        env.APPLE_TEAM_ID!,
        env.APPLE_KEY_ID!,
        env.APPLE_PRIVATE_KEY!,
      ),
      ...(env.APPLE_APP_BUNDLE_IDENTIFIER
        ? { appBundleIdentifier: env.APPLE_APP_BUNDLE_IDENTIFIER }
        : {}),
      // Better Auth requires an email before it performs its persisted-account
      // lookup. Apple can omit it on later callbacks, so recover it only from
      // the already-linked provider account instead of creating a new identity.
      getUserInfo: (tokens: AppleTokenSet) =>
        resolveAppleUserInfo(tokens, findPersistedAppleUser),
    });
  }

  return providers;
}

export function socialProviderTrustedOrigins(
  webOrigin: string,
  env: ProviderEnvironment = process.env,
): string[] {
  const browserOrigins = resolveOriginPolicy(webOrigin, env);
  return hasAppleConfiguration(env)
    ? [...new Set([...browserOrigins, APPLE_AUDIENCE])]
    : browserOrigins;
}
