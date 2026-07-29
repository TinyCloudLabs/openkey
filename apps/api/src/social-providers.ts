import { importPKCS8, SignJWT } from 'jose';

export type SocialProviderId = 'google' | 'apple';

type ProviderEnvironment = Record<string, string | undefined>;

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

export function createSocialProviders(env: ProviderEnvironment = process.env) {
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
      // Keep Better Auth's persisted provider-account lookup and linking
      // behavior. Apple only supplies email during the first authorization.
    });
  }

  return providers;
}

export function socialProviderTrustedOrigins(
  webOrigin: string,
  env: ProviderEnvironment = process.env,
): string[] {
  return hasAppleConfiguration(env)
    ? [webOrigin, APPLE_AUDIENCE]
    : [webOrigin];
}
