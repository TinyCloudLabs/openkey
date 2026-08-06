// OpenKey API - better-auth configuration
// Auth flow: email OTP by default, with optional passkey enrollment and sign-in.
import { betterAuth, type BetterAuthPlugin } from 'better-auth';
import { APIError } from 'better-auth/api';
import type { AuthMiddleware } from '@better-auth/core/api';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { passkey } from '@better-auth/passkey';
import { bearer, emailOTP, jwt } from 'better-auth/plugins';
import { oauthProvider } from '@better-auth/oauth-provider';
import { Resend } from 'resend';
import { AsyncLocalStorage } from 'node:async_hooks';
import { getAddress } from 'viem';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { createTeeClient, seal, generatePrivateKey, getAddressFromPrivateKey } from '@openkey/tee';
import { buildEmailClaims } from './claims';
import {
  DEFAULT_OAUTH_SCOPES,
  DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES,
  OAUTH_SCOPES,
  TINYCLOUD_CANONICAL_IDENTITY_CLAIM,
  TINYCLOUD_MANAGE_KEY_SCOPE,
  TINYCLOUD_MCP_SCOPE,
  TINYCLOUD_OWNER_DIDS_CLAIM,
  TINYCLOUD_SESSION_SCOPE,
  dynamicClientRegistrationEnabled,
  oauthValidAudiences,
} from './oauth-config';
import { createSealingContext } from './services/key-sealing';
import {
  assertFreshPasskeyUserVerification,
  recordPasskeyFreshnessAfterHook,
} from './services/passkey-freshness';
import {
  createSocialProviders,
  socialProviderTrustedOrigins,
} from './social-providers';
import { crossSubDomainCookieOptions } from './auth-options';

export const prisma: PrismaClient = createPrismaClient({
  log: ['error', 'warn'],
});
const tee = createTeeClient();

// Initialize Resend for email OTP
const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

// Environment-based configuration
const isDev = process.env.NODE_ENV !== 'production' && process.env.TEE_MODE !== 'production';
const rpID = process.env.WEBAUTHN_RP_ID!;
const origin = process.env.WEBAUTHN_ORIGIN!;

// Base URL for proper request context
const baseURL = process.env.BETTER_AUTH_URL!;

type AuthoritativeOauthClient = {
  id: string;
};

const oauthRequestContext = new AsyncLocalStorage<{ clientId?: string }>();

function setOauthClientContext(clientId: string | undefined) {
  oauthRequestContext.enterWith(clientId ? { clientId } : {});
}

function currentOauthClientId() {
  return oauthRequestContext.getStore()?.clientId;
}

async function loadAuthoritativeOauthClient(
  database: PrismaClient,
  clientId: string | undefined,
): Promise<AuthoritativeOauthClient | null> {
  if (!clientId) return null;
  return database.oauthClient.findFirst({
    where: { clientId },
    select: { id: true },
  });
}

export async function buildKeyClaims(
  user: { id: string; email: string; emailVerified: boolean },
  scopes: string[],
  client: AuthoritativeOauthClient | undefined,
  _mutate = false,
  database: PrismaClient = prisma,
) {
  if (!scopes.includes('keys')) return undefined;
  if (!client) return [];
  const keys = await database.ethereumKey.findMany({
    where: {
      userId: user.id,
      archivedAt: null,
      ...(scopes.includes(TINYCLOUD_SESSION_SCOPE)
        ? { keyType: 'MANAGED' as const }
        : {}),
    },
    select: {
      id: true,
      address: true,
      keyType: true,
    },
    orderBy: { keyIndex: 'asc' },
  });
  return keys.map((k) => ({
    address: k.address,
    keyType: k.keyType,
    keyId: k.id,
  }));
}

export async function buildOauthKeyClaims(
  user: { id: string; email: string; emailVerified: boolean },
  scopes: string[],
  client: AuthoritativeOauthClient | undefined,
  database: PrismaClient = prisma,
) {
  return buildKeyClaims(user, scopes, client, true, database);
}

/**
 * The identity is deliberately resolved server-side from the canonical-key
 * relation. OAuth clients receive no selector that could make a second
 * personal key appear to be the user's TinyCloud identity.
 */
export async function buildCanonicalTinyCloudIdentityClaim(
  user: { id: string },
  scopes: string[],
  client: AuthoritativeOauthClient | undefined,
  database: PrismaClient = prisma,
) {
  if (!scopes.includes(TINYCLOUD_MANAGE_KEY_SCOPE) || !client) {
    return undefined;
  }
  const key = await database.ethereumKey.findFirst({
    where: {
      userId: user.id,
      keyType: 'MANAGED',
      archivedAt: null,
      isCanonicalTinyCloud: true,
    },
    select: { id: true, address: true },
  });
  if (!key) return undefined;
  const address = getAddress(key.address);
  return {
    version: 'v1',
    keyId: key.id,
    address,
    chainId: 1,
    did: `did:pkh:eip155:1:${address}`,
    spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
  };
}

export async function buildUserInfoKeyClaims(
  user: { id: string; email: string; emailVerified: boolean },
  scopes: string[],
  client: AuthoritativeOauthClient | undefined,
  database: PrismaClient = prisma,
) {
  return buildKeyClaims(user, scopes, client, false, database);
}

const passkeyFreshnessPlugin = {
  id: 'openkey-passkey-freshness',
  hooks: {
    after: [{
      matcher: (ctx) => ctx.path === '/passkey/verify-authentication',
      handler: (async (ctx: { path?: string; headers?: Headers; context: { returned?: unknown } }) => {
        return recordPasskeyFreshnessAfterHook(
          prisma,
          ctx.context.returned,
          ctx.headers?.get('x-openkey-passkey-ceremony'),
        );
      }) as AuthMiddleware,
    }],
  },
} satisfies BetterAuthPlugin;


export const auth = betterAuth({
  baseURL,
  basePath: '/api/auth',
  secret: process.env.BETTER_AUTH_SECRET,
  disabledPaths: ['/token'], // Avoid conflicts with OAuth token endpoint
  logger: {
    level: 'debug',
    disableColors: true,
    log: (level, message, ...args) => {
      const details = args.map((arg) => {
        if (!(arg instanceof Error)) return arg;
        return {
          name: arg.name,
          message: arg.message,
          stack: arg.stack,
          cause: arg.cause,
        };
      });
      console.log(`[Better Auth] [${level}]`, message, ...details);
    },
  },

  database: prismaAdapter(prisma, {
    provider: 'postgresql',
  }),

  // Passwords stay disabled; email OTP is the default authentication path.
  emailAndPassword: {
    enabled: false,
  },

  // Session configuration
  session: {
    expiresIn: 60 * 60 * 24 * 7, // 7 days
    updateAge: 60 * 60 * 24, // Update session every 24 hours
    storeSessionInDatabase: true, // Required for OAuth provider
  },

  plugins: [
    passkeyFreshnessPlugin,
    // Passkeys are an encouraged optional sign-in and step-up method.
    passkey({
      rpID,
      rpName: 'OpenKey',
      origin,
      authentication: {
        // Better Auth does not expose a per-request requireUserVerification
        // option. Keep ordinary login behavior unchanged, but require UV on
        // the server-issued ceremony marker used for custody freshness.
        afterVerification: async ({ ctx, verification }) => {
          if (ctx.headers?.get('x-openkey-passkey-ceremony')) {
            assertFreshPasskeyUserVerification(verification);
          }
        },
      },
    }),

    // Email OTP is the default registration and sign-in method.
    emailOTP({
      async sendVerificationOTP({ email, otp, type }) {
        if (!resend) {
          console.log(`[DEV] OTP for ${email}: ${otp} (type: ${type})`);
          return;
        }

        await resend.emails.send({
          from: 'OpenKey <noreply@openkey.so>',
          to: email,
          subject: 'Verify your OpenKey email',
          html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #1a1a1a; margin-bottom: 24px;">Your verification code</h2>
              <p style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea; margin: 32px 0; text-align: center;">${otp}</p>
              <p style="color: #666; font-size: 14px;">This code expires in 5 minutes.</p>
              <p style="color: #888; font-size: 12px; margin-top: 24px;">If you didn't request this, you can safely ignore this email.</p>
            </div>
          `,
        });
      },
      generateOTP({ email }: { email: string }) {
        if (process.env.TEE_MODE === 'development' && email === 'test@openkey.dev') {
          return '000000';
        }
        return undefined;
      },
      otpLength: 6,
      expiresIn: 300, // 5 minutes
      // Repeated requests during the active window must not invalidate a code
      // that may still be arriving or grouped into the same email thread.
      resendStrategy: 'reuse',
    }),

    // Bearer plugin - returns session token in set-auth-token header
    bearer(),

    // JWT plugin (required for OAuth provider)
    jwt(),

    // OAuth 2.1 Provider - enables third-party apps to authenticate users
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    oauthProvider({
      loginPage: `${origin}/auth/login`,
      consentPage: `${origin}/oauth/consent`,
      allowDynamicClientRegistration: dynamicClientRegistrationEnabled(),
      allowUnauthenticatedClientRegistration: dynamicClientRegistrationEnabled(),
      validAudiences: oauthValidAudiences(baseURL),
      scopes: [...OAUTH_SCOPES],
      clientRegistrationDefaultScopes: [...DEFAULT_OAUTH_SCOPES],
      clientRegistrationAllowedScopes: [...DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES],
      accessTokenExpiresIn: 300,
      refreshTokenExpiresIn: 60 * 60 * 24 * 7, // 7 days in seconds
      idTokenExpiresIn: 60 * 60, // 1 hour in seconds
      storeClientSecret: 'hashed',
      storeTokens: 'hashed',
      async customTokenResponseFields({ user, verificationValue }) {
        // This callback is invoked for every user token response before the
        // provider creates access/refresh tokens. Unlike customAccessTokenClaims,
        // it also runs for the provider's default opaque access-token path.
        const clientId = verificationValue?.query?.client_id;
        if (clientId) setOauthClientContext(clientId);
        return {};
      },
      async customAccessTokenClaims({ user, scopes }) {
        if (!user || !scopes.includes(TINYCLOUD_MCP_SCOPE)) return {};
        const client = await loadAuthoritativeOauthClient(prisma, currentOauthClientId());
        if (!client) return {};
        const keys = await prisma.ethereumKey.findMany({
          where: {
            userId: user.id,
            archivedAt: null,
          },
          select: { address: true },
          orderBy: { keyIndex: 'asc' },
        });
        return {
          [TINYCLOUD_OWNER_DIDS_CLAIM]: keys.map((key) =>
            `did:pkh:eip155:1:${key.address}`
          ),
        };
      },
      async customIdTokenClaims({ user, scopes }) {
        const claims: Record<string, unknown> = {};

        // Email claims
        const emailClaims = buildEmailClaims(user, scopes);
        Object.assign(claims, emailClaims);

        const client = await loadAuthoritativeOauthClient(prisma, currentOauthClientId());
        const keys = client
          ? await buildOauthKeyClaims(user, scopes, client)
          : [];
        if (keys) claims.keys = keys;
        const canonicalIdentity = await buildCanonicalTinyCloudIdentityClaim(
          user,
          scopes,
          client ?? undefined,
        );
        if (canonicalIdentity) claims[TINYCLOUD_CANONICAL_IDENTITY_CLAIM] = canonicalIdentity;

        return claims;
      },
      async customUserInfoClaims({ user, scopes, jwt }) {
        const claims: Record<string, unknown> = buildEmailClaims(user, scopes);
        const clientId = (jwt as { client_id?: string; azp?: string }).client_id ?? (jwt as { client_id?: string; azp?: string }).azp;
        const client = await loadAuthoritativeOauthClient(prisma, clientId);
        const keys = await buildUserInfoKeyClaims(
          user,
          scopes,
          client ?? undefined,
        );
        if (keys) claims.keys = keys;
        const canonicalIdentity = await buildCanonicalTinyCloudIdentityClaim(user, scopes, client ?? undefined);
        if (canonicalIdentity) claims[TINYCLOUD_CANONICAL_IDENTITY_CLAIM] = canonicalIdentity;
        return claims;
      },
    }) as any,
  ],

  // Provider entries are present only when every required secret is configured.
  socialProviders: createSocialProviders(process.env, async (providerAccountId) => {
    const account = await prisma.account.findFirst({
      where: {
        providerId: 'apple',
        accountId: providerAccountId,
      },
      select: {
        user: {
          select: {
            email: true,
            name: true,
            image: true,
          },
        },
      },
    });
    return account?.user ?? null;
  }),

  // Trust proxy for production (dstack gateway)
  trustedOrigins: socialProviderTrustedOrigins(origin),

  // Cross-subdomain cookies: session cookie set on api.openkey.so must be
  // readable by openkey.so (e.g. after Google OAuth redirect back to the web app).
  // In dev (localhost), cookies share the domain naturally so this is only needed in prod.
  advanced: {
    crossSubDomainCookies: crossSubDomainCookieOptions(isDev),
  },

  // Auto-generate an Ethereum key when a new user is created
  // User.autoSignEnabled is @default(true) in Prisma, so every new account
  // starts with bootstrap Auto-Sign enabled before this provisioning hook runs.
  databaseHooks: {
    user: {
      create: {
        after: async (user) => {
          try {
            const privateKey = generatePrivateKey();
            const address = getAddressFromPrivateKey(privateKey);
            const sealingContext = createSealingContext();
            const sealingKey = await tee.deriveKey(`openkey/key/${sealingContext}`);
            const sealedBlob = await seal(privateKey, sealingKey);

            await prisma.ethereumKey.create({
              data: {
                userId: user.id,
                address,
                publicKey: address,
                sealedBlob,
                sealingContext,
                isCanonicalTinyCloud: true,
                keyIndex: 0,
                label: 'Key 0',
              },
            });
            console.log(`[Auth] Auto-generated key for new user ${user.id}: ${address}`);
          } catch (error) {
            console.error(`[Auth] Failed to auto-generate key for user ${user.id}:`, error);
          }
        },
      },
    },
  },
});

// Export auth type for client
export type Auth = typeof auth;
