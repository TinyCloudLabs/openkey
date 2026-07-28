// OpenKey API - better-auth configuration
// Auth flow: email OTP by default, with optional passkey enrollment and sign-in.
import { betterAuth, type BetterAuthPlugin } from 'better-auth';
import { APIError, getSessionFromCtx } from 'better-auth/api';
import { parseSetCookieHeader } from 'better-auth/cookies';
import type { AuthMiddleware } from '@better-auth/core/api';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { passkey } from '@better-auth/passkey';
import { bearer, emailOTP, jwt } from 'better-auth/plugins';
import { oauthProvider } from '@better-auth/oauth-provider';
import { Resend } from 'resend';
import { createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { createTeeClient, seal, generatePrivateKey, getAddressFromPrivateKey } from '@openkey/tee';
import { buildEmailClaims } from './claims';
import {
  DEFAULT_OAUTH_SCOPES,
  OAUTH_SCOPES,
  TINYCLOUD_MCP_SCOPE,
  TINYCLOUD_OWNER_DIDS_CLAIM,
  dynamicClientRegistrationEnabled,
  oauthValidAudiences,
} from './oauth-config';
import { createSealingContext } from './services/key-sealing';
import {
  ensureTenantManagedAccountForVerifiedEmail,
  normalizeSubjectEmail,
} from './services/tenant-managed-accounts';
import {
  assertFreshPasskeyUserVerification,
  recordPasskeyFreshnessAfterHook,
} from './services/passkey-freshness';

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
  mode: 'PERSONAL' | 'TENANT_MANAGED';
  organizationId: string | null;
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
    select: { mode: true, organizationId: true },
  });
}

export async function buildKeyClaims(
  user: { id: string; email: string; emailVerified: boolean },
  scopes: string[],
  client: AuthoritativeOauthClient | undefined,
  mutate = false,
  database: PrismaClient = prisma,
) {
  if (!scopes.includes('keys')) return undefined;
  if (!client) return [];
  if (client.mode === 'TENANT_MANAGED') {
    if (!client.organizationId) {
      console.error('[Auth] Tenant-managed OAuth client is missing organizationId');
      return [];
    }
    if (!user.emailVerified) return [];
    if (mutate) {
      const ensured = await ensureTenantManagedAccountForVerifiedEmail(database, {
          organizationId: client.organizationId,
          email: user.email,
          userId: user.id,
        });
      const account = await database.managedAccount.findFirst({
        where: {
          id: ensured.id,
          organizationId: client.organizationId,
          subjectEmail: normalizeSubjectEmail(user.email),
          state: { notIn: ['DISABLED', 'USER_OWNED'] },
          OR: [{ ownerUserId: null }, { ownerUserId: user.id }],
        },
        select: {
          key: { select: { id: true, address: true, keyType: true } },
        },
      });
      return account ? [{
        address: account.key.address,
        keyType: account.key.keyType,
        keyId: account.key.id,
      }] : [];
    }
    // Fail closed: only return the key if the account is unbound or bound to this user.
    const account = await database.managedAccount.findFirst({
      where: {
        organizationId: client.organizationId,
        subjectEmail: normalizeSubjectEmail(user.email),
        state: { notIn: ['DISABLED', 'USER_OWNED'] },
        OR: [{ ownerUserId: null }, { ownerUserId: user.id }],
      },
      select: {
        key: { select: { id: true, address: true, keyType: true } },
      },
    });
    return account ? [{
      address: account.key.address,
      keyType: account.key.keyType,
      keyId: account.key.id,
    }] : [];
  }

  const keys = await database.ethereumKey.findMany({
    where: {
      userId: user.id,
      keyPurpose: 'PERSONAL',
      archivedAt: null,
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
  try {
    return await buildKeyClaims(user, scopes, client, true, database);
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error
      ? (error as { code?: unknown }).code
      : undefined;
    if (code === 'TENANT_ACCESS_ENDED') {
      throw APIError.from('FORBIDDEN', {
        code,
        message: 'This account is now user-owned and the tenant can no longer access it.',
      });
    }
    if (code === 'ACCOUNT_DISABLED') {
      throw APIError.from('FORBIDDEN', {
        code,
        message: 'This tenant-managed account is disabled.',
      });
    }
    if (code === 'ACCOUNT_IDENTITY_CONFLICT') {
      throw APIError.from('FORBIDDEN', {
        code,
        message: 'This email is already associated with an account owned by another user.',
      });
    }
    throw error;
  }
}

/**
 * Userinfo variant: checks account state at the userinfo endpoint without
 * provisioning. Throws FORBIDDEN for disabled or ejected accounts so that
 * already-issued tokens cannot retrieve stale key claims.
 */
export async function buildUserInfoKeyClaims(
  user: { id: string; email: string; emailVerified: boolean },
  scopes: string[],
  client: AuthoritativeOauthClient | undefined,
  database: PrismaClient = prisma,
) {
  if (!scopes.includes('keys')) return undefined;
  if (!client) return [];
  if (client.mode !== 'TENANT_MANAGED') {
    return buildKeyClaims(user, scopes, client, false, database);
  }
  if (!client.organizationId || !user.emailVerified) return [];
  // Fail closed: only return the key if the account is unbound or bound to this user.
  const account = await database.managedAccount.findFirst({
    where: {
      organizationId: client.organizationId,
      subjectEmail: normalizeSubjectEmail(user.email),
      OR: [{ ownerUserId: null }, { ownerUserId: user.id }],
    },
    select: { state: true, key: { select: { id: true, address: true, keyType: true } } },
  });
  if (!account) return [];
  if (account.state === 'DISABLED') {
    throw APIError.from('FORBIDDEN', {
      code: 'ACCOUNT_DISABLED',
      message: 'This tenant-managed account is disabled.',
    });
  }
  if (account.state === 'USER_OWNED') {
    throw APIError.from('FORBIDDEN', {
      code: 'TENANT_ACCESS_ENDED',
      message: 'This account is now user-owned and the tenant can no longer access it.',
    });
  }
  if (account.state !== 'MANAGED') return [];
  return [{ address: account.key.address, keyType: account.key.keyType, keyId: account.key.id }];
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

/**
 * Enforce tenant-managed account state. Fails closed: disabled or ejected
 * accounts may not obtain or refresh OAuth tokens.
 */
async function enforceTenantManagedAccountStateForOrg(
  database: PrismaClient,
  organizationId: string,
  userEmail: string,
  userEmailVerified: boolean | undefined,
) {
  if (!userEmailVerified) {
    throw APIError.from('FORBIDDEN', {
      code: 'EMAIL_NOT_VERIFIED',
      message: 'A verified email is required for tenant-managed OAuth access.',
    });
  }
  const account = await database.managedAccount.findFirst({
    where: {
      organizationId,
      subjectEmail: normalizeSubjectEmail(userEmail),
    },
    select: { state: true },
  });
  if (!account) return;
  if (account.state === 'DISABLED') {
    throw APIError.from('FORBIDDEN', {
      code: 'ACCOUNT_DISABLED',
      message: 'This tenant-managed account is disabled.',
    });
  }
  if (account.state === 'USER_OWNED') {
    throw APIError.from('FORBIDDEN', {
      code: 'TENANT_ACCESS_ENDED',
      message: 'This account is now user-owned and the tenant can no longer access it.',
    });
  }
}

async function enforceTenantManagedAccountStateForClient(
  database: PrismaClient,
  clientId: string,
  user: { email: string; emailVerified?: boolean },
) {
  const client = await database.oauthClient.findFirst({
    where: { clientId },
    select: { mode: true, organizationId: true },
  });
  if (!client || client.mode !== 'TENANT_MANAGED') return;
  if (!client.organizationId) {
    throw APIError.from('FORBIDDEN', {
      code: 'TENANT_CLIENT_MISCONFIGURED',
      message: 'This tenant-managed OAuth client is not associated with an organization.',
    });
  }
  await enforceTenantManagedAccountStateForOrg(database, client.organizationId, user.email, user.emailVerified);
}

async function hashOauthProviderToken(token: string) {
  return createHash('sha256').update(token).digest('base64url');
}

function oauthClientIdFromTokenRequest(
  body: { client_id?: string } | undefined,
  headers: Headers | undefined,
) {
  const authorization = headers?.get('authorization');
  if (authorization?.startsWith('Basic ')) {
    try {
      const decoded = Buffer.from(authorization.slice('Basic '.length), 'base64').toString('utf8');
      const separator = decoded.indexOf(':');
      if (separator > 0) return decoded.slice(0, separator);
    } catch {
      // The OAuth provider will return the authoritative invalid_client error.
    }
  }
  return body?.client_id;
}

/**
 * Plugin that enforces tenant-managed account lifecycle at every authorization-code
 * issuance boundary. The token endpoint is covered by customTokenResponseFields,
 * which runs after the provider has resolved the user and before it creates any
 * access or refresh token, including opaque tokens.
 */
function createTenantManagedLifecyclePlugin(database: PrismaClient) {
  return {
  id: 'openkey-tenant-managed-lifecycle',
  hooks: {
    before: [
      {
        // Refresh callbacks do not receive the client ID. Resolve the opaque
        // refresh token here so lifecycle checks use the authoritative client
        // columns rather than JSON metadata.
        matcher: (ctx: { path?: string }) => ctx.path === '/oauth2/token',
        handler: (async (ctx: {
          headers?: Headers;
          body?: { grant_type?: string; client_id?: string; refresh_token?: string; code?: string };
        }) => {
          // client_secret_basic carries client_id only in Authorization. The
          // provider accepts all three advertised methods, so resolve the
          // authoritative client from the same request representation before
          // looking up the user for refresh/code lifecycle enforcement.
          const body = ctx.body;
          const clientId = oauthClientIdFromTokenRequest(body, ctx.headers);
          if (!clientId) return;
          const client = await database.oauthClient.findFirst({
            where: { clientId },
            select: { mode: true, organizationId: true },
          });
          setOauthClientContext(clientId);
          if (!client || client.mode !== 'TENANT_MANAGED') return;
          if (!client.organizationId) {
            throw APIError.from('FORBIDDEN', {
              code: 'TENANT_CLIENT_MISCONFIGURED',
              message: 'This tenant-managed OAuth client is not associated with an organization.',
            });
          }
          let userId: string | undefined;
          if (body?.grant_type === 'refresh_token' && body.refresh_token) {
            const refreshToken = await database.oauthRefreshToken.findFirst({
              where: { token: await hashOauthProviderToken(body.refresh_token) },
              select: { userId: true },
            });
            userId = refreshToken?.userId;
          } else if (body?.grant_type === 'authorization_code' && body.code) {
            const verification = await database.verification.findFirst({
              where: { identifier: await hashOauthProviderToken(body.code) },
              select: { value: true },
            });
            if (verification) {
              try {
                userId = (JSON.parse(verification.value) as { userId?: unknown }).userId as string | undefined;
              } catch {
                return;
              }
            }
          } else return;
          if (!userId) return;
          const user = await database.user.findUnique({
            where: { id: userId },
            select: { email: true, emailVerified: true },
          });
          if (!user) return;
          await enforceTenantManagedAccountStateForOrg(database, client.organizationId, user.email, user.emailVerified);
        }) as AuthMiddleware,
      },
      {
        // /oauth2/authorize may issue a code immediately when consent already
        // exists. /oauth2/consent and /oauth2/continue can also reach the
        // provider's code issuance helper, so all three resolve the session
        // explicitly instead of assuming a before-hook has done so.
        matcher: (ctx: { path?: string }) =>
          ctx.path === '/oauth2/authorize'
          || ctx.path === '/oauth2/consent'
          || ctx.path === '/oauth2/continue',
        handler: (async (ctx: {
          path?: string;
          query?: Record<string, string>;
          body?: { oauth_query?: string };
          context?: { session?: { user?: { email?: string; emailVerified?: boolean } } };
        }) => {
          const query = ctx.body?.oauth_query
            ? new URLSearchParams(ctx.body.oauth_query)
            : undefined;
          const clientId = ctx.query?.client_id ?? query?.get('client_id') ?? undefined;
          if (!clientId) return;
          setOauthClientContext(clientId);
          const session = await getSessionFromCtx(ctx as never);
          const user = session?.user;
          if (!user?.email) return;
          await enforceTenantManagedAccountStateForClient(database, clientId, user);
        }) as AuthMiddleware,
      },
    ],
    after: [
      {
        // Better Auth's OAuth provider after-hook resumes authorization after
        // sign-in by consuming the OAuth query and newly-created session cookie.
        // Run before that provider hook so a disabled, user-owned, or
        // unverified tenant identity cannot receive a code after login.
        matcher: (ctx: {
          body?: { oauth_query?: string };
          context?: { responseHeaders?: Headers };
        }) => Boolean(ctx.body?.oauth_query && ctx.context?.responseHeaders?.get('set-cookie')),
        handler: (async (ctx: {
          body?: { oauth_query?: string };
          context: {
            responseHeaders?: Headers;
            authCookies: { sessionToken: { name: string } };
            internalAdapter: { findSession: (token: string) => Promise<{ user: { email: string; emailVerified?: boolean } } | null> };
          };
        }) => {
          const clientId = new URLSearchParams(ctx.body?.oauth_query).get('client_id');
          setOauthClientContext(clientId ?? undefined);
          const sessionToken = clientId
            ? parseSetCookieHeader(ctx.context.responseHeaders?.get('set-cookie') ?? '')
                .get(ctx.context.authCookies.sessionToken.name)?.value?.split('.')[0]
            : undefined;
          if (!clientId || !sessionToken) return;
          const session = await ctx.context.internalAdapter.findSession(sessionToken);
          const user = session?.user;
          if (!user?.email) return;
          try {
            await enforceTenantManagedAccountStateForClient(database, clientId, user);
          } catch (error) {
            // The OAuth provider's own after-hook runs later and would otherwise
            // resume authorization after handling this error. Removing the new
            // session cookie makes that hook a no-op before rethrowing the deny.
            ctx.context.responseHeaders?.delete('set-cookie');
            throw error;
          }
          return {};
        }) as AuthMiddleware,
      },
    ],
  },
  } satisfies BetterAuthPlugin;
}

const tenantManagedLifecyclePlugin = createTenantManagedLifecyclePlugin(prisma);

export const auth = betterAuth({
  baseURL,
  basePath: '/api/auth',
  secret: process.env.BETTER_AUTH_SECRET,
  disabledPaths: ['/token'], // Avoid conflicts with OAuth token endpoint
  logger: {
    level: 'debug',
    log: (level, message, ...args) => {
      console.log(`[Better Auth] [${level}]`, message, ...args);
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
    tenantManagedLifecyclePlugin,
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
      clientRegistrationAllowedScopes: [...OAUTH_SCOPES],
      accessTokenExpiresIn: 60 * 60, // 1 hour in seconds
      refreshTokenExpiresIn: 60 * 60 * 24 * 7, // 7 days in seconds
      idTokenExpiresIn: 60 * 60, // 1 hour in seconds
      storeClientSecret: 'hashed',
      async customTokenResponseFields({ user, verificationValue }) {
        // This callback is invoked for every user token response before the
        // provider creates access/refresh tokens. Unlike customAccessTokenClaims,
        // it also runs for the provider's default opaque access-token path.
        const clientId = verificationValue?.query?.client_id;
        if (clientId) setOauthClientContext(clientId);
        if (clientId && user) await enforceTenantManagedAccountStateForClient(prisma, clientId, user);
        return {};
      },
      async customAccessTokenClaims({ user, scopes }) {
        if (!user || !scopes.includes(TINYCLOUD_MCP_SCOPE)) return {};
        const client = await loadAuthoritativeOauthClient(prisma, currentOauthClientId());
        if (!client || client.mode !== 'PERSONAL') return {};
        const keys = await prisma.ethereumKey.findMany({
          where: {
            userId: user.id,
            keyPurpose: 'PERSONAL',
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

        return claims;
      },
      async customUserInfoClaims({ user, scopes, jwt }) {
        const claims: Record<string, unknown> = {};
        if (scopes.includes('email')) {
          claims.email = user.email;
          claims.emailVerified = user.emailVerified;
        }
        const clientId = (jwt as { client_id?: string; azp?: string }).client_id ?? (jwt as { client_id?: string; azp?: string }).azp;
        const client = await loadAuthoritativeOauthClient(prisma, clientId);
        const keys = await buildUserInfoKeyClaims(
          user,
          scopes,
          client ?? undefined,
        );
        if (keys) claims.keys = keys;
        return claims;
      },
    }) as any,
  ],

  // Do not advertise provider flows that are not actually configured.
  socialProviders: process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
    ? {
        google: {
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        },
      }
    : {},

  // Trust proxy for production (dstack gateway)
  trustedOrigins: [origin],

  // Cross-subdomain cookies: session cookie set on api.openkey.so must be
  // readable by openkey.so (e.g. after Google OAuth redirect back to the web app).
  // In dev (localhost), cookies share the domain naturally so this is only needed in prod.
  advanced: {
    crossSubDomainCookies: isDev
      ? { enabled: false }
      : { enabled: true, domain: '.openkey.so' },
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
                keyPurpose: 'PERSONAL',
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
