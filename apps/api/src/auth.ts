import { rememberSharePreviousSession, shareWindowAuthHooks } from './services/share-window-session';
// OpenKey API - better-auth configuration
import { generateOAuthClientSecret, hasOAuthClientId, hashOAuthClientSecret } from './services/oauth-client-secrets';
// Auth flow: email OTP by default, with optional passkey enrollment and sign-in.
import { betterAuth, type BetterAuthPlugin } from 'better-auth';
import { APIError, createAuthEndpoint, sensitiveSessionMiddleware } from 'better-auth/api';
import type { AuthMiddleware } from '@better-auth/core/api';
import { defineRequestState, getCurrentAuthContext, getCurrentAuthContextAsyncLocalStorage } from '@better-auth/core/context';
import { prismaAdapter } from 'better-auth/adapters/prisma';
import { passkey } from '@better-auth/passkey';
import { bearer, emailOTP, jwt } from 'better-auth/plugins';
import { oauthProvider } from '@better-auth/oauth-provider';
import { Resend } from 'resend';
import { getAddress } from 'viem';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { createTeeClient, seal, generatePrivateKey, getAddressFromPrivateKey } from '@openkey/tee';
import { buildEmailClaims } from './claims';
import {
  DEFAULT_OAUTH_SCOPES,
  DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES,
  isConfidentialWebClient,
  OAUTH_SCOPES,
  TINYCLOUD_CANONICAL_IDENTITY_CLAIM,
  TINYCLOUD_DELEGATION_SCOPE,
  TINYCLOUD_IDENTITY_SCOPE,
  TINYCLOUD_MANAGE_KEY_SCOPE,
  TINYCLOUD_MCP_SCOPE,
  TINYCLOUD_OWNER_DIDS_CLAIM,
  TINYCLOUD_SESSION_SCOPE,
  DEFAULT_ACCESS_TOKEN_EXPIRES_IN,
  accessTokenExpiresInFor,
  dynamicClientRegistrationEnabled,
  oauthValidAudiences,
} from './oauth-config';
import { createSealingContext } from './services/key-sealing';
import { primaryKeyWhere } from './services/primary-key';
import {
  assertFreshPasskeyUserVerification,
  recordPasskeyFreshnessAfterHook,
} from './services/passkey-freshness';
import { passkeyEnrolmentPlugin, type ResolvedSession } from './services/passkey-enrolment';
import {
  appleTokenClientId,
  appleTokenSignIn,
  configuredSocialProviderIds,
  createSocialProviders,
  socialProviderTrustedOrigins,
} from './social-providers';
import { appleRelayEmailUndeliverable } from './services/apple-notifications';
import { crossSubDomainCookieOptions } from './auth-options';
import { resolveRequestUri } from './services/native-delegation/par';
import { exchangeNativeCode, generateNativeRefreshToken, withNativeTokenGuardErrors } from './services/native-delegation/code-exchange';
import { providerTokenOptions } from './services/native-delegation/provider-tokens';
import { emailSignupConfirmation } from './services/email-signup-confirmation';
import { hasFreshEmailStepUp } from './services/email-otp-step-up';
import { confirmedSocialProvider, socialConfirmation } from './services/social-confirmation';
import { assertCurrentSocialLink, socialLinkStatePlugin } from './services/social-link-state';
import { socialMailboxReview } from './services/social-mailbox-review';
import { betterAuthLog, log, logError } from './log';
import { capSessionRefresh } from './services/session-cap';
import { SESSION_EXPIRES_IN_SECONDS, SESSION_UPDATE_AGE_SECONDS } from './services/session-lifetime';

export const prisma: PrismaClient = createPrismaClient();
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
  type: string | null;
  public: boolean;
  tokenEndpointAuthMethod: string | null;
};

const oauthClientContext = defineRequestState<string | undefined>(() => undefined);

async function loadAuthoritativeOauthClient(
  database: PrismaClient,
  clientId: string | undefined,
): Promise<AuthoritativeOauthClient | null> {
  if (!clientId) return null;
  return database.oauthClient.findFirst({
    where: { clientId },
    select: { id: true, type: true, public: true, tokenEndpointAuthMethod: true },
  });
}

export async function buildKeyClaims(
  user: { id: string; email: string; emailVerified: boolean },
  scopes: string[],
  client: AuthoritativeOauthClient | undefined,
  _mutate = false,
  database: PrismaClient = prisma,
) {
  if (scopes.includes(TINYCLOUD_IDENTITY_SCOPE) && !scopes.includes(TINYCLOUD_MANAGE_KEY_SCOPE)) {
    return undefined;
  }
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
  const hasManageKey = scopes.includes(TINYCLOUD_MANAGE_KEY_SCOPE);
  const hasIdentity = scopes.includes(TINYCLOUD_IDENTITY_SCOPE);
  if ((!hasManageKey && !hasIdentity) || !client) return undefined;
  if (!hasManageKey && (!hasIdentity || !isConfidentialWebClient(client))) return undefined;
  const key = await database.ethereumKey.findFirst({
    where: primaryKeyWhere(user.id),
    select: { id: true, address: true },
  });
  if (!key) return undefined;
  const address = getAddress(key.address);
  if (hasManageKey) {
    return {
      version: 'v1',
      keyId: key.id,
      address,
      chainId: 1,
      did: `did:pkh:eip155:1:${address}`,
      spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
    };
  }
  return {
    version: 'v1',
    address,
    chainId: 1,
    did: `did:pkh:eip155:1:${address}`,
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

// Resolve the incoming browser cookie before login endpoints replace it. These endpoints
// do not otherwise populate context.session before their createSession call.
const shareSessionReplacementPlugin = {
  id: 'share-session-replacement',
  hooks: { before: [{
    matcher: (ctx) => ctx.path?.startsWith('/sign-in/') || ctx.path?.startsWith('/sign-up/') || ctx.path?.startsWith('/callback/') ||
      ctx.path === '/passkey/verify-authentication' || ctx.path === '/email-otp/verify-email' ||
      ctx.path === '/social/confirm' || ctx.path === '/social/email-sign-in/confirm',
    handler: (async (ctx: { headers?: Headers; context: object }) => {
      if (!ctx.headers?.get('cookie')) return;
      const previous = await auth.api.getSession({ headers: ctx.headers });
      if (previous) rememberSharePreviousSession(ctx.context, previous.session);
    }) as AuthMiddleware,
  }] },
} satisfies BetterAuthPlugin;

const passkeyFreshnessPlugin = {
  id: 'openkey-passkey-freshness',
  hooks: {
    after: [{
      matcher: (ctx) => ctx.path === '/passkey/verify-authentication',
      handler: (async (ctx: { path?: string; headers?: Headers; body?: unknown; context: { returned?: unknown } }) => {
        return recordPasskeyFreshnessAfterHook(
          prisma,
          ctx.context.returned,
          ctx.headers?.get('x-openkey-passkey-ceremony'),
          (ctx.body as { response?: { id?: unknown } } | undefined)?.response?.id,
        );
      }) as AuthMiddleware,
    }],
  },
} satisfies BetterAuthPlugin;

const accountLinkingStepUpPlugin = {
  id: 'openkey-account-linking-step-up',
  hooks: {
    before: [{
      matcher: (ctx) => ctx.path === '/link-social' || ctx.path === '/unlink-account',
      handler: (async (ctx: { path: string; headers?: Headers; body?: unknown }) => {
        const session = ctx.headers ? await auth.api.getSession({ headers: ctx.headers }) : null;
        if (!session || !await hasFreshEmailStepUp(prisma, session.session.id)) {
          throw new APIError('FORBIDDEN', {
            code: 'EMAIL_STEP_UP_REQUIRED',
            message: 'Verify an email code before changing linked accounts.',
          });
        }
        if (ctx.path === '/unlink-account'
          && (ctx.body as { providerId?: unknown } | undefined)?.providerId === 'apple') {
          throw new APIError('FORBIDDEN', {
            code: 'APPLE_UNLINK_REQUIRES_REVOCATION',
            message: 'Use the revocation-protected account unlink endpoint.',
          });
        }
        if (ctx.path === '/unlink-account' && await prisma.passkey.count({ where: { userId: session.user.id } }) === 0
          && (!session.user.emailVerified
            || await appleRelayEmailUndeliverable(prisma, session.user.id, session.user.email))) {
          throw new APIError('FORBIDDEN', {
            code: 'LAST_SIGN_IN_METHOD',
            message: 'Add a passkey or a deliverable verified email before unlinking this account.',
          });
        }
      }) as AuthMiddleware,
    }],
  },
} satisfies BetterAuthPlugin;

// Better Auth's authorize endpoint otherwise strips extension query keys
// before the OAuth handler sees them. PAR's resolver and the full-query guard
// establish the native bindings; extending the schema keeps them signed.
function withNativeAuthorizeQuery<T extends ReturnType<typeof oauthProvider>>(plugin: T): T {
  const endpoint = plugin.endpoints.oauth2Authorize;
  endpoint.options.query = endpoint.options.query.extend({
    tinycloud_request: endpoint.options.query.shape.client_id.optional(),
    login_method: endpoint.options.query.shape.client_id.optional(),
  });
  return plugin;
}

// The provider reads `accessTokenExpiresIn` from one options object for every token request, and has no hook for a
// per-audience value. The request's own `resource` (the audience the token is issued for) is in the endpoint context
// Better Auth already keeps per request, so read the lifetime from it when the provider asks. `scopeExpirations` and
// `customAccessTokenClaims` cannot do this: the first can only shorten, the second cannot change `exp`.
// `getCurrentAuthContextAsyncLocalStorage` is marked internal by Better Auth and its async sibling cannot serve a
// synchronous getter; @better-auth/oauth-provider is pinned exactly and oauth-mcp-token-lifetime.test.ts (real provider,
// interleaved requests) fails if an upgrade changes how the provider reads the option.
const endpointContext = await getCurrentAuthContextAsyncLocalStorage();
/** The `resource` the endpoint call in progress was made with, if any. */
function currentRequestResource(): unknown {
  return (endpointContext.getStore()?.body as { resource?: unknown } | undefined)?.resource;
}
function withMcpAccessTokenLifetime<T extends ReturnType<typeof oauthProvider>>(plugin: T): T {
  Object.defineProperty(plugin.options, 'accessTokenExpiresIn', {
    enumerable: true,
    get: () => accessTokenExpiresInFor(currentRequestResource()),
  });
  return plugin;
}

// R9 (plan TC-1188 §2): a locked user's live sessions and OAuth tokens stop
// resolving everywhere Better Auth looks them up, including bearer sessions
// (the bearer plugin resolves through the same session lookup), the OAuth
// refresh grant and opaque access-token validation. The filter is on Better
// Auth's client only; OpenKey's own reads keep seeing the rows.
function withLockedUserFilter(db: PrismaClient): PrismaClient {
  const unlocked = { user: { lockedAt: null } };
  const filter = ({ args, query }: { args: { where?: object }; query: (args: unknown) => Promise<unknown> }) =>
    query({ ...args, where: args.where ? { AND: [args.where, unlocked] } : unlocked });
  const reads = { findFirst: filter, findMany: filter };
  return db.$extends({
    query: { session: reads, oauthAccessToken: reads, oauthRefreshToken: reads },
  }) as unknown as PrismaClient;
}

export const auth = betterAuth({
  baseURL,
  basePath: '/api/auth',
  secret: process.env.BETTER_AUTH_SECRET,
  disabledPaths: ['/token'], // Avoid conflicts with OAuth token endpoint
  logger: {
    level: 'debug',
    disableColors: true,
    log: betterAuthLog,
  },

  database: prismaAdapter(withLockedUserFilter(withNativeTokenGuardErrors(prisma)), {
    provider: 'postgresql',
    transaction: true,
  }),

  // Passwords stay disabled; email OTP is the default authentication path.
  emailAndPassword: {
    enabled: false,
  },

  // Session configuration
  session: {
    expiresIn: SESSION_EXPIRES_IN_SECONDS, // 7 days
    updateAge: SESSION_UPDATE_AGE_SECONDS, // Update session every 24 hours
    storeSessionInDatabase: true, // Required for OAuth provider
  },

  user: {
    additionalFields: {
      socialCreatedProvider: { type: 'string', required: false, input: false, returned: false },
      socialEmailReviewedAt: { type: 'date', required: false, input: false, returned: false },
      lockedAt: { type: 'date', required: false, input: false, returned: false },
    },
  },

  account: {
    additionalFields: {
      appleClientId: { type: 'string', required: false, input: false, returned: false },
      appleRestoredAt: { type: 'date', required: false, input: false, returned: false },
      revokedAt: { type: 'date', required: false, input: false, returned: false },
    },
    encryptOAuthTokens: true,
    accountLinking: {
      disableImplicitLinking: true,
      allowDifferentEmails: true,
      allowUnlinkingAll: true,
      trustedProviders: configuredSocialProviderIds(process.env).includes('apple') ? ['apple'] : [],
    },
  },

  plugins: [
    shareSessionReplacementPlugin,
    {
      id: 'revoke-other-sessions',
      endpoints: {
        revokeOtherSessions: createAuthEndpoint('/revoke-other-sessions', {
          method: 'POST',
          requireHeaders: true,
          use: [sensitiveSessionMiddleware],
        }, async (ctx) => {
          const session = ctx.context.session;
          await prisma.session.deleteMany({ where: { userId: session.user.id, token: { not: session.session.token } } });
          return ctx.json({ status: true });
        }),
      },
    },
    passkeyFreshnessPlugin,
    // TC-1198: passkey enrolment and removal need a fresh step-up.
    passkeyEnrolmentPlugin(prisma, (headers): Promise<ResolvedSession | null> => auth.api.getSession({ headers })),
    accountLinkingStepUpPlugin,
    socialLinkStatePlugin(prisma),
    socialConfirmation(prisma),
    socialMailboxReview(prisma),
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

    // Email OTP is the default registration and sign-in method. A verified code
    // for an unknown email asks the user to confirm before an account exists.
    emailOTP({
      async sendVerificationOTP({ email, otp, type }) {
        if (!resend) {
          if (isDev) log('warn', 'otp_delivery_unconfigured');
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
    emailSignupConfirmation(prisma),

    // Bearer plugin - returns session token in set-auth-token header
    bearer(),

    // JWT plugin (required for OAuth provider)
    jwt(),

    // OAuth 2.1 Provider - enables third-party apps to authenticate users
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    withMcpAccessTokenLifetime(withNativeAuthorizeQuery(oauthProvider({
      clientPrivileges: async ({ action }) => {
        if (action === 'create' || action === 'list') return true;
        const request = await getCurrentAuthContext();
        const clientId = action === 'read' ? request.query?.client_id : request.body?.client_id;
        if (!hasOAuthClientId(clientId)) return false;
        const organizationClient = await prisma.oauthClient.findFirst({
          where: { clientId, organizationId: { not: null } },
          select: { id: true },
        });
        return !organizationClient;
      },
      requestUriResolver: ({ requestUri, clientId }) => resolveRequestUri(prisma, requestUri, clientId),
      loginPage: `${origin}/auth/login`,
      consentPage: `${origin}/oauth/consent`,
      allowDynamicClientRegistration: dynamicClientRegistrationEnabled(),
      allowUnauthenticatedClientRegistration: dynamicClientRegistrationEnabled(),
      validAudiences: oauthValidAudiences(baseURL),
      scopes: [...OAUTH_SCOPES],
      clientRegistrationDefaultScopes: [...DEFAULT_OAUTH_SCOPES],
      clientRegistrationAllowedScopes: [...DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES],
      accessTokenExpiresIn: DEFAULT_ACCESS_TOKEN_EXPIRES_IN, // replaced per request by withMcpAccessTokenLifetime
      refreshTokenExpiresIn: 60 * 60 * 24 * 7, // 7 days in seconds
      idTokenExpiresIn: 60 * 60, // 1 hour in seconds
      storeClientSecret: { hash: hashOAuthClientSecret },
      generateClientSecret: generateOAuthClientSecret,
      storeTokens: 'hashed',
      generateRefreshToken: (): Promise<string> => generateNativeRefreshToken(prisma, providerTokenOptions(auth)),
      async customTokenResponseFields({ grantType, user, scopes, verificationValue }) {
        // R9: no grant (authorization code or refresh) issues tokens to a
        // locked user, whatever was authorized before the lock.
        if (user && (await prisma.user.findUnique({ where: { id: user.id }, select: { lockedAt: true } }))?.lockedAt) {
          throw new APIError('BAD_REQUEST', { error: 'invalid_grant', error_description: 'The account is locked' });
        }
        // Runs before any access, refresh or ID token is created. A token
        // carrying tinycloud:delegation comes only from the native code
        // exchange, never from the provider's other grants.
        let nativeFields: Record<string, unknown> = {};
        if (grantType === 'authorization_code') {
          nativeFields = await exchangeNativeCode(prisma, `${baseURL}/api/auth`, { user, scopes, verificationValue });
        } else if (scopes.includes(TINYCLOUD_DELEGATION_SCOPE)) {
          throw new APIError('BAD_REQUEST', {
            error: 'invalid_grant',
            error_description: `${TINYCLOUD_DELEGATION_SCOPE} is not issued by this grant`,
          });
        }
        // Runs after the provider authenticates the client, before either
        // opaque/JWT access tokens or the ID token are created. Refresh has no
        // verificationValue: resolve the same request credentials the provider
        // validated, including Basic-header precedence over body client_id.
        let clientId = verificationValue?.query?.client_id;
        if (grantType === 'refresh_token') {
          const ctx = await getCurrentAuthContext();
          const authorization = ctx.request?.headers.get('authorization');
          clientId = authorization?.startsWith('Basic ')
            ? Buffer.from(authorization.slice(6), 'base64').toString('utf8').split(':', 1)[0]
            : ctx.body?.client_id;
        }
        // A 12 hour token is for the hosted MCP only: asking for an MCP resource without the MCP scope is refused, so
        // the long lifetime cannot be minted by a client that was never consented to MCP access.
        if (accessTokenExpiresInFor(currentRequestResource()) > DEFAULT_ACCESS_TOKEN_EXPIRES_IN && !scopes.includes(TINYCLOUD_MCP_SCOPE)) {
          throw new APIError('BAD_REQUEST', {
            error: 'invalid_scope',
            error_description: `${TINYCLOUD_MCP_SCOPE} is required for this resource`,
          });
        }
        await oauthClientContext.set(clientId);
        return nativeFields;
      },
      async customAccessTokenClaims({ user, scopes }) {
        if (!user || !scopes.includes(TINYCLOUD_MCP_SCOPE)) return {};
        const client = await loadAuthoritativeOauthClient(prisma, await oauthClientContext.get());
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

        const client = await loadAuthoritativeOauthClient(prisma, await oauthClientContext.get());
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
    }))) as any,
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
    // Web sessions end at most WEB_SESSION_ABSOLUTE_CAP_SECONDS after sign-in (services/session-cap.ts).
    session: {
      create: { after: async (session, context) => { shareWindowAuthHooks.created(session, context); } },
      delete: { after: async (session) => { shareWindowAuthHooks.deleted(session); } },
      update: {
        before: capSessionRefresh,
        after: async (session) => { shareWindowAuthHooks.updated(session); },
      },
    },
    user: {
      create: {
        before: async (user) => {
          if (user.emailVerified !== true) {
            throw new APIError('FORBIDDEN', {
              code: 'UNVERIFIED_EMAIL',
              message: 'A verified email is required to create an OpenKey account.',
            });
          }
          const socialProvider = await confirmedSocialProvider.get();
          if (socialProvider) return { data: { socialCreatedProvider: socialProvider } };
        },
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
            log('info', 'auth_key_generated');
          } catch (error) {
            logError('error', 'auth_key_generation_failed', error);
          }
        },
      },
    },
    account: {
      create: { before: async (account) => {
        if (account.providerId === 'google' || account.providerId === 'apple') {
          await assertCurrentSocialLink(prisma, account.providerId, account.userId);
        }
        if (account.providerId === 'apple') {
          const clientId = await appleTokenClientId.get();
          if (!clientId) throw new APIError('FORBIDDEN', {
            code: 'APPLE_ISSUING_CLIENT_UNKNOWN',
            message: 'The Apple token issuer was not verified.',
          });
          // Linking (or confirmed creation) restores the Apple identity now. In
          // whole seconds, Apple's event_time unit: a revocation from before
          // this second is ignored, one from this second or later applies.
          const restoredAt = new Date(Math.floor(Date.now() / 1000) * 1000);
          return { data: { appleClientId: clientId, appleRestoredAt: restoredAt } };
        }
      } },
      update: { before: async (account) => {
        await assertCurrentSocialLink(prisma);
        const clientId = await appleTokenClientId.get();
        if (clientId && (account.refreshToken !== undefined || account.accessToken !== undefined)) {
          // A sign-in by `sub` restores the link: it clears revokedAt, and
          // appleRestoredAt advances to the later of its value and the id_token
          // iat in one statement, so concurrent sign-ins never move it back.
          const signIn = await appleTokenSignIn.get();
          if (!signIn) return { data: { appleClientId: clientId } };
          const issuedAt = new Date(signIn.issuedAt * 1000);
          // Postgres re-checks the condition on the locked row, so the later value wins.
          await prisma.account.updateMany({
            where: {
              providerId: 'apple', accountId: signIn.sub,
              OR: [{ appleRestoredAt: null }, { appleRestoredAt: { lt: issuedAt } }],
            },
            data: { appleRestoredAt: issuedAt },
          });
          return { data: { appleClientId: clientId, revokedAt: null } };
        }
      } },
    },
  },
});

// Export auth type for client
export type Auth = typeof auth;
