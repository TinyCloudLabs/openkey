import { createHash } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import type { SessionContext } from './session';
import { TINYCLOUD_MANAGE_KEY_SCOPE, TINYCLOUD_SESSION_SCOPE } from '../oauth-config';

export type DelegateSignerPrincipal =
  | { kind: 'session'; userId: string }
  | {
      kind: 'oauth-manage-key';
      userId: string;
      clientId: string;
      oauthAccessTokenId: string;
      tokenDigest: string;
    }
  | {
      kind: 'coordinationos-oauth';
      userId: string;
      clientId: string;
      oauthAccessTokenId: string;
      tokenDigest: string;
    };

export type DelegateSignerAuthCode =
  | 'missing_authorization'
  | 'malformed_authorization'
  | 'multiple_authorization'
  | 'unknown_token'
  | 'token_expired'
  | 'token_too_old'
  | 'wrong_client'
  | 'client_disabled'
  | 'client_misconfigured'
  | 'missing_scope'
  | 'user_not_found'
  | 'email_not_verified';

export type CoordinationosOauthContext = {
  token: {
    id: string;
    clientId: string;
    userId: string;
    scopes: string[];
    createdAt: Date;
    expiresAt: Date;
  };
  client: {
    clientId: string;
    disabled: boolean;
    mode: string;
    type: string | null;
    public: boolean;
    tokenEndpointAuthMethod: string | null;
    grantTypes: string[];
    responseTypes: string[];
    scopes: string[];
    tinycloudSessionPolicy: string | null;
    tinycloudSessionOrigin: string | null;
  } | null;
  user: { id: string; emailVerified: boolean } | null;
};

export type DelegateSignerAuthFailure = {
  code: DelegateSignerAuthCode;
  oauthAccessTokenId: string | null;
  tokenDigest: string | null;
  clientId: string | null;
  userId: string | null;
};

export type DelegateSignerContext = SessionContext & {
  Variables: SessionContext['Variables'] & {
    delegateSignerPrincipal: DelegateSignerPrincipal | null;
    delegateSignerOauthContext: CoordinationosOauthContext | null;
    delegateSignerAuthFailure: DelegateSignerAuthFailure | null;
  };
};

export type ParsedDelegateAuthorization =
  | { kind: 'missing' }
  | { kind: 'malformed' }
  | { kind: 'multiple' }
  | { kind: 'bearer'; token: string };

export function parseDelegateAuthorization(value: string | null): ParsedDelegateAuthorization {
  if (value === null || value === '') return { kind: 'missing' };
  if (value.includes(',')) return { kind: 'multiple' };
  const match = /^Bearer ([A-Za-z0-9_-]+)$/i.exec(value);
  if (!match) return { kind: 'malformed' };
  return { kind: 'bearer', token: match[1]! };
}

export function oauthTokenLookupDigest(rawBearer: string): string {
  return createHash('sha256').update(rawBearer, 'utf8').digest('base64url');
}

export function oauthTokenAuditDigest(rawBearer: string): string {
  return createHash('sha256').update(rawBearer, 'utf8').digest('hex');
}

type DelegateSignerAuthDatabase = {
  oauthAccessToken: { findUnique: (args: any) => Promise<any> };
  oauthClient: { findUnique: (args: any) => Promise<any> };
  user: { findUnique: (args: any) => Promise<any> };
  tinyCloudManageKeyAppPreference: { findUnique: (args: any) => Promise<any> };
};

export type DelegateSignerAuthDependencies = {
  database: DelegateSignerAuthDatabase;
  resolveSession: (context: any) => Promise<boolean>;
  now?: () => Date;
};

function sameStringSet(actual: string[], expected: readonly string[]): boolean {
  return actual.length === expected.length
    && new Set(actual).size === actual.length
    && expected.every((item) => actual.includes(item));
}

function isConfidentialPersonalWebClient(client: NonNullable<CoordinationosOauthContext['client']>): boolean {
  return client.mode === 'PERSONAL'
    && client.type === 'web'
    && !client.public
    && client.tokenEndpointAuthMethod === 'client_secret_basic'
    && sameStringSet(client.grantTypes, ['authorization_code'])
    && sameStringSet(client.responseTypes, ['code']);
}

function hasCoordinationosSessionScopeSet(scopes: string[]): boolean {
  return sameStringSet(scopes, ['openid', 'email', 'keys', TINYCLOUD_SESSION_SCOPE])
    // This is a safe transition state for CoordinationOS: session requests
    // still take the narrower session policy below even when its client has
    // also been granted the generic manage-key scope.
    || sameStringSet(scopes, [
      'openid',
      'email',
      'keys',
      TINYCLOUD_SESSION_SCOPE,
      TINYCLOUD_MANAGE_KEY_SCOPE,
    ]);
}

export function createDelegateSignerAuth(dependencies: DelegateSignerAuthDependencies) {
  const { database, resolveSession, now = () => new Date() } = dependencies;
  return createMiddleware<DelegateSignerContext>(async (c, next) => {
  c.set('delegateSignerPrincipal', null);
  c.set('delegateSignerOauthContext', null);
  c.set('delegateSignerAuthFailure', null);

  const parsed = parseDelegateAuthorization(c.req.header('authorization') ?? null);
  if (parsed.kind === 'malformed' || parsed.kind === 'multiple') {
    c.set('delegateSignerAuthFailure', {
      code: parsed.kind === 'multiple' ? 'multiple_authorization' : 'malformed_authorization',
      oauthAccessTokenId: null,
      tokenDigest: null,
      clientId: null,
      userId: null,
    });
    await next();
    return;
  }

  if (parsed.kind === 'missing') {
    if (await resolveSession(c)) {
      c.set('delegateSignerPrincipal', { kind: 'session', userId: c.get('user').id });
    } else {
      c.set('delegateSignerAuthFailure', {
        code: 'missing_authorization',
        oauthAccessTokenId: null,
        tokenDigest: null,
        clientId: null,
        userId: null,
      });
    }
    await next();
    return;
  }

  const lookupDigest = oauthTokenLookupDigest(parsed.token);
  const tokenDigest = oauthTokenAuditDigest(parsed.token);
  const token = await database.oauthAccessToken.findUnique({
    where: { token: lookupDigest },
    select: {
      id: true,
      clientId: true,
      userId: true,
      scopes: true,
      createdAt: true,
      expiresAt: true,
    },
  });

  if (!token) {
    // A bearer credential is always interpreted as OAuth on this endpoint.
    // Falling back to a first-party Better Auth session here would let an
    // OAuth client bypass the client-bound manage-key consent boundary.
    c.set('delegateSignerAuthFailure', {
      code: 'unknown_token',
      oauthAccessTokenId: null,
      tokenDigest,
      clientId: null,
      userId: null,
    });
    await next();
    return;
  }

  const [client, user] = await Promise.all([
    database.oauthClient.findUnique({
      where: { clientId: token.clientId },
      select: {
        clientId: true,
        disabled: true,
        mode: true,
        type: true,
        public: true,
        tokenEndpointAuthMethod: true,
        grantTypes: true,
        responseTypes: true,
        scopes: true,
        tinycloudSessionPolicy: true,
        tinycloudSessionOrigin: true,
      },
    }),
    database.user.findUnique({
      where: { id: token.userId },
      select: { id: true, emailVerified: true },
    }),
  ]);
  const context: CoordinationosOauthContext = { token, client, user };
  c.set('delegateSignerOauthContext', context);
  const failure = (code: DelegateSignerAuthCode): DelegateSignerAuthFailure => ({
    code,
    oauthAccessTokenId: token.id,
    tokenDigest,
    clientId: token.clientId,
    userId: token.userId,
  });
  const nowMs = now().getTime();

  if (token.expiresAt.getTime() <= nowMs) c.set('delegateSignerAuthFailure', failure('token_expired'));
  // Both signing paths use short-lived tokens. Check freshness before routing
  // by scope so a combined session/manage-key token cannot bypass it.
  else if (token.createdAt.getTime() + 300_000 <= nowMs) c.set('delegateSignerAuthFailure', failure('token_too_old'));
  // A transition client holding both scopes must retain the narrower
  // CoordinationOS session policy until it stops requesting this scope.
  else if (token.scopes.includes(TINYCLOUD_SESSION_SCOPE)) {
    if (!client || client.clientId !== token.clientId) {
      c.set('delegateSignerAuthFailure', failure('wrong_client'));
    } else if (client.disabled) c.set('delegateSignerAuthFailure', failure('client_disabled'));
    else if (!client.scopes.includes(TINYCLOUD_SESSION_SCOPE)) {
      c.set('delegateSignerAuthFailure', failure('missing_scope'));
    }
    else if (!isConfidentialPersonalWebClient(client)
      || !hasCoordinationosSessionScopeSet(client.scopes)) {
      c.set('delegateSignerAuthFailure', failure('client_misconfigured'));
    } else if (!user) c.set('delegateSignerAuthFailure', failure('user_not_found'));
    else if (!user.emailVerified) c.set('delegateSignerAuthFailure', failure('email_not_verified'));
    else {
      c.set('delegateSignerPrincipal', {
        kind: 'coordinationos-oauth',
        userId: token.userId,
        clientId: token.clientId,
        oauthAccessTokenId: token.id,
        tokenDigest,
      });
    }
  } else if (token.scopes.includes(TINYCLOUD_MANAGE_KEY_SCOPE)) {
    if (!client || client.clientId !== token.clientId) {
      c.set('delegateSignerAuthFailure', failure('wrong_client'));
    } else if (client.disabled) {
      c.set('delegateSignerAuthFailure', failure('client_disabled'));
    } else if (!isConfidentialPersonalWebClient(client)) {
      // Tenant-managed and public clients are not custodians of a user's
      // canonical personal TinyCloud identity. This also prevents dynamic
      // client registrations from using a manage-key consent grant.
      c.set('delegateSignerAuthFailure', failure('client_misconfigured'));
    } else if (!client.scopes.includes(TINYCLOUD_MANAGE_KEY_SCOPE)) {
      c.set('delegateSignerAuthFailure', failure('missing_scope'));
    } else if (!user) {
      c.set('delegateSignerAuthFailure', failure('user_not_found'));
    } else if (!user.emailVerified) {
      c.set('delegateSignerAuthFailure', failure('email_not_verified'));
    } else {
      // Authorization establishes identity only. The policy is deliberately
      // evaluated inside the signing transaction so a settings mutation cannot
      // race the check and signature production.
      c.set('delegateSignerPrincipal', {
        kind: 'oauth-manage-key',
        userId: token.userId,
        clientId: token.clientId,
        oauthAccessTokenId: token.id,
        tokenDigest,
      });
    }
  } else c.set('delegateSignerAuthFailure', failure('missing_scope'));

  await next();
  });
}
