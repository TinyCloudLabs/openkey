import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { requireAccountOriginForSensitiveAuth } from '../middleware/bearer-origin';

const accountOrigin = 'https://openkey.test';
const savedEnv = new Map(['WEBAUTHN_ORIGIN', 'CONSOLE_ORIGIN', 'CORS_ORIGIN', 'TEE_MODE'].map((name) => [name, process.env[name]]));

beforeAll(() => {
  process.env.WEBAUTHN_ORIGIN = accountOrigin;
  process.env.CONSOLE_ORIGIN = 'https://console.openkey.test';
  process.env.CORS_ORIGIN = `${accountOrigin},https://console.openkey.test,https://staging.openkey.test`;
  process.env.TEE_MODE = 'production';
});
afterAll(() => {
  for (const [name, value] of savedEnv) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

const sensitiveRoutes = [
  ['GET', '/api/auth/passkey/generate-register-options'],
  ['POST', '/api/auth/passkey/verify-registration'],
  ['GET', '/api/auth/passkey/list-user-passkeys'],
  ['POST', '/api/auth/passkey/update-passkey'],
  ['POST', '/api/auth/passkey/delete-passkey'],
  ['POST', '/api/auth/revoke-session'],
  ['POST', '/api/auth/revoke-sessions'],
  ['POST', '/api/auth/revoke-other-sessions'],
  ['GET', '/api/auth/list-sessions'],
  ['GET', '/api/auth/list-accounts'],
  ['POST', '/api/auth/link-social'],
  ['POST', '/api/auth/unlink-account'],
  ['POST', '/api/auth/change-email'],
  ['POST', '/api/auth/email-otp/request-email-change'],
  ['POST', '/api/auth/get-access-token'],
  ['POST', '/api/auth/refresh-token'],
  ['GET', '/api/auth/account-info'],
  ['POST', '/api/auth/oauth2/client/rotate-secret'],
  ['POST', '/api/auth/oauth2/update-client'],
  ['POST', '/api/auth/oauth2/delete-client'],
  ['POST', '/api/auth/oauth2/create-client'],
  ['GET', '/api/auth/oauth2/get-client'],
  ['GET', '/api/auth/oauth2/get-clients'],
  ['POST', '/api/auth/email-otp/change-email'],
  ['POST', '/api/auth/change-password'],
  ['POST', '/api/auth/delete-user'],
  ['GET', '/api/auth/oauth2/get-consents'],
  ['GET', '/api/auth/oauth2/get-consent?id=consent_1'],
  ['POST', '/api/auth/oauth2/update-consent'],
  ['POST', '/api/auth/oauth2/delete-consent'],
  ['POST', '/api/auth/oauth2/consent'],
] as const;

function fixture() {
  let reachedHandler = 0;
  const app = new Hono();
  app.use('*', requireAccountOriginForSensitiveAuth);
  app.all('*', (c) => {
    reachedHandler++;
    return c.json({ ok: true });
  });
  return { app, reached: () => reachedHandler };
}

async function call(app: Hono, method: string, path: string, headers: Record<string, string> = {}) {
  return app.request(path, { method, headers });
}

describe('sensitive Better Auth endpoints require an account origin', () => {
  test.each(sensitiveRoutes)('%s %s rejects a console cookie before the handler', async (method, path) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, { origin: 'https://console.openkey.test', cookie: 'session=valid' });
    expect(response.status).toBe(403);
    expect(reached()).toBe(0);
  });

  test.each(sensitiveRoutes)('%s %s rejects a session bearer with no Origin', async (method, path) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, { authorization: 'Bearer session-token' });
    expect(response.status).toBe(403);
    expect(reached()).toBe(0);
  });

  const invalidOrigins = [
    ['staging', 'https://staging.openkey.test'],
    ['null', 'null'],
    ['malformed', 'not an origin'],
  ] as const;
  test.each(sensitiveRoutes.flatMap(([method, path]) =>
    invalidOrigins.map(([name, origin]) => [method, path, name, origin] as const),
  ))('%s %s rejects a %s cookie Origin before the handler', async (method, path, _name, origin) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, { origin, cookie: 'session=valid' });
    expect(response.status).toBe(403);
    expect(reached()).toBe(0);
  });

  test.each(sensitiveRoutes)('%s %s permits an account-origin cookie', async (method, path) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, { origin: accountOrigin, cookie: 'session=valid' });
    expect(response.status).toBe(200);
    expect(reached()).toBe(1);
  });
  test.each(sensitiveRoutes)('%s %s permits an account-origin bearer', async (method, path) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, {
      origin: accountOrigin,
      authorization: 'Bearer session-token',
    });
    expect(response.status).toBe(200);
    expect(reached()).toBe(1);
  });

  test.each(sensitiveRoutes)('%s %s permits a cookie with no Origin as before', async (method, path) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, { cookie: 'session=valid' });
    expect(response.status).toBe(200);
    expect(reached()).toBe(1);
  });

  test.each([
    ['POST', '/api/auth/sign-in/email'],
    ['GET', '/api/auth/get-session'],
    ['GET', '/api/auth/passkey/generate-authenticate-options'],
    ['POST', '/api/auth/passkey/verify-authentication'],
    ['GET', '/api/auth/oauth2/authorize'],
    ['POST', '/api/auth/oauth2/token'],
    ['POST', '/api/auth/oauth2/introspect'],
    ['GET', '/api/auth/oauth2/userinfo'],
    ['GET', '/api/auth/jwks'],
    ['POST', '/api/auth/oauth2/register'],
    ['POST', '/api/auth/oauth2/continue'],
    ['POST', '/api/auth/email-otp/verify-email'],
  ])('%s %s stays ungated', async (method, path) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, { origin: 'https://console.openkey.test', cookie: 'session=valid' });
    expect(response.status).toBe(200);
    expect(reached()).toBe(1);
  });

  test.each(sensitiveRoutes.flatMap(([method, path]) =>
    invalidOrigins.map(([name, origin]) => [method, path, name, origin] as const),
  ))('%s %s rejects a session bearer with %s Origin before the handler', async (method, path, _name, origin) => {
    const { app, reached } = fixture();
    const response = await call(app, method, path, {
      origin,
      authorization: 'Bearer session-token',
    });
    expect(response.status).toBe(403);
    expect(reached()).toBe(0);
  });
});
