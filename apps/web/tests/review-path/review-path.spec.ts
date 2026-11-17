// "Review path": what the app reviewer does in OpenKey, against a real API and database (see playwright.config.ts).
//
// The store reviewer opens the connector's authorize link, signs in with the review code, allows the
// connector, the connector exchanges the code for a token, and the reviewer approves the connector's access
// request on the approval screen. The hosted-MCP cases P01-P05 and N01-N03 (js-sdk
// packages/mcp/plugin/review-evidence.json) also need the hosted MCP and a real TinyCloud node, which a
// hermetic run does not have; each test below names the case whose OpenKey half it covers.
//
// Outside OpenKey, only three addresses are answered in the browser: the connector's redirect target, the
// connector's approval callback and the (local, never real) TinyCloud node. The API, the database, the
// sign-in, the consent and the signing are real.
//
// The cases share one reviewer account and its consent, so they run in file order against a fresh database.
// A second run against the same database sees the first run's consent and the N01 case fails.

import { test, expect, request as apiRequest, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ORIGIN } from '../browser/e2e-port';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';

type Fixture = {
  email: string; code: string; clientId: string; redirectUri: string; resource: string; nodeHost: string;
  sessionDid: string; sessionPublicJwk: Record<string, string>; spaceId: string; callbackUri: string;
};
const fixture: Fixture = JSON.parse(readFileSync(process.env.REVIEW_PATH_FIXTURE ?? '', 'utf8'));

const SCOPE = 'openid email offline_access tinycloud:mcp';
const connectorOrigin = new URL(fixture.redirectUri).origin;
const APP = 'xyz.tinycloud.tinyapps.todos/';
const KV = ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/put'];

function authorizeQuery(overrides: Record<string, string> = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: fixture.clientId,
    redirect_uri: fixture.redirectUri,
    scope: SCOPE,
    state: randomBytes(12).toString('base64url'),
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    resource: fixture.resource,
    ...overrides,
  });
  return { verifier, params, state: params.get('state')! };
}

async function answerConnectorRedirect(page: Page) {
  await page.route(`${fixture.redirectUri}**`, (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>connector</p>' }));
}

async function signInWithReviewCode(page: Page, code: string) {
  await page.waitForURL(/\/auth\/login/);
  // Handlers attach when hydration lands; wait so clicks and fills stick.
  await page.waitForLoadState('networkidle');
  await page.getByRole('button', { name: 'Use a review code' }).click();
  await page.getByLabel('Review account').fill(fixture.email);
  await page.getByLabel('Review code').fill(code);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

function exchangeForm(authorizationCode: string, verifier: string) {
  return {
    grant_type: 'authorization_code', code: authorizationCode, redirect_uri: fixture.redirectUri,
    client_id: fixture.clientId, code_verifier: verifier, resource: fixture.resource,
  };
}

function claims(jwt: string): { aud?: string | string[]; iat: number; exp: number; scope?: string } {
  return JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'));
}

function permission(space: string, path: string) {
  return [{ service: 'tinycloud.kv', space, path, actions: KV }];
}

function delegationBody(permissions: unknown, host = fixture.nodeHost) {
  return { keyId: 'reviewer', jwk: fixture.sessionPublicJwk, host, permissions };
}

test.describe.configure({ mode: 'serial' });

test('a wrong review code is refused and no session is created', async ({ page }) => {
  await answerConnectorRedirect(page);
  await page.goto(`/api/auth/oauth2/authorize?${authorizeQuery().params}`);
  await signInWithReviewCode(page, 'r'.repeat(43));
  await expect(page.getByRole('alert')).toContainText("Couldn't sign in with those details");
  expect(await (await page.request.get('/api/auth/get-session')).json()).toBeNull();
});

test('review sign-in refuses a forged authorize query, a foreign origin and the email-code route', async ({ request }) => {
  const forged = authorizeQuery();
  forged.params.set('exp', String(Math.floor(Date.now() / 1000) + 600));
  forged.params.set('sig', 'forged');
  const body = { email: fixture.email, code: fixture.code, oauth_query: forged.params.toString() };
  const refused = [
    await request.post('/api/auth/sign-in/reviewer', { data: body, headers: { origin: ORIGIN } }),
    await request.post('/api/auth/sign-in/reviewer', { data: body, headers: { origin: 'https://foreign.test' } }),
    await request.post('/api/auth/sign-in/email-otp', { data: { email: fixture.email, otp: '000000' }, headers: { origin: ORIGIN } }),
  ];
  for (const response of refused) {
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.status()).toBeLessThan(500);
    expect(response.headers()['set-cookie']).toBeUndefined();
  }
});

test('N01 (OpenKey half): denying the connector at consent returns access_denied, issues no code, and consent is asked again', async ({ page }) => {
  await answerConnectorRedirect(page);
  const first = authorizeQuery();
  await page.goto(`/api/auth/oauth2/authorize?${first.params}`);
  await signInWithReviewCode(page, fixture.code);
  await page.waitForURL(/\/oauth\/consent/);
  await page.getByRole('button', { name: 'Deny' }).click();
  await page.waitForURL((url) => url.origin === connectorOrigin);
  const denied = new URL(page.url());
  expect(denied.searchParams.get('error')).toBe('access_denied');
  expect(denied.searchParams.get('code')).toBeNull();
  expect(denied.searchParams.get('state')).toBe(first.state);

  // Nothing was granted: the same request asks again.
  await page.goto(`/api/auth/oauth2/authorize?${authorizeQuery().params}`);
  await page.waitForURL(/\/oauth\/consent/);
  await expect(page.getByRole('button', { name: 'Allow' })).toBeVisible();
});

test.describe('after the reviewer allows the connector', () => {
  let context: BrowserContext;
  let page: Page;
  let connector: APIRequestContext;

  test.beforeAll(async ({ browser }) => {
    context = await browser.newContext({ baseURL: ORIGIN });
    page = await context.newPage();
    // The connector exchanges the code from its own server: no browser cookies.
    connector = await apiRequest.newContext({ baseURL: ORIGIN });
  });
  test.afterAll(async () => {
    await connector.dispose();
    await context.close();
  });

  test('P01 (OpenKey half): sign in with the review code, allow, and the connector gets a one-hour tinycloud:mcp token', async () => {
    await answerConnectorRedirect(page);
    const attempt = authorizeQuery();
    await page.goto(`/api/auth/oauth2/authorize?${attempt.params}`);
    await signInWithReviewCode(page, fixture.code);
    await page.waitForURL(/\/oauth\/consent/);
    await page.getByRole('button', { name: 'Allow' }).click();
    await page.waitForURL((url) => url.origin === connectorOrigin);
    const granted = new URL(page.url());
    expect(granted.searchParams.get('state')).toBe(attempt.state);
    const authorizationCode = granted.searchParams.get('code');
    expect(authorizationCode).toBeTruthy();

    const exchange = await connector.post('/api/auth/oauth2/token', { form: exchangeForm(authorizationCode!, attempt.verifier) });
    expect(exchange.status()).toBe(200);
    const token = await exchange.json();
    expect(token.access_token).toBeTruthy();
    const access = claims(token.access_token);
    expect([access.aud].flat()).toContain(fixture.resource);
    expect(access.scope?.split(' ')).toContain('tinycloud:mcp');
    // A review session lasts at most an hour, and so does the token it mints, though an MCP token is 12 hours for others.
    expect(access.exp - access.iat).toBeLessThanOrEqual(3600);

    // The same code cannot be used twice.
    const replay = await connector.post('/api/auth/oauth2/token', { form: exchangeForm(authorizationCode!, attempt.verifier) });
    expect(replay.status()).toBeGreaterThanOrEqual(400);
  });

  test('P01/P05 (OpenKey half): the approval screen shows the connector request and Approve returns a signed delegation to the connector', async () => {
    const callbacks: Array<{ delegationHeader?: { Authorization?: string } }> = [];
    const nodeActivations: Array<string | undefined> = [];
    await page.route(`${fixture.nodeHost}/**`, (route) => {
      nodeActivations.push(route.request().headers()['authorization']);
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    });
    await page.route(fixture.callbackUri, (route) => {
      callbacks.push(route.request().postDataJSON());
      return route.fulfill({
        status: 200, contentType: 'application/json', body: '{"ok":true}', headers: { 'access-control-allow-origin': '*' },
      });
    });
    const link = `/delegate?${new URLSearchParams({
      did: fixture.sessionDid,
      jwk: Buffer.from(JSON.stringify(fixture.sessionPublicJwk)).toString('base64url'),
      host: fixture.nodeHost,
      callback: fixture.callbackUri,
      permissions: encodeBase64UrlJson({ permissions: permission(fixture.spaceId, APP) }),
    })}`;
    await page.goto(link);
    await expect(page.getByRole('heading', { name: 'Authorize capabilities' })).toBeVisible();
    await expect(page.getByText(fixture.callbackUri)).toBeVisible();
    await expect(page.getByText('Read and update application data')).toBeVisible();
    await page.getByRole('button', { name: 'Approve', exact: true }).click();
    await expect(page.getByText('Authenticated')).toBeVisible();
    expect(callbacks).toHaveLength(1);
    expect(callbacks[0]!.delegationHeader?.Authorization).toBeTruthy();
    expect(nodeActivations).toHaveLength(1);
  });

  test("N02 (OpenKey half): a delegation outside the review account's own apps space, or to another node, is refused", async () => {
    const delegate = (body: unknown) => context.request.post('/api/delegate/prepare', { data: body });
    // The allowed request, so the refusals below are not refusals of everything.
    expect((await delegate(delegationBody(permission(fixture.spaceId, APP)))).status()).toBe(200);
    const otherAccount = 'tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:applications';
    expect((await delegate(delegationBody(permission(otherAccount, APP)))).status()).toBe(403);
    expect((await delegate(delegationBody(permission(fixture.spaceId, 'secrets/')))).status()).toBe(403);
    expect((await delegate(delegationBody(permission(fixture.spaceId, APP), 'https://node.tinycloud.xyz'))).status()).toBe(403);
  });

  test('N03 (OpenKey half): the review session reaches the connector flow only; keys, sessions and a widened scope are refused', async () => {
    expect((await context.request.get('/api/auth/get-session')).status()).toBe(200);
    for (const path of ['/api/auth/list-sessions', '/api/auth/list-accounts', '/api/keys']) {
      expect((await context.request.get(path)).status(), path).toBe(403);
    }
    // An authorize request wider than the review account is bound to is refused, not redirected to the connector.
    const widened = await context.request.get(`/api/auth/oauth2/authorize?${authorizeQuery({ scope: `${SCOPE} keys` }).params}`, { maxRedirects: 0 });
    expect(widened.status()).toBe(403);
    expect(widened.headers()['location']).toBeUndefined();
  });
});
