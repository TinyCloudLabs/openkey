#!/usr/bin/env bun
/**
 * TC-3840: after a deploy, check from outside that the live API answers with the signing settings fixed in
 * docker-compose.prod.yml. Anonymous requests only, the same a visitor's browser makes on the sign-in page.
 * Prints each check and exits 1 on any mismatch. Never prints a token or a secret: every value checked is public.
 *
 *   API_URL=https://api.openkey.so bun scripts/probe-api-settings.ts
 */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

// CORS_ORIGIN stays in the encrypted env, so it has no compose value. These are the origins
// docs/deployment.md lists for it; the probe checks each is allowed and an unknown one is not.
const EXPECTED_CORS_ORIGINS = ['https://openkey.so', 'https://console.openkey.so'];
// Used only while WEBAUTHN_ORIGIN stays in the encrypted env (docs/deployment.md).
const DOCUMENTED_ACCOUNT_ORIGIN = 'https://openkey.so';
const FOREIGN_ORIGIN = 'https://probe.invalid';

/** The `api` service's literal `NAME=value` entries; interpolated entries are left out. */
export function composeLiterals(composeText: string): Map<string, string> {
  const compose: unknown = Bun.YAML.parse(composeText);
  if (typeof compose !== 'object' || compose === null || !('services' in compose)) throw new Error('compose has no services');
  const { services } = compose;
  if (typeof services !== 'object' || services === null || !('api' in services)) throw new Error('compose has no api service');
  const { api } = services;
  if (typeof api !== 'object' || api === null || !('environment' in api) || !Array.isArray(api.environment)) {
    throw new Error('compose api service has no environment list');
  }
  const literals = new Map<string, string>();
  for (const entry of api.environment) {
    if (typeof entry !== 'string') continue;
    const separator = entry.indexOf('=');
    const value = entry.slice(separator + 1);
    if (separator > 0 && !value.includes('$')) literals.set(entry.slice(0, separator), value);
  }
  return literals;
}

function required(literals: Map<string, string>, name: string): string {
  const value = literals.get(name);
  if (value === undefined) throw new Error(`${name} is not a literal in docker-compose.prod.yml`);
  return value;
}

async function json(response: Response): Promise<unknown> {
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

function field(value: unknown, key: string): unknown {
  if (typeof value !== 'object' || value === null || !(key in value)) return undefined;
  return Object.getOwnPropertyDescriptor(value, key)?.value;
}

async function main(): Promise<void> {
  const api = (process.env.API_URL ?? 'https://api.openkey.so').replace(/\/$/, '');
  const literals = composeLiterals(await readFile(resolve(import.meta.dir, '..', 'docker-compose.prod.yml'), 'utf8'));
  const failures: string[] = [];
  const check = (name: string, observed: unknown, expected: unknown) => {
    const ok = observed === expected;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: observed ${JSON.stringify(observed)}, expected ${JSON.stringify(expected)}`);
    if (!ok) failures.push(name);
  };

  // BETTER_AUTH_URL: the OIDC issuer is `${BETTER_AUTH_URL}/api/auth`.
  const discovery = await json(await fetch(`${api}/api/auth/.well-known/openid-configuration`));
  check('issuer (BETTER_AUTH_URL)', field(discovery, 'issuer'), `${required(literals, 'BETTER_AUTH_URL')}/api/auth`);

  // WEBAUTHN_RP_ID: the passkey sign-in options name the relying party.
  const passkey = await json(await fetch(`${api}/api/auth/passkey/generate-authenticate-options`));
  check('passkey rpId (WEBAUTHN_RP_ID)', field(passkey, 'rpId'), required(literals, 'WEBAUTHN_RP_ID'));

  // CORS: each expected origin is echoed on a credentialed preflight; an unknown origin gets no ACAO.
  for (const origin of [...EXPECTED_CORS_ORIGINS, FOREIGN_ORIGIN]) {
    const preflight = await fetch(`${api}/api/auth/get-session`, {
      method: 'OPTIONS',
      headers: { Origin: origin, 'Access-Control-Request-Method': 'GET' },
    });
    const expected = origin === FOREIGN_ORIGIN ? null : origin;
    check(`Access-Control-Allow-Origin for ${origin}`, preflight.headers.get('access-control-allow-origin'), expected);
  }

  // WEBAUTHN_ORIGIN: account routes refuse any other browser origin before they look for a session, so the
  // account origin gets 401 (no session) and a CORS-only origin gets 403.
  const accountOrigin = literals.get('WEBAUTHN_ORIGIN') ?? DOCUMENTED_ACCOUNT_ORIGIN;
  for (const [origin, expected] of [[accountOrigin, 401], [EXPECTED_CORS_ORIGINS[1]!, 403]] as const) {
    const response = await fetch(`${api}/api/device-authorizations/probe/approve`, { method: 'POST', headers: { Origin: origin } });
    check(`account-origin route status for ${origin} (WEBAUTHN_ORIGIN)`, response.status, expected);
  }

  // GOOGLE_CLIENT_ID: the Google redirect carries the client id.
  const social = await json(await fetch(`${api}/api/auth/sign-in/social`, {
    method: 'POST',
    headers: { Origin: DOCUMENTED_ACCOUNT_ORIGIN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider: 'google', callbackURL: DOCUMENTED_ACCOUNT_ORIGIN, disableRedirect: true }),
  }));
  const redirect = field(social, 'url');
  const clientId = typeof redirect === 'string' ? new URL(redirect).searchParams.get('client_id') : null;
  check('Google client_id (GOOGLE_CLIENT_ID)', clientId, required(literals, 'GOOGLE_CLIENT_ID'));

  if (failures.length > 0) {
    console.error(`Live API settings differ from docker-compose.prod.yml: ${failures.join('; ')}`);
    process.exit(1);
  }
}

if (import.meta.main) await main();
