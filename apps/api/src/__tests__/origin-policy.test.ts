import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import {
  API_EXPOSED_HEADERS,
  corsOriginPolicy,
  DEFAULT_CONSOLE_ORIGIN,
  isAccountOriginAllowed,
  resolveAccountOriginPolicy,
  resolveOriginPolicy,
} from '../origin-policy';

function credentialedApp(env: Record<string, string | undefined>) {
  const app = new Hono();
  app.use('*', cors({
    origin: corsOriginPolicy('http://localhost:5173', env),
    credentials: true,
  }));
  app.get('/api/auth/get-session', (c) => c.json({ ok: true }));
  return app;
}

describe('production console origin policy', () => {
  test('adds the console host for the sealed Phala environment and serves its preflight', async () => {
    const env = {
      CORS_ORIGIN: 'https://openkey.so',
      TEE_MODE: 'production',
    };
    expect(resolveOriginPolicy('http://localhost:5173', env)).toEqual([
      'https://openkey.so',
      DEFAULT_CONSOLE_ORIGIN,
    ]);

    const app = credentialedApp(env);
    const allowed = await app.request('https://api.openkey.so/api/auth/get-session', {
      method: 'OPTIONS',
      headers: {
        Origin: DEFAULT_CONSOLE_ORIGIN,
        'Access-Control-Request-Method': 'GET',
      },
    });
    const denied = await app.request('https://api.openkey.so/api/auth/get-session', {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://untrusted.example',
        'Access-Control-Request-Method': 'GET',
      },
    });

    expect(allowed.status).toBe(204);
    expect(allowed.headers.get('access-control-allow-origin')).toBe(DEFAULT_CONSOLE_ORIGIN);
    expect(allowed.headers.get('access-control-allow-credentials')).toBe('true');
    expect(denied.headers.get('access-control-allow-origin')).toBeNull();
  });

  test('preserves explicit origins, console overrides, comma-separated lists, and deduplication', () => {
    expect(resolveOriginPolicy('http://localhost:5173', {
      CORS_ORIGIN: 'https://openkey.so, https://staging.openkey.so,https://openkey.so',
      CONSOLE_ORIGIN: 'https://console.example.test',
      TEE_MODE: 'production',
    })).toEqual([
      'https://openkey.so',
      'https://staging.openkey.so',
      'https://console.example.test',
    ]);
  });

  test('keeps the local development default unchanged', () => {
    expect(resolveOriginPolicy('http://localhost:5173', {})).toEqual([
      'http://localhost:5173',
    ]);
    expect(corsOriginPolicy('http://localhost:5173', {})).toBe('http://localhost:5173');
  });

  test('uses the single-origin Hono branch for local development', async () => {
    const response = await credentialedApp({}).request('http://localhost:3000/api/auth/get-session', {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:5173',
        'Access-Control-Request-Method': 'GET',
      },
    });

    expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
  });

  test('exposes Date to the page and keeps set-auth-token exposed', () => {
    expect(API_EXPOSED_HEADERS).toContain('Date');
    expect(API_EXPOSED_HEADERS).toContain('set-auth-token');
  });
});

describe('account origin policy', () => {
  test('accepts only canonical account origins, not CORS-only console or staging origins', () => {
    expect(resolveAccountOriginPolicy('http://localhost:5173', {
      CORS_ORIGIN: 'https://openkey.so,https://console.openkey.so,https://staging.openkey.so',
      WEBAUTHN_ORIGIN: 'https://openkey.so/',
      CONSOLE_ORIGIN: 'https://console.openkey.so',
      TEE_MODE: 'production',
    })).toEqual(['https://openkey.so']);
  });

  test('keeps the console when it is the configured account origin and refuses empty config', () => {
    expect(resolveAccountOriginPolicy('http://localhost:5173', {
      WEBAUTHN_ORIGIN: 'https://console.openkey.so',
      CONSOLE_ORIGIN: 'https://console.openkey.so',
      TEE_MODE: 'production',
    })).toEqual(['https://console.openkey.so']);
    expect(resolveAccountOriginPolicy('http://localhost:5173', {
      CORS_ORIGIN: 'https://console.openkey.so',
      CONSOLE_ORIGIN: 'https://console.openkey.so',
      TEE_MODE: 'production',
    })).toEqual([]);
  });
  test('matches request Origins canonically and refuses missing or malformed values', () => {
    const env = {
      CORS_ORIGIN: 'https://openkey.so,https://console.openkey.so,https://staging.openkey.so',
      WEBAUTHN_ORIGIN: 'https://openkey.so',
      CONSOLE_ORIGIN: 'https://console.openkey.so',
      TEE_MODE: 'production',
    };
    const cases: Array<[string | undefined, boolean]> = [
      ['https://openkey.so/', true],
      ['https://console.openkey.so', false],
      ['https://staging.openkey.so', false],
      ['null', false],
      [undefined, false],
      ['not an origin', false],
    ];
    for (const [origin, expected] of cases) {
      expect(isAccountOriginAllowed(origin, 'http://localhost:5173', env)).toBe(expected);
    }
  });

  test('origin decisions cover route groups, auth modes, origin categories, and deployment shapes', () => {
    const routeGroups = [
      ['account', 'account'],
      ['keys', 'account'],
      ['approval-request deny', 'account'],
      ['device authorization', 'account'],
      ['delegate session routes', 'account'],
      ['owner revocation', 'account'],
      ['prepared handoffs', 'account'],
      ['secrets', 'account'],
      ['variables', 'account'],
      ['Nostr keys', 'account'],
      ['organizations', 'full'],
      ['tenant console', 'full'],
    ] as const;
    const configs = [
      {
        label: 'production',
        env: {
          CORS_ORIGIN: 'https://openkey.so,https://console.openkey.so,https://staging.openkey.so',
          WEBAUTHN_ORIGIN: 'https://openkey.so',
          CONSOLE_ORIGIN: 'https://console.openkey.so',
          TEE_MODE: 'production',
        },
        origins: [
          ['account', 'https://openkey.so', true, true],
          ['console', 'https://console.openkey.so', false, true],
          ['staging-in-CORS', 'https://staging.openkey.so', false, true],
          ['null', 'null', false, false],
          ['none', undefined, false, false],
          ['malformed', 'not an origin', false, false],
        ] as const,
      },
      {
        label: 'console-is-account development',
        env: {
          NODE_ENV: 'development',
          WEBAUTHN_ORIGIN: 'http://localhost:5173',
          CONSOLE_ORIGIN: 'http://localhost:5173',
          CORS_ORIGIN: 'http://localhost:5173,http://127.0.0.1:8080',
        },
        origins: [
          ['account', 'http://localhost:5173', true, true],
          ['console', 'http://localhost:5173', true, true],
          ['staging-in-CORS', 'http://127.0.0.1:8080', false, true],
          ['null', 'null', false, false],
          ['none', undefined, false, false],
          ['malformed', 'not an origin', false, false],
        ] as const,
      },
      {
        label: 'console-only misconfiguration',
        env: {
          NODE_ENV: 'production',
          CONSOLE_ORIGIN: 'https://console.openkey.so',
          CORS_ORIGIN: 'https://console.openkey.so',
          TEE_MODE: 'production',
        },
        origins: [
          ['account', 'https://openkey.so', false, false],
          ['console', 'https://console.openkey.so', false, true],
          ['staging-in-CORS', 'https://staging.openkey.so', false, false],
          ['null', 'null', false, false],
          ['none', undefined, false, false],
          ['malformed', 'not an origin', false, false],
        ] as const,
      },
    ] as const;
    for (const config of configs) {
      for (const [routeGroup, policy] of routeGroups) {
        for (const [category, origin, accountExpected, fullExpected] of config.origins) {
          for (const auth of ['cookie', 'session bearer']) {
            let fullAllowed = false;
            try {
              const canonical = origin === undefined ? 'null' : new URL(origin).origin;
              fullAllowed = canonical !== 'null'
                && resolveOriginPolicy('http://localhost:5173', config.env).includes(canonical);
            } catch {
              // Malformed Origins are refused by both policies.
            }
            const accepted = policy === 'account'
              ? isAccountOriginAllowed(origin, 'http://localhost:5173', config.env)
              : fullAllowed;
            expect(accepted, `${routeGroup} ${category} ${auth} ${config.label}`)
              .toBe(policy === 'account' ? accountExpected : fullExpected);
          }
        }
      }
    }
  });

  test('keeps the development localhost defaults', () => {
    expect(resolveAccountOriginPolicy('http://localhost:5173,http://localhost:3000', {
      NODE_ENV: 'development',
    })).toEqual(['http://localhost:5173', 'http://localhost:3000']);
  });
});
