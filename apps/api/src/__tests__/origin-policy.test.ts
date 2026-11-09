import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import {
  API_EXPOSED_HEADERS,
  corsOriginPolicy,
  DEFAULT_CONSOLE_ORIGIN,
  resolveOriginPolicy,
  resolveSigningOriginPolicy,
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

describe('signing origin policy', () => {
  test('keeps the account origin and drops the production console default', () => {
    const env = {
      CORS_ORIGIN: 'https://openkey.so,https://console.openkey.so',
      TEE_MODE: 'production',
    };
    expect(resolveOriginPolicy('http://localhost:5173', env)).toContain(DEFAULT_CONSOLE_ORIGIN);
    expect(resolveSigningOriginPolicy('http://localhost:5173', env)).toEqual(['https://openkey.so']);
  });

  test('drops the console origin whether CORS_ORIGIN or CONSOLE_ORIGIN supplies it', () => {
    // The console origin listed explicitly in CORS_ORIGIN, matched against
    // the production default.
    expect(resolveSigningOriginPolicy('http://localhost:5173', {
      CORS_ORIGIN: 'https://openkey.so,https://console.openkey.so',
      TEE_MODE: 'production',
    })).toEqual(['https://openkey.so']);

    // The console origin appended by CONSOLE_ORIGIN.
    expect(resolveSigningOriginPolicy('http://localhost:5173', {
      CORS_ORIGIN: 'https://openkey.so',
      CONSOLE_ORIGIN: 'https://console.example.test',
      TEE_MODE: 'production',
    })).toEqual(['https://openkey.so']);

    // An explicit origin that is not the console origin survives.
    expect(resolveSigningOriginPolicy('http://localhost:5173', {
      CORS_ORIGIN: 'https://openkey.so,https://staging.openkey.so',
      TEE_MODE: 'production',
    })).toEqual(['https://openkey.so', 'https://staging.openkey.so']);
  });

  test('matches the console origin despite case and trailing slashes', () => {
    expect(resolveSigningOriginPolicy('http://localhost:5173', {
      CORS_ORIGIN: 'https://openkey.so,HTTPS://Console.OpenKey.so/',
      CONSOLE_ORIGIN: 'https://console.openkey.so/',
      TEE_MODE: 'production',
    })).toEqual(['https://openkey.so']);
  });

  test('keeps the local development default unchanged', () => {
    expect(resolveSigningOriginPolicy('http://localhost:5173', {})).toEqual([
      'http://localhost:5173',
    ]);
    expect(resolveSigningOriginPolicy('http://localhost:5173,http://localhost:3000', {})).toEqual([
      'http://localhost:5173',
      'http://localhost:3000',
    ]);
  });
});
