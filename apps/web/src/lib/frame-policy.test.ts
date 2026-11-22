// The sign pop-up and the login page refuse to be framed; the signing iframe and every other page keep their headers.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { framePolicyFor, withFramePolicy } from './frame-policy';

const POLICY = "frame-ancestors 'none'";

describe('which pages refuse framing', () => {
  test('the sign pop-up and the login page, with or without a trailing slash', () => {
    for (const path of ['/widget/sign', '/widget/sign/', '/auth/login', '/auth/login/']) {
      expect(framePolicyFor(path), path).toBe(POLICY);
    }
  });

  test('the signing iframe stays framable, and so does every other page', () => {
    for (const path of [
      '/widget/embed/sign', '/widget/embed/connect', '/widget/embed', '/widget/connect', '/widget/sign-typed-data', '/widget/signing',
      '/widget/sign/extra', '/widget', '/auth/login/extra', '/auth/register', '/auth/recover', '/auth/terms', '/auth/social',
      '/', '/dashboard', '/delegate', '/oauth/consent', '/console', '/device', '/constructor', '/__proto__', '/toString',
    ]) {
      expect(framePolicyFor(path), path).toBeNull();
    }
  });
});

describe('the response', () => {
  test('gets the policy on the two pages and keeps everything else', async () => {
    for (const path of ['/widget/sign', '/auth/login']) {
      const original = new Response('<html></html>', { status: 200, statusText: 'OK', headers: { 'content-type': 'text/html', 'x-keep': '1' } });
      const result = withFramePolicy(original, path);
      expect(result.headers.get('content-security-policy')).toBe(POLICY);
      expect(result.headers.get('content-type')).toBe('text/html');
      expect(result.headers.get('x-keep')).toBe('1');
      expect(result.status).toBe(200);
      expect(await result.text()).toBe('<html></html>');
      expect(result.headers.get('x-frame-options')).toBeNull();
    }
  });

  test('joins a policy the response already has instead of replacing it', () => {
    const original = new Response('', { headers: { 'content-security-policy': "default-src 'self'" } });
    const result = withFramePolicy(original, '/widget/sign');
    expect(result.headers.get('content-security-policy')).toBe(`default-src 'self', ${POLICY}`);
  });

  test('a redirect keeps its status and location and gets it too', () => {
    const redirect = Response.redirect('https://openkey.test/auth/login', 302);
    const result = withFramePolicy(redirect, '/auth/login');
    expect(result.status).toBe(302);
    expect(result.headers.get('location')).toBe('https://openkey.test/auth/login');
    expect(result.headers.get('content-security-policy')).toBe(POLICY);
  });

  test('every other page gets the same response back, untouched', () => {
    for (const path of ['/widget/embed/sign', '/dashboard', '/']) {
      const original = new Response('x', { headers: { 'content-type': 'text/html' } });
      const result = withFramePolicy(original, path);
      expect(result).toBe(original);
      expect(result.headers.get('content-security-policy')).toBeNull();
    }
  });
});

describe('the server hook', () => {
  test('applies the policy to the response the app resolves, after the console host routing', () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'hooks.server.ts'), 'utf8');
    expect(source).toContain("import { withFramePolicy } from '$lib/frame-policy';");
    expect(source).toContain('return withFramePolicy(await resolve(event), event.url.pathname);');
    expect(source).not.toMatch(/return resolve\(event\)/);
  });
});
