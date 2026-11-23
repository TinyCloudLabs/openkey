// The app-keys file goes through the same guarded fetcher as the manifest,
// on its own path; the manifest's behaviour is the same as before.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { mockModules } from './mock-module';

type Call = { url: string; init: Record<string, unknown> };
let calls: Call[] = [];
let respond: () => Response = () => Response.json({});
const undiciFetch = mock(async (url: string, init: Record<string, unknown>) => {
  calls.push({ url, init });
  return respond();
});
await mockModules({ undici: () => ({ fetch: undiciFetch }) });

let fetchAppKeysFile: typeof import('../services/manifest-origin-fetch')['fetchAppKeysFile'];
let fetchAndBindWellKnownManifest: typeof import('../services/manifest-origin-fetch')['fetchAndBindWellKnownManifest'];

beforeAll(async () => {
  ({ fetchAppKeysFile, fetchAndBindWellKnownManifest } = await import('../services/manifest-origin-fetch?app-keys-file-fetch' as string));
});
beforeEach(() => {
  calls = [];
  respond = () => Response.json({});
});

// An address literal: resolving it needs no network.
const PUBLIC_HOST = '93.184.216.34';

describe('fetchAppKeysFile', () => {
  test('asks for the app-keys path over https with no redirects and returns the bytes', async () => {
    const body = '{"type":"openkey-app-keys","app_id":"x","keys":[]}';
    respond = () => new Response(body, { headers: { 'Content-Type': 'application/json; charset=UTF-8' } });
    const result = await fetchAppKeysFile(PUBLIC_HOST);
    expect(result.ok).toBe(true);
    expect(result.ok && new TextDecoder().decode(result.bytes)).toBe(body);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`https://${PUBLIC_HOST}/.well-known/openkey-app-keys.json`);
    expect(calls[0]!.init.redirect).toBe('error');
  });

  test.each([[404, 'missing'], [410, 'missing'], [403, 'unavailable'], [500, 'unavailable']])('status %i is %s', async (status, kind) => {
    respond = () => new Response('', { status });
    await expect(fetchAppKeysFile(PUBLIC_HOST)).resolves.toMatchObject({ ok: false, kind });
  });

  test('a body over 64 KiB is unavailable', async () => {
    respond = () => new Response('x'.repeat(64 * 1024 + 1), { headers: { 'Content-Type': 'application/json' } });
    await expect(fetchAppKeysFile(PUBLIC_HOST)).resolves.toMatchObject({ ok: false, kind: 'unavailable' });
  });

  test('a fetch that throws is unavailable', async () => {
    respond = () => { throw new Error('boom'); };
    await expect(fetchAppKeysFile(PUBLIC_HOST)).resolves.toMatchObject({ ok: false, kind: 'unavailable' });
  });

  test.each(['10.0.0.1', '127.0.0.1', '169.254.169.254', 'localhost'])('never asks a private host (%s)', async (host) => {
    await expect(fetchAppKeysFile(host)).resolves.toMatchObject({ ok: false, kind: 'unavailable' });
    expect(calls).toEqual([]);
  });
});

describe('the manifest fetch', () => {
  test('still asks for the manifest path and reports the status as before', async () => {
    respond = () => new Response('', { status: 404 });
    const result = await fetchAndBindWellKnownManifest({ reportedOrigin: `https://${PUBLIC_HOST}`, declaredDigest: 'a'.repeat(64) });
    expect(result).toEqual({ ok: false, reason: 'fetch returned status 404' });
    expect(calls[0]!.url).toBe(`https://${PUBLIC_HOST}/.well-known/openkey-manifest.json`);
  });

  test('checks the digest before it fetches', async () => {
    const result = await fetchAndBindWellKnownManifest({ reportedOrigin: `https://${PUBLIC_HOST}`, declaredDigest: 'nope' });
    expect(result).toEqual({ ok: false, reason: 'declaredDigest is not a 64-char hex sha256' });
    expect(calls).toEqual([]);
  });
});
