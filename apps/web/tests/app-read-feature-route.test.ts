// @ts-nocheck -- Bun server and subprocess verification, outside the web client tsconfig.
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { join } from 'node:path';

const capabilities = { schemaVersion: 1, protocolVersion: 1, implementationVersion: '1', discovery: 'app-read', scope: 'registry-and-selected-app', transport: 'paste' };
let supported = true;
let api, web;
const endpoint = 'http://127.0.0.1:5781/.well-known/tinycloud-app-read.json';

beforeAll(async () => {
  api = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch(request) {
    if (new URL(request.url).pathname !== '/api/delegate/app-read-capabilities') return new Response(null, { status: 404 });
    return supported ? Response.json(capabilities) : new Response('old API', { status: 404 });
  } });
  web = Bun.spawn(['bun', '../../node_modules/vite/bin/vite.js', 'dev', '--host', '127.0.0.1', '--port', '5781', '--strictPort'], {
    cwd: join(import.meta.dir, '..'),
    env: { ...process.env, VITE_API_URL: '', API_URL: api.url.origin }, stdout: 'ignore', stderr: 'ignore',
  });
  for (let attempt = 0; attempt < 80; attempt++) {
    try { await fetch(endpoint); return; } catch { await Bun.sleep(250); }
  }
  throw new Error('Local web fixture did not start');
}, 30000);

afterAll(() => { web?.kill(); api?.stop(true); });

test('well-known route checks the same API proxy used by the approval browser on every request', async () => {
  const ready = await fetch(endpoint);
  expect(ready.status).toBe(200);
  expect(ready.headers.get('cache-control')).toBe('no-store');
  expect(await ready.json()).toEqual({ ...capabilities, apiBacked: true });
  supported = false;
  const oldApi = await fetch(endpoint);
  expect(oldApi.status).toBe(503);
  expect(oldApi.headers.get('cache-control')).toBe('no-store');
  expect(await oldApi.json()).toEqual({ code: 'app_read_deployment_incompatible' });
});
