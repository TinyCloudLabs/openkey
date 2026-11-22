// TC-3842: the production client's appInfo against a fake dstack guest agent on a Unix socket.
// The public attestation route returns these values next to the quote, so a malformed answer must
// throw rather than reach a verifier.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTeeClient } from '../src/index';

const COMPOSE_HASH = 'f29afbb944c28ff89ea21d778a8b556c3d269a5155fb15c2ca3403ef73e12126';
const APP_ID = 'b7d6e87778f73904a8f5fd26e4d0f1d1310234be';

let socketDir: string;
let server: Server;
let info: Record<string, unknown> = {};
const savedEnv = { TEE_MODE: process.env.TEE_MODE, DSTACK_SIMULATOR_ENDPOINT: process.env.DSTACK_SIMULATOR_ENDPOINT };

/** The guest agent's /Info answer: tcb_info is a JSON string, as dstack sends it. */
function agentInfo(fields: { app_id?: string; compose_hash?: string; tcb_compose_hash?: string }): Record<string, unknown> {
  const { tcb_compose_hash, ...top } = fields;
  return {
    instance_id: 'i',
    app_cert: '',
    app_name: 'openkey-api',
    device_id: 'd',
    key_provider_info: '{}',
    ...top,
    tcb_info: JSON.stringify({ mrtd: '', rtmr0: '', rtmr1: '', rtmr2: '', rtmr3: '', app_compose: '{}', event_log: [], compose_hash: tcb_compose_hash }),
  };
}

beforeAll(async () => {
  socketDir = mkdtempSync(join(tmpdir(), 'openkey-info-'));
  const socketPath = join(socketDir, 'dstack.sock');
  server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const text = JSON.stringify(info);
      res.writeHead(req.url === '/Info' ? 200 : 404, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
      res.end(text);
    });
  });
  const listening = Promise.withResolvers<void>();
  server.listen(socketPath, listening.resolve);
  await listening.promise;
  process.env.TEE_MODE = 'production';
  process.env.DSTACK_SIMULATOR_ENDPOINT = socketPath;
});

afterAll(async () => {
  const closed = Promise.withResolvers<void>();
  server.close(() => closed.resolve());
  await closed.promise;
  rmSync(socketDir, { recursive: true, force: true });
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe('production appInfo', () => {
  test('returns the agent app_id and compose_hash, lowercase without 0x', async () => {
    info = agentInfo({ app_id: `0x${APP_ID.toUpperCase()}`, compose_hash: COMPOSE_HASH, tcb_compose_hash: COMPOSE_HASH });
    expect(await createTeeClient().appInfo()).toEqual({ appId: APP_ID, composeHash: COMPOSE_HASH });
  });

  test('falls back to tcb_info.compose_hash when the top level has none', async () => {
    info = agentInfo({ app_id: APP_ID, tcb_compose_hash: COMPOSE_HASH });
    expect(await createTeeClient().appInfo()).toEqual({ appId: APP_ID, composeHash: COMPOSE_HASH });
  });

  test('throws on a missing app_id or a compose_hash that is not 32 bytes of hex', async () => {
    info = agentInfo({ compose_hash: COMPOSE_HASH });
    await expect(createTeeClient().appInfo()).rejects.toThrow('well-formed');
    info = agentInfo({ app_id: APP_ID, compose_hash: COMPOSE_HASH.slice(2) });
    await expect(createTeeClient().appInfo()).rejects.toThrow('well-formed');
  });
});

test('the development mock has no app identity', async () => {
  const saved = process.env.TEE_MODE;
  process.env.TEE_MODE = 'development';
  try {
    await expect(createTeeClient().appInfo()).rejects.toThrow('no dstack app identity');
  } finally {
    process.env.TEE_MODE = saved;
  }
});
