// Contract tests for the production client's quote binding (TC-1193).
//
// The production TeeClient runs against a fake dstack guest agent on a Unix
// socket we own. dstack quotes at most 64 bytes of report data (the pinned SDK
// refuses more before any socket I/O), so the client must send SHA-256 of the
// binding and accept only a quote over exactly that digest.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTeeClient } from '../src/index';

type QuoteBody = { quote: string; event_log: string; report_data?: string; vm_config: string };
type Reply = (reportDataHex: string) => { status: number; body: QuoteBody | { error: string } };

/** dstack's answer: a quote over the request's report data, zero-padded to 64 bytes. */
function honestQuote(reportDataHex: string): QuoteBody {
  return {
    quote: 'ab'.repeat(64),
    event_log: '[{"imr":3,"event":"app-id"}]',
    report_data: reportDataHex.padEnd(128, '0'),
    vm_config: '{}',
  };
}
const honest: Reply = (reportDataHex) => ({ status: 200, body: honestQuote(reportDataHex) });

/** The `report_data` field of a recorded GetQuote JSON body. */
function reportDataOf(json: string): string {
  const parsed: unknown = JSON.parse(json);
  if (parsed && typeof parsed === 'object' && 'report_data' in parsed && typeof parsed.report_data === 'string') {
    return parsed.report_data;
  }
  throw new Error(`GetQuote body has no report_data: ${json}`);
}

let socketDir: string;
let server: Server;
let requests: { url: string; body: string }[] = [];
let reply: Reply = honest;
const savedEnv = { TEE_MODE: process.env.TEE_MODE, DSTACK_SIMULATOR_ENDPOINT: process.env.DSTACK_SIMULATOR_ENDPOINT };

beforeAll(async () => {
  socketDir = mkdtempSync(join(tmpdir(), 'openkey-quote-'));
  const socketPath = join(socketDir, 'dstack.sock');
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      requests.push({ url: req.url ?? '', body });
      const { status, body: payload } = reply(reportDataOf(body));
      const text = JSON.stringify(payload);
      res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
      res.end(text);
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  process.env.TEE_MODE = 'production';
  process.env.DSTACK_SIMULATOR_ENDPOINT = socketPath;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(socketDir, { recursive: true, force: true });
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

beforeEach(() => {
  requests = [];
  reply = honest;
});

// The shape the keys route binds: well over 64 bytes.
const binding = JSON.stringify({
  type: 'openkey.key-quote',
  version: 1,
  address: '0x0123456789abcdef0123456789abcdef01234567',
  userId: 'user_with_a_realistic_identifier_length',
  timestamp: 1_760_000_000_000,
});
const digest = createHash('sha256').update(binding, 'utf8').digest('hex');

describe('production getQuote binding (TC-1193)', () => {
  test('sends SHA-256 of the binding as 32 bytes of report data', async () => {
    expect(Buffer.byteLength(binding)).toBeGreaterThan(64);

    const quote = await createTeeClient().getQuote(binding);

    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe('/GetQuote');
    const sent = reportDataOf(requests[0].body);
    expect(sent.length).toBeLessThanOrEqual(128);
    expect(sent).toBe(digest);
    expect(quote).toEqual({
      quote: 'ab'.repeat(64),
      eventLog: '[{"imr":3,"event":"app-id"}]',
      reportDataSha256: digest,
    });
  });

  test('rejects when the guest agent answers with an error', async () => {
    reply = () => ({ status: 400, body: { error: 'Report data is too long' } });
    await expect(createTeeClient().getQuote(binding)).rejects.toThrow();
  });

  test('rejects a quote over different report data', async () => {
    reply = () => honest('11'.repeat(32));
    await expect(createTeeClient().getQuote(binding)).rejects.toThrow(/report data/);
  });

  test('rejects a quote without report data', async () => {
    reply = (hex) => {
      const { report_data: _omitted, ...rest } = honestQuote(hex);
      return { status: 200, body: rest };
    };
    await expect(createTeeClient().getQuote(binding)).rejects.toThrow(/report data/);
  });
});
