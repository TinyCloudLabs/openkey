// Known-answer test for OpenKey's sealing-key derivation (TC-964).
//
// Every sealed user wallet and Nostr key is encrypted under
// sha256(dstack v0 GetKey(path).key). If that output ever changes, every sealed
// key becomes unrecoverable. In @phala/dstack-sdk 0.6, `DstackClient` is the v1
// client: the unchanged call `getKey(path)` throws ("algorithm is required"),
// and the obvious fix, `getKey(path, 'secp256k1')`, calls `/v1/GetKey`, which
// derives different keys for the same path.
//
// This test drives OpenKey's production client (`createTeeClient()` with
// TEE_MODE=production), from both src and the built dist the API image runs,
// against a fake dstack guest agent on a Unix socket. The fake implements the
// frozen v0 `GetKey` exactly as dstack does:
//   key = HKDF-SHA256(salt = "RATLS", ikm = app k256 key, info = path, 32 bytes)
// (dstack ra-tls `derive_key`, guest-agent `rpc_service.rs` `get_key`), keyed
// with the public simulator app key from dstack's `sdk/simulator/appkeys.json`.
// The answers below were cross-checked against the real dstack guest-agent
// simulator built from dstack v0.6.0 (see OPENKEY_DSTACK_SIMULATOR_SOCKET).
//
// It fails if:
// - the installed SDK version, the package.json spec, or the bun.lock entry
//   differs from KNOWN_ANSWER.sdkVersion;
// - the client sends anything other than the recorded v0 requests;
// - OpenKey's post-processing of the key changes.
//
// Not covered: the probe reaches the agent through the SDK's
// DSTACK_SIMULATOR_ENDPOINT; production uses the SDK's default socket
// (/var/run/dstack.sock). `getQuote` has no known answer. Both are covered only
// by the exact version pin.
//
// Never edit KNOWN_ANSWER to make this pass. Changing the SDK version or the
// recorded request is allowed only after proving that every sealing key is
// byte-identical against a dstack guest agent of the version production runs
// (the v0.6.0 simulator alone doesn't prove it for an older production agent);
// record that proof in the PR.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHash, createHmac } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak256 } from 'viem';

const KNOWN_ANSWER = {
  sdkVersion: '0.5.7',
  vectors: [
    {
      // Per-key sealing context: `openkey/key/<43-char base64url>`.
      path: 'openkey/key/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      request: {
        url: '/GetKey',
        body: '{"path":"openkey/key/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","purpose":""}',
      },
      dstackKey: '69e4abf98a56751e4482efa31dab402feb162f8b34cbd2b386b7ed3850d38ed3',
      sealingKey: 'd8777af36cfaafe84bd5b204d2c67a257d4acc8cd95c8bca59dc7205c70764fb',
    },
    {
      // Legacy per-user path: `openkey/user/<userId>/keys`.
      path: 'openkey/user/user-a/keys',
      request: {
        url: '/GetKey',
        body: '{"path":"openkey/user/user-a/keys","purpose":""}',
      },
      dstackKey: 'cbd4c308594a8e2685230a613f0572651dbf488a4511d3be8cbf1b9719e54a21',
      sealingKey: '53581d6d24f90554aeee2f848351b9fbfb7f9967314c3cc37a257a566e0f6691',
    },
  ],
} as const;

// Public test fixture from dstack `sdk/simulator/appkeys.json` (v0.6.0). Not a
// production key.
const SIMULATOR_APP_K256_KEY = Buffer.from(
  'd6e88992cdeeee35fe70b5db61ab66cdb191fb9b6ec9313757ef162dd7214d5d',
  'hex',
);
const SIMULATOR_APP_K256_SIGNATURE =
  '9e618603e72d01fedb82deff6daf2d62a572becf0059eec3f89c1ab40e1f2e594d2a283f843f34e8f39e4cc49a612496ce67223a12ac923f8efe330346dfc6c500';

const SDK = '@phala/dstack-sdk';
const TEE_DIR = join(import.meta.dir, '..');
const REPO_ROOT = join(TEE_DIR, '..', '..');
const PROBE = join(import.meta.dir, 'fixtures', 'dstack-kat-probe.ts');

/** dstack ra-tls `derive_key`: HKDF-SHA256 under the legacy "RATLS" salt. */
function v0DeriveKey(path: string): Buffer {
  const prk = createHmac('sha256', 'RATLS').update(SIMULATOR_APP_K256_KEY).digest();
  return createHmac('sha256', prk).update(path).update(Buffer.from([1])).digest();
}

/** dstack `sign_recoverable_keccak256`: r || s || recovery id. */
function v0SignatureChain(purpose: string, derivedKey: Buffer): string[] {
  const pubkey = Buffer.from(secp256k1.getPublicKey(derivedKey, true)).toString('hex');
  const digest = keccak256(Buffer.from(`${purpose}:${pubkey}`), 'bytes');
  const signature = secp256k1.sign(digest, SIMULATOR_APP_K256_KEY);
  const link = Buffer.concat([signature.toCompactRawBytes(), Buffer.from([signature.recovery])]);
  return [link.toString('hex'), SIMULATOR_APP_K256_SIGNATURE];
}

type RecordedRequest = { method: string; url: string; contentType: string; body: string };

interface FakeGuestAgent {
  requests: RecordedRequest[];
  server: Server;
  listening: Promise<void>;
}

/** A dstack guest agent that serves only the frozen v0 `POST /GetKey`. */
function startFakeGuestAgent(socketPath: string): FakeGuestAgent {
  const requests: RecordedRequest[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      requests.push({
        method: req.method ?? '',
        url: req.url ?? '',
        contentType: req.headers['content-type'] ?? '',
        body,
      });
      const reply = (status: number, payload: string) => {
        res.writeHead(status, {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        });
        res.end(payload);
      };
      if (req.method !== 'POST' || req.url !== '/GetKey') {
        reply(404, JSON.stringify({ error: `not served by this fake: ${req.method} ${req.url}` }));
        return;
      }
      const args = JSON.parse(body) as { path?: string; purpose?: string; algorithm?: string };
      // The v0 agent treats "", "secp256k1" and "k256" alike; anything else differs.
      if (!['', 'secp256k1', 'k256'].includes(args.algorithm ?? '')) {
        reply(400, JSON.stringify({ error: 'Unsupported algorithm' }));
        return;
      }
      const key = v0DeriveKey(args.path ?? '');
      reply(200, JSON.stringify({
        key: key.toString('hex'),
        signature_chain: v0SignatureChain(args.purpose ?? '', key),
      }));
    });
  });
  return {
    requests,
    server,
    listening: new Promise<void>((resolve) => server.listen(socketPath, resolve)),
  };
}

type TeeEntry = 'src' | 'dist';

/** Runs OpenKey's production TeeClient (from `entry`) in a child process against `endpoint`. */
async function deriveThroughOpenKey(
  entry: TeeEntry,
  endpoint: string,
  paths: string[],
): Promise<Record<string, string>> {
  const child = Bun.spawn([process.execPath, 'run', PROBE, entry, ...paths], {
    cwd: TEE_DIR,
    env: {
      PATH: process.env.PATH ?? '',
      HOME: process.env.HOME ?? '',
      TEE_MODE: 'production',
      DSTACK_SIMULATOR_ENDPOINT: endpoint,
    },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  if (exitCode !== 0) {
    throw new Error(`dstack-kat-probe (${entry}) exited ${exitCode}: ${stderr}`);
  }
  return JSON.parse(stdout) as Record<string, string>;
}

function installedSdkVersion(): string {
  let dir = dirname(Bun.resolveSync(SDK, TEE_DIR));
  for (;;) {
    const manifest = join(dir, 'package.json');
    if (existsSync(manifest)) {
      const pkg = JSON.parse(readFileSync(manifest, 'utf8')) as { name?: string; version?: string };
      if (pkg.name === SDK && pkg.version) return pkg.version;
    }
    const parent = dirname(dir);
    if (parent === dir) throw new Error(`cannot find the installed ${SDK} package.json`);
    dir = parent;
  }
}

const paths = KNOWN_ANSWER.vectors.map((vector) => vector.path);
const expectedSealingKeys = Object.fromEntries(
  KNOWN_ANSWER.vectors.map((vector) => [vector.path, vector.sealingKey]),
);
// dist exists after `bun run build` (CI and the Dockerfile build it first).
const hasDist = existsSync(join(TEE_DIR, 'dist', 'index.js'));

describe('dstack sealing-key derivation (known answer, TC-964)', () => {
  test(`${SDK} is exactly the version the known answer was proven against`, () => {
    const teePackage = JSON.parse(readFileSync(join(TEE_DIR, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    expect(teePackage.dependencies[SDK]).toBe(KNOWN_ANSWER.sdkVersion);

    const lockfile = readFileSync(join(REPO_ROOT, 'bun.lock'), 'utf8');
    const specs = [...lockfile.matchAll(/"@phala\/dstack-sdk": "([^"]+)"/g)].map((m) => m[1]);
    const resolved = [...lockfile.matchAll(/"@phala\/dstack-sdk": \["@phala\/dstack-sdk@([^"]+)"/g)].map(
      (m) => m[1],
    );
    expect(specs.length).toBeGreaterThan(0);
    expect(specs.filter((spec) => spec !== KNOWN_ANSWER.sdkVersion)).toEqual([]);
    expect(resolved).toEqual([KNOWN_ANSWER.sdkVersion]);

    expect(installedSdkVersion()).toBe(KNOWN_ANSWER.sdkVersion);
  });

  describe('through a fake v0 guest agent', () => {
    let socketDir: string;
    let agent: FakeGuestAgent;

    beforeAll(async () => {
      socketDir = mkdtempSync(join(tmpdir(), 'openkey-kat-'));
      agent = startFakeGuestAgent(join(socketDir, 'dstack.sock'));
      await agent.listening;
    });

    afterAll(async () => {
      await new Promise<void>((resolve) => agent.server.close(() => resolve()));
      rmSync(socketDir, { recursive: true, force: true });
    });

    test('the recorded dstack keys and sealing keys are consistent', () => {
      for (const vector of KNOWN_ANSWER.vectors) {
        expect(v0DeriveKey(vector.path).toString('hex')).toBe(vector.dstackKey);
        expect(createHash('sha256').update(Buffer.from(vector.dstackKey, 'hex')).digest('hex')).toBe(
          vector.sealingKey,
        );
      }
    });

    for (const entry of ['src', 'dist'] as const) {
      test.skipIf(entry === 'dist' && !hasDist)(
        `${entry}: derives the recorded sealing keys with the recorded v0 requests`,
        async () => {
          agent.requests.length = 0;
          const sealingKeys = await deriveThroughOpenKey(entry, join(socketDir, 'dstack.sock'), paths);

          expect(agent.requests).toEqual(
            KNOWN_ANSWER.vectors.map((vector) => ({
              method: 'POST',
              url: vector.request.url,
              contentType: 'application/json',
              body: vector.request.body,
            })),
          );
          expect(sealingKeys).toEqual(expectedSealingKeys);
        },
      );
    }
  });

  // Opt-in: the same answers from the real dstack guest-agent simulator, run with
  // dstack's `sdk/simulator` config (and so its appkeys.json). Build it with
  // `cargo build --release -p dstack-guest-agent-simulator` in a dstack checkout.
  const simulatorSocket = process.env.OPENKEY_DSTACK_SIMULATOR_SOCKET;
  test.skipIf(!simulatorSocket)('the real dstack simulator gives the same sealing keys', async () => {
    expect(await deriveThroughOpenKey('src', simulatorSocket!, paths)).toEqual(expectedSealingKeys);
  });
});
