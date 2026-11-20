// K1 (TC-3554): the epoch-0 read. DO NOT MERGE.
//
// Core (loadLegacyRoot): a fake transport answers like a KMS would. A root sealed
// under the old derivation must open; every wrong answer must stop the read.
// Transport (createRaTlsKmsTransport): a fake guest agent on a Unix socket and
// a fake KMS over mutual TLS, to pin the wire shape: temp CA check, the quote
// bound to the client key, the legacy extensions, `GetAppKey{root_epoch: 0}`.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHash, createHmac, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak256 } from 'viem';
import { seal, unseal } from '../src/index';
import { loadLegacyRoot, legacyRootPinsFromEnv, LEGACY_ROOT_ENV, LegacyRootError, type KmsAppKeyResponse, type LegacyKmsTransport } from '../src/legacy-root';
import { certExtensionValue, createRaTlsKmsTransport, issueRaTlsClientCredentials } from '../src/legacy-root-kms';

// dstack sdk/simulator/appkeys.json app key and the KAT's recorded answers
// (dstack-key-derivation.kat.test.ts): the epoch-0 derivation must reproduce them.
const OLD_APP_KEY = Buffer.from('d6e88992cdeeee35fe70b5db61ab66cdb191fb9b6ec9313757ef162dd7214d5d', 'hex');
const KAT = [
  {
    path: 'openkey/key/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    sealingKey: 'd8777af36cfaafe84bd5b204d2c67a257d4acc8cd95c8bca59dc7205c70764fb',
  },
  {
    path: 'openkey/user/user-a/keys',
    sealingKey: '53581d6d24f90554aeee2f848351b9fbfb7f9967314c3cc37a257a566e0f6691',
  },
];

const APP_ID = '11'.repeat(20);
// A stand-in for the pinned epoch-0 KMS root key (a test key, not a production one).
const ROOT_SECRET = new Uint8Array(32).fill(7);
const ROOT_PUB_HEX = Buffer.from(secp256k1.getPublicKey(ROOT_SECRET, true)).toString('hex');
const OTHER_SECRET = new Uint8Array(32).fill(9);

function issue(appKey: Uint8Array, signer: Uint8Array = ROOT_SECRET, appId = APP_ID): Uint8Array {
  const pub = secp256k1.getPublicKey(appKey, true);
  const digest = keccak256(Buffer.concat([Buffer.from('dstack-kms-issued:'), Buffer.from(appId, 'hex'), pub]), 'bytes');
  const sig = Buffer.from(secp256k1.sign(digest, signer, { prehash: false, format: 'recovered' }));
  return new Uint8Array(Buffer.concat([sig.subarray(1), sig.subarray(0, 1)])); // r || s || v
}

function answer(overrides: Partial<KmsAppKeyResponse> = {}): KmsAppKeyResponse {
  return {
    rootEpoch: 0,
    appEpoch: 0,
    k256Key: new Uint8Array(OLD_APP_KEY),
    k256Signature: issue(OLD_APP_KEY),
    ...overrides,
  };
}

function transportReturning(response: () => KmsAppKeyResponse | Promise<KmsAppKeyResponse>): LegacyKmsTransport & { calls: number } {
  const transport = {
    calls: 0,
    async getAppKey(request: { rootEpoch: 0 }) {
      transport.calls += 1;
      expect(request).toEqual({ rootEpoch: 0 });
      return response();
    },
  };
  return transport;
}

const config = { rootEpoch: 0, appId: APP_ID, kmsRootPubkey: ROOT_PUB_HEX };

/** A record sealed the way the old CVM sealed it: under the KAT's sealing key for its path. */
async function oldSealed(path: string, plaintext: string): Promise<{ path: string; sealed: string }> {
  const key = KAT.find((vector) => vector.path === path)!.sealingKey;
  return { path, sealed: await seal(plaintext, new Uint8Array(Buffer.from(key, 'hex'))) };
}

describe('loadLegacyRoot', () => {
  test('happy path: reproduces the recorded sealing keys and opens an old-sealed fixture', async () => {
    const canary = await oldSealed(KAT[0]!.path, 'old secret');
    const root = await loadLegacyRoot({ config, transport: transportReturning(() => answer()), canaries: [canary] });
    for (const vector of KAT) {
      expect(Buffer.from(root.legacyKey(vector.path)).toString('hex')).toBe(vector.sealingKey);
    }
    // Reads a second record, sealed under a different path, that was not the canary.
    const other = await oldSealed(KAT[1]!.path, 'another secret');
    expect(await unseal(other.sealed, root.legacyKey(other.path))).toBe('another secret');
    root.destroy();
    expect(() => root.legacyKey(KAT[0]!.path)).toThrow(LegacyRootError);
  });

  test('wrong epoch in the answer: bail', async () => {
    const canary = await oldSealed(KAT[0]!.path, 'x');
    for (const bad of [
      answer({ rootEpoch: 1 }),
      answer({ appEpoch: 1 }),
      // An absent epoch is a refusal, not 0: an old KMS that ignores root_epoch must not pass here.
      answer({ rootEpoch: undefined }),
      answer({ appEpoch: undefined }),
    ]) {
      await expect(
        loadLegacyRoot({ config, transport: transportReturning(() => bad), canaries: [canary] }),
      ).rejects.toMatchObject({ code: 'epoch_mismatch' });
    }
  });

  test('bad signature: bail (wrong signer, wrong app id, tampered key, high-S)', async () => {
    const canary = await oldSealed(KAT[0]!.path, 'x');
    const tampered = new Uint8Array(OLD_APP_KEY);
    tampered[31] ^= 1;
    const highS = issue(OLD_APP_KEY);
    // Flip s to n - s (still a valid ECDSA signature, but not low-S).
    const n = secp256k1.Point.Fn.ORDER;
    const s = BigInt(`0x${Buffer.from(highS.subarray(32, 64)).toString('hex')}`);
    highS.set(Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex'), 32);
    const cases = [
      answer({ k256Signature: issue(OLD_APP_KEY, OTHER_SECRET) }),
      answer({ k256Signature: issue(OLD_APP_KEY, ROOT_SECRET, '22'.repeat(20)) }),
      answer({ k256Key: tampered }),
      answer({ k256Signature: highS }),
    ];
    for (const bad of cases) {
      await expect(
        loadLegacyRoot({ config, transport: transportReturning(() => bad), canaries: [canary] }),
      ).rejects.toMatchObject({ code: 'signature_invalid' });
    }
  });

  test('malformed answer: bail', async () => {
    const canary = await oldSealed(KAT[0]!.path, 'x');
    for (const bad of [
      answer({ k256Key: new Uint8Array(31) }),
      answer({ k256Key: new Uint8Array(32) }),
      answer({ k256Signature: new Uint8Array(64) }),
    ]) {
      await expect(
        loadLegacyRoot({ config, transport: transportReturning(() => bad), canaries: [canary] }),
      ).rejects.toMatchObject({ code: 'response_invalid' });
    }
  });

  test('KMS refusal: bail, with a closed code and no KMS text in the error', async () => {
    const canary = await oldSealed(KAT[0]!.path, 'x');
    const refusing = transportReturning(() => {
      throw new Error('app not authorized; secret=hunter2');
    });
    const error = await loadLegacyRoot({ config, transport: refusing, canaries: [canary] }).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(LegacyRootError);
    expect((error as LegacyRootError).code).toBe('kms_refused');
    expect((error as LegacyRootError).message).not.toContain('hunter2');
  });

  test('canary that does not unseal (a root that is correctly signed but is not the old one): bail', async () => {
    // Sealed under the KAT key of a different path: the fetched root cannot open it.
    const wrong = { path: KAT[0]!.path, sealed: (await oldSealed(KAT[1]!.path, 'x')).sealed };
    await expect(
      loadLegacyRoot({ config, transport: transportReturning(() => answer()), canaries: [wrong] }),
    ).rejects.toMatchObject({ code: 'canary_failed' });
  });

  test('no canary, wrong config epoch, bad pin: bail before asking the KMS', async () => {
    const canary = await oldSealed(KAT[0]!.path, 'x');
    const transport = transportReturning(() => answer());
    await expect(loadLegacyRoot({ config, transport, canaries: [] })).rejects.toMatchObject({ code: 'config_invalid' });
    await expect(
      loadLegacyRoot({ config: { ...config, rootEpoch: 1 }, transport, canaries: [canary] }),
    ).rejects.toMatchObject({ code: 'config_invalid' });
    await expect(
      loadLegacyRoot({ config: { ...config, kmsRootPubkey: '00'.repeat(33) }, transport, canaries: [canary] }),
    ).rejects.toMatchObject({ code: 'config_invalid' });
    await expect(
      loadLegacyRoot({ config: { ...config, appId: '11' }, transport, canaries: [canary] }),
    ).rejects.toMatchObject({ code: 'config_invalid' });
    expect(transport.calls).toBe(0);
  });
});

describe('pins', () => {
  const env = {
    [LEGACY_ROOT_ENV.kmsUrl]: 'https://kms.example:12001',
    [LEGACY_ROOT_ENV.rootEpoch]: '0',
    [LEGACY_ROOT_ENV.kmsRootPubkey]: ROOT_PUB_HEX,
    [LEGACY_ROOT_ENV.kmsCaCert]: 'AAAA',
    [LEGACY_ROOT_ENV.appId]: APP_ID,
  };

  test('are read from the environment: all five, epoch 0, well-formed', () => {
    expect(legacyRootPinsFromEnv(env)).toEqual({
      config: { rootEpoch: 0, appId: APP_ID, kmsRootPubkey: ROOT_PUB_HEX },
      kmsUrl: 'https://kms.example:12001',
      kmsCaCert: 'AAAA',
    });
    for (const name of Object.values(LEGACY_ROOT_ENV)) {
      expect(() => legacyRootPinsFromEnv({ ...env, [name]: undefined })).toThrow(LegacyRootError);
      expect(() => legacyRootPinsFromEnv({ ...env, [name]: '  ' })).toThrow(LegacyRootError);
    }
    for (const bad of [
      { [LEGACY_ROOT_ENV.rootEpoch]: '1' },
      { [LEGACY_ROOT_ENV.rootEpoch]: 'zero' },
      { [LEGACY_ROOT_ENV.kmsRootPubkey]: '00'.repeat(33) },
      { [LEGACY_ROOT_ENV.appId]: '11' },
    ]) {
      expect(() => legacyRootPinsFromEnv({ ...env, ...bad })).toThrow(LegacyRootError);
    }
  });
});

// The spec's vectors (tinycloud-node docs/tc-3554-kms-epoch-fetch.md), shared with the Rust side.
test('the shared vectors: issuance digest, app pub, and GetKey(path) from k256_key = 01 x 32', () => {
  const key = new Uint8Array(32).fill(1);
  const pub = secp256k1.getPublicKey(key, true);
  expect(Buffer.from(pub).toString('hex')).toBe('031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f');
  expect(keccak256(new Uint8Array(0), 'hex')).toBe('0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  const digest = keccak256(Buffer.concat([Buffer.from('dstack-kms-issued:'), Buffer.alloc(20, 0x35), pub]), 'hex');
  expect(digest).toBe('0xb5e4fd2ef63b05285fe79190ddfb3e40efba1eef5a507bf4aed05da771847721');
  const prk = createHmac('sha256', 'RATLS').update(key).digest();
  const getKey = createHmac('sha256', prk).update('tinycloud/keys/primary').update(Buffer.from([1])).digest('hex');
  expect(getKey).toBe('bbeb1e02123fe7cfab8471656ab89eff4d0b517fabdd457aa624942d1d5e0b02');
});

test('the signature recovery byte is ignored: only (r, s) under the pinned key count', async () => {
  const canary = await oldSealed(KAT[0]!.path, 'x');
  const signature = issue(OLD_APP_KEY);
  signature[64] = 0x7f;
  const root = await loadLegacyRoot({
    config,
    transport: transportReturning(() => answer({ k256Signature: signature })),
    canaries: [canary],
  });
  root.destroy();
});

// ---- transport: fake agent + fake KMS -------------------------------------

function openssl(args: string[], cwd: string): void {
  const result = Bun.spawnSync(['openssl', ...args], { cwd, stdout: 'pipe', stderr: 'pipe' });
  if (result.exitCode !== 0) throw new Error(`openssl ${args[0]} failed: ${result.stderr.toString()}`);
}

// A TDX-v4-shaped fake quote: the 64-byte REPORTDATA sits at offset 568, as in a real one.
const QUOTE_HEAD = Buffer.alloc(568, 0xab);
const QUOTE_TAIL = Buffer.alloc(100, 0xcd);
const VM_CONFIG = '{"os_image_hash":"00"}';

describe('createRaTlsKmsTransport against a fake agent and a fake KMS', () => {
  let dir: string;
  let agent: HttpServer;
  let kms: HttpsServer;
  let kmsNoUsage: HttpsServer;
  let kmsUrl: string;
  let kmsNoUsageUrl: string;
  let kmsCaCert: string;
  let agentRequests: { path: string; reportData?: string }[];
  let kmsSeen: { path: string; body: Record<string, unknown>; authorized: boolean }[];
  let mode: 'ok' | 'refuse' | 'epoch1' | 'no-root-epoch' | 'no-app-epoch';
  let agentMode: 'ok' | 'other-app' | 'bad-report-data';

  function fakeKms(keyFile: string, certFile: string): HttpsServer {
    return createHttpsServer(
      {
        key: readFileSync(join(dir, keyFile)),
        cert: readFileSync(join(dir, certFile)),
        ca: [readFileSync(join(dir, 'tmp.pem'))],
        requestCert: true,
        rejectUnauthorized: false,
      },
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
          const socket = req.socket as TLSSocket;
          kmsSeen.push({ path: req.url ?? '', body, authorized: socket.authorized });
          const send = (status: number, payload: unknown) =>
            res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(payload));
          if (req.url === '/prpc/GetTempCaCert?json') {
            send(200, {
              temp_ca_cert: readFileSync(join(dir, 'tmp.pem'), 'utf8'),
              temp_ca_key: readFileSync(join(dir, 'tmp.key'), 'utf8'),
              ca_cert: readFileSync(join(dir, 'ca.pem'), 'utf8'),
            });
            return;
          }
          if (req.url === '/prpc/GetAppKey?json' && socket.authorized && mode !== 'refuse') {
            send(200, {
              ca_cert: readFileSync(join(dir, 'ca.pem'), 'utf8'),
              k256_key: Buffer.from(OLD_APP_KEY).toString('hex'),
              k256_signature: Buffer.from(issue(OLD_APP_KEY)).toString('hex'),
              ...(mode === 'no-root-epoch' ? {} : { root_epoch: mode === 'epoch1' ? 1 : 0 }),
              ...(mode === 'no-app-epoch' ? {} : { app_epoch: 0 }),
            });
            return;
          }
          send(400, { error: 'not authorized' });
        });
      },
    );
  }

  const port = (server: HttpsServer) => {
    const address = server.address();
    return typeof address === 'object' && address ? address.port : 0;
  };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'openkey-k1-'));
    // KMS CA, the temp CA (P-256, as the KMS issues it), and two KMS server leaves:
    // one marked kms:rpc (extension 1.3.6.1.4.1.62397.1.4 = DER OCTET STRING "kms:rpc"), one not.
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ca.key'], dir);
    openssl(['req', '-x509', '-new', '-key', 'ca.key', '-days', '2', '-subj', '/CN=fake kms ca', '-out', 'ca.pem'], dir);
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'tmp.key'], dir);
    openssl(['req', '-x509', '-new', '-key', 'tmp.key', '-days', '2', '-subj', '/CN=Dstack Client Temp CA', '-out', 'tmp.pem'], dir);
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'srv.key'], dir);
    openssl(['req', '-new', '-key', 'srv.key', '-subj', '/CN=localhost', '-out', 'srv.csr'], dir);
    const san = 'subjectAltName=DNS:localhost,IP:127.0.0.1\n';
    writeFileSync(join(dir, 'ext-rpc.cnf'), `${san}1.3.6.1.4.1.62397.1.4=DER:04076b6d733a727063\n`);
    writeFileSync(join(dir, 'ext-plain.cnf'), san);
    for (const [name, ext] of [['srv', 'ext-rpc.cnf'], ['srv-plain', 'ext-plain.cnf']] as const) {
      openssl(['x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2', '-extfile', ext, '-out', `${name}.pem`], dir);
    }
    kmsCaCert = new X509Certificate(readFileSync(join(dir, 'ca.pem'))).raw.toString('base64');

    agentRequests = [];
    kmsSeen = [];
    mode = 'ok';
    agentMode = 'ok';

    // Fake guest agent: POST /Info and POST /GetQuote {report_data hex}.
    agent = createHttpServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { report_data?: string };
        agentRequests.push({ path: req.url ?? '', reportData: body.report_data });
        const payload =
          req.url === '/Info'
            ? { app_id: agentMode === 'other-app' ? '22'.repeat(20) : APP_ID.toUpperCase(), tcb_info: '{}' }
            : {
                quote: Buffer.concat([
                  QUOTE_HEAD,
                  Buffer.from(agentMode === 'bad-report-data' ? '00'.repeat(64) : body.report_data!, 'hex'),
                  QUOTE_TAIL,
                ]).toString('hex'),
                event_log: '[{"imr":3}]',
                report_data: body.report_data,
                vm_config: VM_CONFIG,
              };
        const text = JSON.stringify(payload);
        // The SDK's own HTTP reader needs a Content-Length, as the real agent sends.
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) }).end(text);
      });
    });
    await new Promise<void>((resolve) => agent.listen(join(dir, 'dstack.sock'), resolve));

    kms = fakeKms('srv.key', 'srv.pem');
    kmsNoUsage = fakeKms('srv.key', 'srv-plain.pem');
    await new Promise<void>((resolve) => kms.listen(0, '127.0.0.1', resolve));
    await new Promise<void>((resolve) => kmsNoUsage.listen(0, '127.0.0.1', resolve));
    kmsUrl = `https://localhost:${port(kms)}`;
    kmsNoUsageUrl = `https://localhost:${port(kmsNoUsage)}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => agent.close(() => resolve()));
    await new Promise<void>((resolve) => kms.close(() => resolve()));
    await new Promise<void>((resolve) => kmsNoUsage.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  });

  function transport(overrides: { url?: string; ca?: string } = {}) {
    return createRaTlsKmsTransport({
      kmsUrl: overrides.url ?? kmsUrl,
      kmsCaCert: overrides.ca ?? kmsCaCert,
      appId: APP_ID,
      agentEndpoint: join(dir, 'dstack.sock'),
    });
  }

  function reset(next: typeof mode = 'ok', agentNext: typeof agentMode = 'ok') {
    mode = next;
    agentMode = agentNext;
    agentRequests.length = 0;
    kmsSeen.length = 0;
  }

  test('happy path: a quoted, temp-CA-signed client cert fetches epoch 0, and an old-sealed fixture unseals', async () => {
    reset();
    const canary = await oldSealed(KAT[0]!.path, 'old secret');
    const root = await loadLegacyRoot({ config, transport: transport(), canaries: [canary] });
    expect(Buffer.from(root.legacyKey(KAT[1]!.path)).toString('hex')).toBe(KAT[1]!.sealingKey);

    // Step 3 is without a client certificate; step 7 is with one that chains to the temp CA.
    const tempCaCall = kmsSeen.find((seen) => seen.path === '/prpc/GetTempCaCert?json')!;
    expect(tempCaCall.authorized).toBe(false);
    const appKeyCall = kmsSeen.find((seen) => seen.path === '/prpc/GetAppKey?json')!;
    // Epoch 0 pinned explicitly, no app_epoch, the agent's vm_config forwarded, no ticket.
    expect(appKeyCall.body).toEqual({ api_version: 1, vm_config: VM_CONFIG, root_epoch: 0, launch_ticket: '' });
    expect(appKeyCall.authorized).toBe(true);
    // The agent was asked who it is before anything went to the KMS, then for one quote.
    expect(agentRequests.map((r) => r.path)).toEqual(['/Info', '/GetQuote']);
    root.destroy();
  });

  test('the client certificate binds the quote to its own key, chains to the temp CA, and carries the legacy extensions', async () => {
    reset();
    const tempCaCertPem = readFileSync(join(dir, 'tmp.pem'), 'utf8');
    const creds = await issueRaTlsClientCredentials({
      agentEndpoint: join(dir, 'dstack.sock'),
      tempCaCertPem,
      tempCaKeyPem: readFileSync(join(dir, 'tmp.key'), 'utf8'),
    });
    const cert = new X509Certificate(creds.certPem);
    const caCert = new X509Certificate(tempCaCertPem);
    expect(cert.issuer).toBe(caCert.subject);
    expect(cert.subject).toBe('CN=RA-TLS TEMP Cert');
    expect(cert.verify(caCert.publicKey)).toBe(true);
    expect(cert.checkIssued(caCert)).toBe(true);
    // The quote request was over sha512("ratls-cert:" || the cert's own SPKI) ...
    const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
    const expected = createHash('sha512').update(Buffer.concat([Buffer.from('ratls-cert:'), spki])).digest('hex');
    expect(agentRequests.map((r) => r.reportData)).toEqual([expected]);
    expect(creds.reportData.toString('hex')).toBe(expected);
    // ... and quote and event log ride in the legacy extensions, each a DER OCTET STRING inside extnValue
    // (what ra-tls get_extension_bytes parses).
    const quote = Buffer.concat([QUOTE_HEAD, Buffer.from(expected, 'hex'), QUOTE_TAIL]);
    const quoteExt = certExtensionValue(cert.raw, '1.3.6.1.4.1.62397.1.1')!;
    expect(quoteExt[0]).toBe(0x04);
    expect(quoteExt.subarray(quoteExt.length - quote.length).equals(quote)).toBe(true);
    expect(quoteExt.length).toBe(quote.length + 4); // tag, 0x82, two length bytes
    const logExt = certExtensionValue(cert.raw, '1.3.6.1.4.1.62397.1.2')!;
    expect([...logExt.subarray(0, 2)]).toEqual([0x04, '[{"imr":3}]'.length]);
    expect(logExt.subarray(2).toString('utf8')).toBe('[{"imr":3}]');
    // keyUsage: critical, digitalSignature only (BIT STRING 07 80).
    expect(certExtensionValue(cert.raw, '2.5.29.15')!.equals(Buffer.from('03020780', 'hex'))).toBe(true);
    expect(creds.vmConfig).toBe(VM_CONFIG);
  });

  test('a KMS CA that is not the pinned one: bail before any quote is requested', async () => {
    reset();
    const canary = await oldSealed(KAT[0]!.path, 'x');
    const otherCa = new X509Certificate(readFileSync(join(dir, 'tmp.pem'))).raw.toString('base64');
    await expect(
      loadLegacyRoot({ config, transport: transport({ ca: otherCa }), canaries: [canary] }),
    ).rejects.toMatchObject({ code: 'kms_refused' });
    expect(agentRequests.filter((r) => r.path === '/GetQuote')).toEqual([]);
    expect(kmsSeen).toEqual([]);
  });

  test('a server leaf that is not marked kms:rpc is refused, though the CA signed it', async () => {
    reset();
    const canary = await oldSealed(KAT[0]!.path, 'x');
    await expect(
      loadLegacyRoot({ config, transport: transport({ url: kmsNoUsageUrl }), canaries: [canary] }),
    ).rejects.toMatchObject({ code: 'kms_refused' });
    expect(agentRequests.filter((r) => r.path === '/GetQuote')).toEqual([]);
  });

  test('a guest agent that is not the pinned app: bail before any KMS call', async () => {
    reset('ok', 'other-app');
    const canary = await oldSealed(KAT[0]!.path, 'x');
    await expect(loadLegacyRoot({ config, transport: transport(), canaries: [canary] })).rejects.toMatchObject({
      code: 'kms_refused',
    });
    expect(kmsSeen).toEqual([]);
  });

  test('a quote whose REPORTDATA is not the requested one: bail before GetAppKey', async () => {
    reset('ok', 'bad-report-data');
    const canary = await oldSealed(KAT[0]!.path, 'x');
    await expect(loadLegacyRoot({ config, transport: transport(), canaries: [canary] })).rejects.toMatchObject({
      code: 'kms_refused',
    });
    expect(kmsSeen.some((seen) => seen.path === '/prpc/GetAppKey?json')).toBe(false);
  });

  test('KMS refusal: bail', async () => {
    reset('refuse');
    const canary = await oldSealed(KAT[0]!.path, 'x');
    await expect(loadLegacyRoot({ config, transport: transport(), canaries: [canary] })).rejects.toMatchObject({
      code: 'kms_refused',
    });
  });

  test('a KMS that answers for epoch 1, or without saying which epoch: bail', async () => {
    const canary = await oldSealed(KAT[0]!.path, 'x');
    for (const next of ['epoch1', 'no-root-epoch', 'no-app-epoch'] as const) {
      reset(next);
      await expect(loadLegacyRoot({ config, transport: transport(), canaries: [canary] })).rejects.toMatchObject({
        code: 'epoch_mismatch',
      });
    }
  });
});

// The KAT's own derivation, restated, so a change to hkdf/salt cannot pass by echoing itself.
test('the recorded sealing keys equal sha256(HKDF-SHA256(RATLS, app key, path))', () => {
  for (const vector of KAT) {
    const prk = createHmac('sha256', 'RATLS').update(OLD_APP_KEY).digest();
    const okm = createHmac('sha256', prk).update(vector.path).update(Buffer.from([1])).digest();
    expect(createHash('sha256').update(okm).digest('hex')).toBe(vector.sealingKey);
  }
});
