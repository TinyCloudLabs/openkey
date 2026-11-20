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
import { loadLegacyRoot, LegacyRootError, type KmsAppKeyResponse, type LegacyKmsTransport } from '../src/legacy-root';
import { createRaTlsKmsTransport, issueRaTlsClientCredentials } from '../src/legacy-root-kms';

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
    for (const bad of [answer({ rootEpoch: 1 }), answer({ appEpoch: 1 })]) {
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

// ---- transport: fake agent + fake KMS -------------------------------------

function openssl(args: string[], cwd: string): void {
  const result = Bun.spawnSync(['openssl', ...args], { cwd, stdout: 'pipe', stderr: 'pipe' });
  if (result.exitCode !== 0) throw new Error(`openssl ${args[0]} failed: ${result.stderr.toString()}`);
}

describe('createRaTlsKmsTransport against a fake agent and a fake KMS', () => {
  let dir: string;
  let agent: HttpServer;
  let kms: HttpsServer;
  let kmsUrl: string;
  let kmsCaPin: string;
  let agentRequests: { reportData: string }[];
  let kmsSeen: { path: string; body: Record<string, unknown>; authorized: boolean }[];
  let mode: 'ok' | 'refuse' | 'epoch1';

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'openkey-k1-'));
    // KMS CA (what GetMeta.ca_cert is), KMS server cert, and the temp CA (P-256, as the KMS issues it).
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ca.key'], dir);
    openssl(['req', '-x509', '-new', '-key', 'ca.key', '-days', '2', '-subj', '/CN=fake kms ca', '-out', 'ca.pem'], dir);
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'tmp.key'], dir);
    openssl(['req', '-x509', '-new', '-key', 'tmp.key', '-days', '2', '-subj', '/CN=Dstack Client Temp CA', '-out', 'tmp.pem'], dir);
    openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'srv.key'], dir);
    openssl(['req', '-new', '-key', 'srv.key', '-subj', '/CN=localhost', '-out', 'srv.csr'], dir);
    writeFileSync(join(dir, 'ext.cnf'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\n');
    openssl(['x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2', '-extfile', 'ext.cnf', '-out', 'srv.pem'], dir);
    const caPem = readFileSync(join(dir, 'ca.pem'), 'utf8');
    const spki = new X509Certificate(caPem).publicKey.export({ type: 'spki', format: 'der' });
    kmsCaPin = createHash('sha256').update(spki).digest('hex');

    agentRequests = [];
    kmsSeen = [];
    mode = 'ok';

    // Fake guest agent: POST /GetQuote {report_data hex}.
    agent = createHttpServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { report_data: string };
        agentRequests.push({ reportData: body.report_data });
        const payload = JSON.stringify({
          quote: 'ab'.repeat(64),
          event_log: '[{"imr":3}]',
          report_data: body.report_data,
          vm_config: '{"os_image_hash":"00"}',
        });
        // The SDK's own HTTP reader needs a Content-Length, as the real agent sends.
        res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }).end(payload);
      });
    });
    await new Promise<void>((resolve) => agent.listen(join(dir, 'dstack.sock'), resolve));

    // Fake KMS: public GetTempCaCert; GetAppKey only for a client cert issued by the temp CA.
    kms = createHttpsServer(
      {
        key: readFileSync(join(dir, 'srv.key')),
        cert: readFileSync(join(dir, 'srv.pem')),
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
          if (req.url?.startsWith('/prpc/KMS.GetTempCaCert')) {
            send(200, {
              temp_ca_cert: readFileSync(join(dir, 'tmp.pem'), 'utf8'),
              temp_ca_key: readFileSync(join(dir, 'tmp.key'), 'utf8'),
              ca_cert: caPem,
            });
            return;
          }
          if (req.url?.startsWith('/prpc/KMS.GetAppKey') && socket.authorized && mode !== 'refuse') {
            const signature = issue(OLD_APP_KEY);
            send(200, {
              ca_cert: caPem,
              k256_key: Buffer.from(OLD_APP_KEY).toString('hex'),
              k256_signature: Buffer.from(signature).toString('hex'),
              // proto3 JSON omits zeros: epoch 0 arrives as an absent field.
              ...(mode === 'epoch1' ? { root_epoch: 1 } : {}),
            });
            return;
          }
          send(400, { error: 'not authorized' });
        });
      },
    );
    await new Promise<void>((resolve) => kms.listen(0, '127.0.0.1', resolve));
    const address = kms.address();
    kmsUrl = `https://localhost:${typeof address === 'object' && address ? address.port : 0}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => agent.close(() => resolve()));
    await new Promise<void>((resolve) => kms.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  });

  function transport(pin = kmsCaPin) {
    return createRaTlsKmsTransport({ kmsUrl, kmsCaPin: pin, agentEndpoint: join(dir, 'dstack.sock') });
  }

  test('happy path: a quoted, temp-CA-signed client cert fetches epoch 0, and an old-sealed fixture unseals', async () => {
    mode = 'ok';
    agentRequests.length = 0;
    kmsSeen.length = 0;
    const canary = await oldSealed(KAT[0]!.path, 'old secret');
    const root = await loadLegacyRoot({ config, transport: transport(), canaries: [canary] });
    expect(Buffer.from(root.legacyKey(KAT[1]!.path)).toString('hex')).toBe(KAT[1]!.sealingKey);

    const appKeyCall = kmsSeen.find((seen) => seen.path.startsWith('/prpc/KMS.GetAppKey'))!;
    // The request: epoch 0 pinned explicitly, the agent's vm_config forwarded, no ticket.
    expect(appKeyCall.body).toEqual({
      api_version: 1,
      vm_config: '{"os_image_hash":"00"}',
      root_epoch: 0,
      launch_ticket: '',
    });
    // The client cert chained to the temp CA at the TLS layer.
    expect(appKeyCall.authorized).toBe(true);
    expect(agentRequests).toHaveLength(1);
    root.destroy();
  });

  test('the client certificate binds the quote to its own key and chains to the temp CA', async () => {
    agentRequests.length = 0;
    const tempCaCertPem = readFileSync(join(dir, 'tmp.pem'), 'utf8');
    const creds = await issueRaTlsClientCredentials({
      agentEndpoint: join(dir, 'dstack.sock'),
      tempCaCertPem,
      tempCaKeyPem: readFileSync(join(dir, 'tmp.key'), 'utf8'),
    });
    const cert = new X509Certificate(creds.certPem);
    const caCert = new X509Certificate(tempCaCertPem);
    // Issued by the temp CA, and its signature verifies under the CA key.
    expect(cert.issuer).toBe(caCert.subject);
    expect(cert.verify(caCert.publicKey)).toBe(true);
    expect(cert.checkIssued(caCert)).toBe(true);
    // The quote request was over sha512("ratls-cert:" || the cert's own SPKI) ...
    const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
    const expected = createHash('sha512').update(Buffer.concat([Buffer.from('ratls-cert:'), spki])).digest('hex');
    expect(agentRequests.map((r) => r.reportData)).toEqual([expected]);
    expect(creds.reportData.toString('hex')).toBe(expected);
    // ... and the agent's quote and event log ride in dstack's legacy RA-TLS extensions.
    const raw = cert.raw;
    expect(raw.includes(Buffer.from('ab'.repeat(64), 'hex'))).toBe(true);
    expect(raw.includes(Buffer.from('[{"imr":3}]'))).toBe(true);
    // OIDs 1.3.6.1.4.1.62397.1.1 (quote) and .1.2 (event log).
    expect(raw.includes(Buffer.from('2b0601040183e73d0101', 'hex'))).toBe(true);
    expect(raw.includes(Buffer.from('2b0601040183e73d0102', 'hex'))).toBe(true);
    expect(creds.vmConfig).toBe('{"os_image_hash":"00"}');
  });

  test('a KMS CA that does not match the pin: bail before any quote is requested', async () => {
    mode = 'ok';
    agentRequests.length = 0;
    const canary = await oldSealed(KAT[0]!.path, 'x');
    await expect(
      loadLegacyRoot({ config, transport: transport('00'.repeat(32)), canaries: [canary] }),
    ).rejects.toMatchObject({ code: 'kms_refused' });
    expect(agentRequests).toEqual([]);
  });

  test('KMS refusal: bail', async () => {
    mode = 'refuse';
    const canary = await oldSealed(KAT[0]!.path, 'x');
    await expect(loadLegacyRoot({ config, transport: transport(), canaries: [canary] })).rejects.toMatchObject({
      code: 'kms_refused',
    });
  });

  test('a KMS that answers for epoch 1: bail', async () => {
    mode = 'epoch1';
    const canary = await oldSealed(KAT[0]!.path, 'x');
    await expect(loadLegacyRoot({ config, transport: transport(), canaries: [canary] })).rejects.toMatchObject({
      code: 'epoch_mismatch',
    });
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
