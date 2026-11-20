// The KMS leg of the epoch-0 read: an RA-TLS client for `KMS.GetAppKey`. TC-3554, K1.
//
// DO NOT MERGE. Mirrors the node's path B (node-design-bridge.md, "The shared
// piece"), the one the 0.5.12 guest's own boot takes:
//   1. fetch the KMS temp CA (`GetTempCaCert`, public) and check the CA cert's
//      public key against the pinned hash;
//   2. generate a P-256 key in process and ask the guest agent for a quote over
//      sha512("ratls-cert:" || SPKI DER) (dstack `QuoteContentType::RaTlsCert`);
//   3. sign a client certificate for that key with the temp CA, carrying the
//      quote and event log in dstack's legacy RA-TLS extensions
//      (1.3.6.1.4.1.62397.1.1 / .1.2), which KMS builds from 0.5 on still read;
//   4. call `KMS.GetAppKey {api_version: 1, root_epoch: 0, vm_config}` over
//      mutual TLS, trusting only the pinned CA.
// The KMS answer is not trusted for what it says: loadLegacyRoot checks its
// epoch and its signature under a pinned root key. Nothing here is a fallback;
// every failure throws.
//
// Not run against a real KMS: without TDX hardware no quote binds a fresh key.
// Tests cover the wire shape against a fake agent and a fake KMS.
import { createHash, createPrivateKey, createSign, generateKeyPairSync, randomBytes, X509Certificate } from 'crypto';
import { request as httpsRequest } from 'https';
import type { KmsAppKeyResponse, LegacyKmsTransport } from './legacy-root';

export interface RaTlsKmsTransportOptions {
  /** KMS base URL, e.g. https://kms.dstack-pha-prod2.phala.network (`/prpc` is added). */
  kmsUrl: string;
  /** sha256 of the KMS CA certificate's SubjectPublicKeyInfo DER, hex. */
  kmsCaPin: string;
  /** Guest agent socket or URL; default is the SDK's own (/var/run/dstack.sock). */
  agentEndpoint?: string;
  /** Per-call limit. Default 20 s. */
  timeoutMs?: number;
}

const OID_RATLS_TDX_QUOTE = '1.3.6.1.4.1.62397.1.1';
const OID_RATLS_EVENT_LOG = '1.3.6.1.4.1.62397.1.2';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_COMMON_NAME = '2.5.4.3';

// ---- minimal DER ----------------------------------------------------------

function derLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

function derOid(oid: string): Buffer {
  const arcs = oid.split('.').map(Number);
  const out: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunk = [arc & 0x7f];
    for (let n = Math.floor(arc / 128); n > 0; n = Math.floor(n / 128)) chunk.unshift((n & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return der(0x06, Buffer.from(out));
}

function derUtcTime(date: Date): Buffer {
  const pad = (n: number) => String(n).padStart(2, '0');
  const text = `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return der(0x17, Buffer.from(text, 'ascii'));
}

/** Reads one TLV at `offset`; returns its content range and the end of the element. */
function readTlv(buf: Buffer, offset: number): { start: number; end: number; next: number } {
  let pos = offset + 1;
  let length = buf[pos++]!;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[pos++]!;
  }
  return { start: pos, end: pos + length, next: pos + length };
}

/** The issuer name to use: the temp CA certificate's subject, byte for byte. */
function subjectOf(caDer: Buffer): Buffer {
  const cert = readTlv(caDer, 0);
  const tbs = readTlv(caDer, cert.start);
  let pos = tbs.start;
  if (caDer[pos] === 0xa0) pos = readTlv(caDer, pos).next; // [0] version
  pos = readTlv(caDer, pos).next; // serialNumber
  pos = readTlv(caDer, pos).next; // signature algorithm
  pos = readTlv(caDer, pos).next; // issuer
  pos = readTlv(caDer, pos).next; // validity
  const subject = readTlv(caDer, pos);
  return caDer.subarray(pos, subject.next);
}

function extension(oid: string, value: Buffer): Buffer {
  return der(0x30, derOid(oid), der(0x04, value));
}

/**
 * An X.509 client certificate for `spkiDer`, signed by the temp CA, carrying the
 * attestation in the legacy RA-TLS extensions.
 */
export function buildRaTlsClientCert(options: {
  spkiDer: Buffer;
  caCertPem: string;
  caKeyPem: string;
  quote: Buffer;
  eventLog: Buffer;
  now?: Date;
}): { certPem: string; certDer: Buffer } {
  const caKey = createPrivateKey(options.caKeyPem);
  if (caKey.asymmetricKeyType !== 'ec' || caKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('the KMS temp CA key is not a P-256 key');
  }
  const caDer = new X509Certificate(options.caCertPem).raw;
  const now = options.now ?? new Date();
  const notBefore = new Date(now.getTime() - 3600_000);
  const notAfter = new Date(now.getTime() + 3600_000);
  const serial = randomBytes(16);
  serial[0] = serial[0]! & 0x7f; // positive
  if (serial[0] === 0) serial[0] = 1;
  const sigAlg = der(0x30, derOid(OID_ECDSA_SHA256));
  const subject = der(0x30, der(0x31, der(0x30, derOid(OID_COMMON_NAME), der(0x0c, Buffer.from('openkey legacy-root client', 'utf8')))));
  const tbs = der(
    0x30,
    der(0xa0, der(0x02, Buffer.from([2]))), // v3
    der(0x02, serial),
    sigAlg,
    subjectOf(caDer),
    der(0x30, derUtcTime(notBefore), derUtcTime(notAfter)),
    subject,
    options.spkiDer,
    der(
      0xa3,
      der(0x30, extension(OID_RATLS_TDX_QUOTE, options.quote), extension(OID_RATLS_EVENT_LOG, options.eventLog)),
    ),
  );
  const signature = createSign('sha256').update(tbs).sign(caKey); // ECDSA, DER
  const certDer = der(0x30, tbs, sigAlg, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const b64 = certDer.toString('base64').replace(/(.{64})/g, '$1\n');
  return { certDer, certPem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n` };
}

// ---- HTTPS / prpc ---------------------------------------------------------

interface TlsOptions {
  ca?: string;
  cert?: string;
  key?: string;
  rejectUnauthorized: boolean;
}

function postJson(url: string, body: unknown, tls: TlsOptions, timeoutMs: number): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const req = httpsRequest(
      url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': payload.length },
        timeout: timeoutMs,
        ...tls,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode !== 200) {
            reject(new Error(`KMS answered ${res.statusCode}`));
            return;
          }
          try {
            const parsed: unknown = JSON.parse(text);
            if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
            resolve(parsed as Record<string, unknown>);
          } catch {
            reject(new Error('KMS answer is not a JSON object'));
          }
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('KMS request timed out')));
    req.on('error', reject);
    req.end(payload);
  });
}

function hexField(source: Record<string, unknown>, name: string): Buffer {
  const value = source[name];
  if (typeof value !== 'string' || !/^(?:[0-9a-fA-F]{2})+$/.test(value)) {
    throw new Error(`KMS answer field ${name} is not hex`);
  }
  return Buffer.from(value, 'hex');
}

function uintField(source: Record<string, unknown>, name: string): number {
  const value = source[name] ?? 0; // proto3 JSON omits a zero
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new Error(`KMS answer field ${name} is not a counter`);
  }
  return value;
}

export interface RaTlsClientCredentials {
  certPem: string;
  keyPem: string;
  /** What the guest agent was asked to quote: sha512("ratls-cert:" || SPKI DER). */
  reportData: Buffer;
  /** The vm_config the agent returned with the quote; forwarded to the KMS. */
  vmConfig: string;
}

/**
 * Steps 2 and 3: a throwaway P-256 key, quoted by the guest agent, and a client
 * certificate for it signed by the temp CA.
 */
export async function issueRaTlsClientCredentials(options: {
  agentEndpoint?: string;
  tempCaCertPem: string;
  tempCaKeyPem: string;
}): Promise<RaTlsClientCredentials> {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const reportData = createHash('sha512').update(Buffer.concat([Buffer.from('ratls-cert:', 'utf8'), spkiDer])).digest();
  // Lazy, as in index.ts: the SDK is loaded only where a guest agent exists.
  const { DstackClient } = await import('@phala/dstack-sdk');
  const quote = await new DstackClient(options.agentEndpoint).getQuote(reportData);
  const quoteHex = quote.quote.replace(/^0x/, '');
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(quoteHex) || typeof quote.event_log !== 'string') {
    throw new Error('the guest agent quote is malformed');
  }
  const { certPem } = buildRaTlsClientCert({
    spkiDer,
    caCertPem: options.tempCaCertPem,
    caKeyPem: options.tempCaKeyPem,
    quote: Buffer.from(quoteHex, 'hex'),
    eventLog: Buffer.from(quote.event_log, 'utf8'),
  });
  return {
    certPem,
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    reportData,
    vmConfig: quote.vm_config ?? '',
  };
}

export function createRaTlsKmsTransport(options: RaTlsKmsTransportOptions): LegacyKmsTransport {
  const base = `${options.kmsUrl.replace(/\/+$/, '').replace(/\/prpc$/, '')}/prpc`;
  const timeoutMs = options.timeoutMs ?? 20_000;
  const pin = options.kmsCaPin.toLowerCase();

  return {
    async getAppKey({ rootEpoch }): Promise<KmsAppKeyResponse> {
      // 1. Temp CA. Unauthenticated read; what it returns is checked against the pin.
      const tempCa = await postJson(`${base}/KMS.GetTempCaCert?json`, {}, { rejectUnauthorized: false }, timeoutMs);
      const tempCaCert = tempCa['temp_ca_cert'];
      const tempCaKey = tempCa['temp_ca_key'];
      const kmsCa = tempCa['ca_cert'];
      if (typeof tempCaCert !== 'string' || typeof tempCaKey !== 'string' || typeof kmsCa !== 'string') {
        throw new Error('GetTempCaCert answer is incomplete');
      }
      const spki = new X509Certificate(kmsCa).publicKey.export({ type: 'spki', format: 'der' });
      if (createHash('sha256').update(spki).digest('hex') !== pin) {
        throw new Error('the KMS CA does not match the pinned hash');
      }

      // 2-3. Quoted throwaway key and the temp-CA-signed client certificate.
      const creds = await issueRaTlsClientCredentials({
        agentEndpoint: options.agentEndpoint,
        tempCaCertPem: tempCaCert,
        tempCaKeyPem: tempCaKey,
      });

      // 4. GetAppKey for root epoch 0, trusting only the pinned CA.
      const answer = await postJson(
        `${base}/KMS.GetAppKey`,
        { api_version: 1, vm_config: creds.vmConfig, root_epoch: rootEpoch, launch_ticket: '' },
        { ca: kmsCa, cert: creds.certPem, key: creds.keyPem, rejectUnauthorized: true },
        timeoutMs,
      );
      return {
        rootEpoch: uintField(answer, 'root_epoch'),
        appEpoch: uintField(answer, 'app_epoch'),
        k256Key: new Uint8Array(hexField(answer, 'k256_key')),
        k256Signature: new Uint8Array(hexField(answer, 'k256_signature')),
      };
    },
  };
}
