// The KMS leg of the epoch-0 read: an RA-TLS client for `KMS.GetAppKey`. TC-3554, K1.
//
// DO NOT MERGE. Implements the protocol in tinycloud-node's
// docs/tc-3554-kms-epoch-fetch.md (aa33b25c; /var/tmp/aa33-tc3554.IODx/
// tc-3554-kms-epoch-fetch.md, sha256 033d819a…); if this file and that document
// disagree, this file is the bug:
//   1. the guest agent's app id must equal the pinned one;
//   2. every KMS connection trusts only the pinned KMS CA, with hostname
//      verification, and the server's leaf must carry extension
//      1.3.6.1.4.1.62397.1.4 = "kms:rpc" (the CA also signs app certificates);
//   3. `GetTempCaCert` (no client certificate);
//   4-6. a throwaway P-256 key, a quote over sha512("ratls-cert:" || SPKI), whose
//      REPORTDATA is checked, and a client certificate signed by the temp CA
//      carrying quote and event log in dstack's legacy RA-TLS extensions;
//   7. `GetAppKey {api_version: 1, vm_config, root_epoch, launch_ticket: ""}`
//      presenting [client cert, temp CA cert]; any non-2xx stops, no retry.
// The KMS answer is not trusted for what it says: loadLegacyRoot checks its epoch
// and its signature under a pinned root key. Nothing here is a fallback.
//
// Not run against a real KMS: without TDX hardware no quote binds a fresh key.
// Tests cover the wire shape against a fake agent and a fake KMS.
import { createHash, createPrivateKey, createSign, generateKeyPairSync, randomBytes, X509Certificate } from 'crypto';
import { request as httpsRequest } from 'https';
import type { TLSSocket } from 'tls';
import type { KmsAppKeyResponse, LegacyKmsTransport } from './legacy-root';

export interface RaTlsKmsTransportOptions {
  /** KMS origin, `https://host[:port]`, no path (`/prpc` is added). */
  kmsUrl: string;
  /** The KMS RPC CA certificate: base64 (standard, padded) of its DER. The only trust anchor. */
  kmsCaCert: string;
  /** The app id, 20 bytes as hex. The guest agent must report the same one. */
  appId: string;
  /** Guest agent socket or URL; default is the SDK's own (/var/run/dstack.sock). */
  agentEndpoint?: string;
  /** Per-call limit. Default 20 s. */
  timeoutMs?: number;
}

const OID_RATLS_TDX_QUOTE = '1.3.6.1.4.1.62397.1.1';
const OID_RATLS_EVENT_LOG = '1.3.6.1.4.1.62397.1.2';
const OID_RATLS_CERT_USAGE = '1.3.6.1.4.1.62397.1.4';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_COMMON_NAME = '2.5.4.3';
const OID_KEY_USAGE = '2.5.29.15';
const KMS_RPC_USAGE = 'kms:rpc';

// TDX v4 quote: 48-byte header, then the 584-byte body whose REPORTDATA starts at body offset 520.
const TD_REPORT_DATA_OFFSET = 48 + 520;

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

function oidBytes(oid: string): Buffer {
  const arcs = oid.split('.').map(Number);
  const out: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const chunk = [arc & 0x7f];
    for (let n = Math.floor(arc / 128); n > 0; n = Math.floor(n / 128)) chunk.unshift((n & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return Buffer.from(out);
}

function derOid(oid: string): Buffer {
  return der(0x06, oidBytes(oid));
}

function derUtcTime(date: Date): Buffer {
  const pad = (n: number) => String(n).padStart(2, '0');
  const text = `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  return der(0x17, Buffer.from(text, 'ascii'));
}

/** Reads one TLV at `offset`; returns its content range and the end of the element. */
function readTlv(buf: Buffer, offset: number): { tag: number; start: number; end: number; next: number } {
  const tag = buf[offset]!;
  let pos = offset + 1;
  let length = buf[pos++]!;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + buf[pos++]!;
  }
  return { tag, start: pos, end: pos + length, next: pos + length };
}

/** The tbsCertificate of a DER certificate, with the offset of its first field after `version`. */
function tbsFields(certDer: Buffer): { tbs: { start: number; end: number }; firstAfterVersion: number } {
  const cert = readTlv(certDer, 0);
  const tbs = readTlv(certDer, cert.start);
  let pos = tbs.start;
  if (certDer[pos] === 0xa0) pos = readTlv(certDer, pos).next; // [0] version
  return { tbs, firstAfterVersion: pos };
}

/** The issuer name to use: the temp CA certificate's subject, byte for byte. */
function subjectOf(caDer: Buffer): Buffer {
  let pos = tbsFields(caDer).firstAfterVersion;
  pos = readTlv(caDer, pos).next; // serialNumber
  pos = readTlv(caDer, pos).next; // signature algorithm
  pos = readTlv(caDer, pos).next; // issuer
  pos = readTlv(caDer, pos).next; // validity
  const subject = readTlv(caDer, pos);
  return caDer.subarray(pos, subject.next);
}

/**
 * The bytes inside the extnValue OCTET STRING of extension `oid`, or undefined.
 * dstack writes its values as a DER OCTET STRING inside extnValue.
 */
export function certExtensionValue(certDer: Buffer, oid: string): Buffer | undefined {
  const { tbs, firstAfterVersion } = tbsFields(certDer);
  let pos = firstAfterVersion;
  for (const _skipped of ['serialNumber', 'signature', 'issuer', 'validity', 'subject', 'subjectPublicKeyInfo']) {
    pos = readTlv(certDer, pos).next;
  }
  while (pos < tbs.end && certDer[pos] !== 0xa3) pos = readTlv(certDer, pos).next; // skip [1] and [2] unique ids
  if (pos >= tbs.end) return undefined;
  const extensions = readTlv(certDer, readTlv(certDer, pos).start);
  const wanted = oidBytes(oid);
  for (let ext = extensions.start; ext < extensions.end; ) {
    const item = readTlv(certDer, ext);
    const id = readTlv(certDer, item.start);
    if (certDer.subarray(id.start, id.end).equals(wanted)) {
      let next = id.next;
      if (certDer[next] === 0x01) next = readTlv(certDer, next).next; // critical flag
      const value = readTlv(certDer, next);
      return certDer.subarray(value.start, value.end);
    }
    ext = item.next;
  }
  return undefined;
}

/** A dstack RA-TLS extension: extnValue holds a DER OCTET STRING of the raw bytes. */
function extension(oid: string, raw: Buffer): Buffer {
  return der(0x30, derOid(oid), der(0x04, der(0x04, raw)));
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
  serial[0] = (serial[0]! & 0x7f) | 0x01; // positive, no leading zero
  const sigAlg = der(0x30, derOid(OID_ECDSA_SHA256));
  const subject = der(0x30, der(0x31, der(0x30, derOid(OID_COMMON_NAME), der(0x0c, Buffer.from('RA-TLS TEMP Cert', 'utf8')))));
  const keyUsage = der(0x30, derOid(OID_KEY_USAGE), der(0x01, Buffer.from([0xff])), der(0x04, der(0x03, Buffer.from([0x07, 0x80])))); // digitalSignature
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
      der(
        0x30,
        keyUsage,
        extension(OID_RATLS_TDX_QUOTE, options.quote),
        extension(OID_RATLS_EVENT_LOG, options.eventLog),
      ),
    ),
  );
  const signature = createSign('sha256').update(tbs).sign(caKey); // ECDSA, DER
  const certDer = der(0x30, tbs, sigAlg, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const b64 = certDer.toString('base64').replace(/(.{64})/g, '$1\n');
  return { certDer, certPem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n` };
}

// ---- HTTPS / prpc ---------------------------------------------------------

interface ClientCredentials {
  /** PEM chain presented to the KMS: client cert, then the temp CA cert. */
  certChainPem: string;
  keyPem: string;
}

/**
 * POSTs JSON to the KMS. The only trust anchor is `caPem` (no system roots), the
 * hostname is verified, TLS is 1.2 or later, and the server's leaf must carry
 * the `kms:rpc` usage extension. Any non-2xx answer is an error.
 */
function kmsPost(
  url: string,
  body: unknown,
  caPem: string,
  credentials: ClientCredentials | undefined,
  timeoutMs: number,
): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const req = httpsRequest(
      url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': payload.length },
        timeout: timeoutMs,
        ca: caPem, // replaces the system roots
        minVersion: 'TLSv1.2',
        rejectUnauthorized: true,
        ...(credentials ? { cert: credentials.certChainPem, key: credentials.keyPem } : {}),
      },
      (res) => {
        const leaf = (res.socket as TLSSocket).getPeerCertificate?.().raw;
        const usage = leaf ? certExtensionValue(leaf, OID_RATLS_CERT_USAGE) : undefined;
        const expected = Buffer.concat([Buffer.from([0x04, KMS_RPC_USAGE.length]), Buffer.from(KMS_RPC_USAGE, 'utf8')]);
        if (!usage || !usage.equals(expected)) {
          res.resume();
          reject(new Error('the KMS server certificate is not marked kms:rpc'));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          if (res.statusCode === undefined || res.statusCode < 200 || res.statusCode > 299) {
            reject(new Error(`KMS answered ${res.statusCode}`));
            return;
          }
          try {
            const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
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

/** Bytes fields in KMS JSON are hex strings; an optional `0x` prefix is accepted. */
function hexField(source: Record<string, unknown>, name: string): Buffer {
  const value = source[name];
  const stripped = typeof value === 'string' ? value.replace(/^0x/, '') : undefined;
  if (stripped === undefined || !/^(?:[0-9a-fA-F]{2})+$/.test(stripped)) {
    throw new Error(`KMS answer field ${name} is not hex`);
  }
  return Buffer.from(stripped, 'hex');
}

/** The counter, `undefined` when the field is absent, an error when it is present but not a counter. */
function counterField(source: Record<string, unknown>, name: string): number | undefined {
  const value = source[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new Error(`KMS answer field ${name} is not a counter`);
  }
  return value;
}

// ---- credentials (steps 4-6) ---------------------------------------------

export interface RaTlsClientCredentials {
  certPem: string;
  keyPem: string;
  /** What the guest agent was asked to quote: sha512("ratls-cert:" || SPKI DER). */
  reportData: Buffer;
  /** The vm_config the agent returned with the quote; forwarded to the KMS. */
  vmConfig: string;
}

/**
 * Steps 4 to 6: a throwaway P-256 key, quoted by the guest agent, and a client
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
  const quoteBytes = Buffer.from(quoteHex, 'hex');
  const quoted = quoteBytes.subarray(TD_REPORT_DATA_OFFSET, TD_REPORT_DATA_OFFSET + 64);
  if (quoted.length !== 64 || !quoted.equals(reportData)) {
    throw new Error('the quote REPORTDATA is not the requested report data');
  }
  const { certPem } = buildRaTlsClientCert({
    spkiDer,
    caCertPem: options.tempCaCertPem,
    caKeyPem: options.tempCaKeyPem,
    quote: quoteBytes,
    eventLog: Buffer.from(quote.event_log, 'utf8'),
  });
  return {
    certPem,
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    reportData,
    vmConfig: quote.vm_config ?? '',
  };
}

// ---- transport -----------------------------------------------------------

export function createRaTlsKmsTransport(options: RaTlsKmsTransportOptions): LegacyKmsTransport {
  const base = `${options.kmsUrl.replace(/\/+$/, '').replace(/\/prpc$/, '')}/prpc`;
  const timeoutMs = options.timeoutMs ?? 20_000;
  const expectedAppId = options.appId.replace(/^0x/, '').toLowerCase();
  const caDer = Buffer.from(options.kmsCaCert, 'base64');
  const caPem = new X509Certificate(caDer).toString(); // throws on a CA that does not parse

  return {
    async getAppKey({ rootEpoch }): Promise<KmsAppKeyResponse> {
      // 1. The agent must be this app.
      const { DstackClient } = await import('@phala/dstack-sdk');
      const info = await new DstackClient(options.agentEndpoint).info();
      if (typeof info.app_id !== 'string' || info.app_id.replace(/^0x/, '').toLowerCase() !== expectedAppId) {
        throw new Error('the guest agent reports a different app id');
      }

      // 2-3. Temp CA, over TLS pinned to the KMS CA, without a client certificate.
      const tempCa = await kmsPost(`${base}/GetTempCaCert?json`, {}, caPem, undefined, timeoutMs);
      const tempCaCert = tempCa['temp_ca_cert'];
      const tempCaKey = tempCa['temp_ca_key'];
      if (typeof tempCaCert !== 'string' || typeof tempCaKey !== 'string') {
        throw new Error('GetTempCaCert answer is incomplete');
      }

      // 4-6. Quoted throwaway key and the temp-CA-signed client certificate.
      const creds = await issueRaTlsClientCredentials({
        agentEndpoint: options.agentEndpoint,
        tempCaCertPem: tempCaCert,
        tempCaKeyPem: tempCaKey,
      });

      // 7. GetAppKey for root epoch `rootEpoch`; app_epoch stays unset.
      const answer = await kmsPost(
        `${base}/GetAppKey?json`,
        { api_version: 1, vm_config: creds.vmConfig, root_epoch: rootEpoch, launch_ticket: '' },
        caPem,
        { certChainPem: `${creds.certPem}${tempCaCert}`, keyPem: creds.keyPem },
        timeoutMs,
      );
      return {
        // Absent stays undefined: loadLegacyRoot refuses it. It is never read as 0.
        rootEpoch: counterField(answer, 'root_epoch'),
        appEpoch: counterField(answer, 'app_epoch'),
        k256Key: new Uint8Array(hexField(answer, 'k256_key')),
        k256Signature: new Uint8Array(hexField(answer, 'k256_signature')),
      };
    },
  };
}
