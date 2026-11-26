import { Client } from 'undici/index.js';
import { isIP } from 'node:net';
import { checkServerIdentity, connect } from 'node:tls';

const DEADLINE_MS = 5_000;

type PinnedHttpsResult =
  | { ok: true; bytes: Uint8Array; contentType: string | undefined }
  | { ok: false; kind: 'request' | 'body' | 'limit' | 'no-body' }
  | { ok: false; kind: 'status'; status: number };

/** The caller validates the IP. The URL supplies the HTTP and TLS identity, not the socket destination. */
export async function pinnedHttpsGet(url: URL, ip: string, maxBytes: number, callerSignal?: AbortSignal): Promise<PinnedHttpsResult> {
  if (url.protocol !== 'https:' || !isIP(ip)) return { ok: false, kind: 'request' };
  const hostname = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
  const intrinsicDeadline = AbortSignal.timeout(DEADLINE_MS);
  const signal = callerSignal ? AbortSignal.any([callerSignal, intrinsicDeadline]) : intrinsicDeadline;
  // The package Client parses HTTP on a socket we verify before handing it over.
  const client = new Client(url.origin, {
    pipelining: 0,
    maxResponseSize: maxBytes,
    connect: (_options, callback) => {
      if (signal.aborted) {
        callback(signal.reason, null);
        return;
      }
      const socket = connect({
        host: ip,
        port: Number(url.port || 443),
        servername: isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: true,
      });
      const abort = () => socket.destroy(signal.reason);
      const onError = (error: Error) => callback(error, null);
      signal.addEventListener('abort', abort, { once: true });
      socket.once('close', () => signal.removeEventListener('abort', abort));
      socket.once('error', onError);
      socket.once('secureConnect', () => {
        const cert = socket.getPeerCertificate();
        if (!socket.authorized || !cert?.raw || checkServerIdentity(hostname, cert)) {
          socket.destroy(new Error('TLS identity did not verify'));
          return;
        }
        socket.off('error', onError);
        callback(null, socket);
      });
    },
  });
  let hasHeaders = false;
  try {
    const response = await client.request({
      path: url.pathname + url.search,
      method: 'GET',
      headers: { Host: url.host, Accept: 'application/json', 'Accept-Encoding': 'identity' },
      idempotent: false,
      signal,
    });
    hasHeaders = true;
    const status = response.statusCode;
    if (status < 200 || status >= 300) return { ok: false, kind: 'status', status };
    if (status === 204 || status === 205) return { ok: false, kind: 'no-body' };

    const chunks: Buffer[] = [];
    for await (const chunk of response.body) chunks.push(chunk);
    const contentType = response.headers['content-type'];
    return {
      ok: true,
      bytes: chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks),
      // Repeated headers join as a fetch Headers object would, so a caller can refuse them.
      contentType: Array.isArray(contentType) ? contentType.join(', ') : contentType,
    };
  } catch (error) {
    if ((error as { code?: string } | null)?.code === 'UND_ERR_RES_EXCEEDED_MAX_SIZE') {
      return { ok: false, kind: 'limit' };
    }
    return { ok: false, kind: hasHeaders ? 'body' : 'request' };
  } finally {
    await client.destroy();
  }
}
