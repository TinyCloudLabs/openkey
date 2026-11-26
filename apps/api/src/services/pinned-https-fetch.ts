import { Client } from 'undici/index.js';
import { isIP } from 'node:net';
import { checkServerIdentity, connect, type TLSSocket } from 'node:tls';

const DEADLINE_MS = 5_000;

type PinnedHttpsResult =
  | { ok: true; bytes: Uint8Array; contentType: string | undefined }
  | { ok: false; kind: 'request' | 'body' | 'limit' | 'no-body' }
  | { ok: false; kind: 'status'; status: number };

/** The caller validates the IP. The URL supplies the HTTP and TLS identity, not the socket destination. */
export async function pinnedHttpsGet(url: URL, ip: string, maxBytes: number, callerSignal?: AbortSignal): Promise<PinnedHttpsResult> {
  if (url.protocol !== 'https:' || !isIP(ip)) return { ok: false, kind: 'request' };
  const hostname = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
  const started = performance.now();
  const controller = new AbortController();
  const signal = controller.signal;
  const timer = setTimeout(() => controller.abort(), DEADLINE_MS);
  const abortFromCaller = () => controller.abort(callerSignal?.reason);
  callerSignal?.addEventListener('abort', abortFromCaller, { once: true });
  if (callerSignal?.aborted) abortFromCaller();
  let activeSocket: TLSSocket | undefined;
  const expired = () => {
    if (performance.now() - started >= DEADLINE_MS) controller.abort();
    return signal.aborted;
  };
  // The package Client parses HTTP on a socket we verify before handing it over.
  const client = new Client(url.origin, {
    pipelining: 0,
    maxResponseSize: maxBytes,
    connect: (_options, callback) => {
      if (signal.aborted) {
        callback(signal.reason, null);
        return;
      }
      const socket = activeSocket = connect({
        host: ip,
        port: Number(url.port || 443),
        servername: isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: true,
      });
      const onError = (error: Error) => callback(error, null);
      socket.once('close', () => { if (activeSocket === socket) activeSocket = undefined; });
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
  const abortActive = () => {
    activeSocket?.destroy(signal.reason);
    void client.destroy(signal.reason instanceof Error ? signal.reason : undefined);
  };
  signal.addEventListener('abort', abortActive, { once: true });
  if (signal.aborted) abortActive();
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
    if (expired()) return { ok: false, kind: 'body' };
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
    clearTimeout(timer);
    callerSignal?.removeEventListener('abort', abortFromCaller);
    signal.removeEventListener('abort', abortActive);
    await client.destroy();
  }
}
