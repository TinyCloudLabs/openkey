// The sidecar leg of the epoch-0 read: a client for the dstack-key-recovery sidecar. TC-3554, K1.
//
// DO NOT MERGE. The sidecar (ghcr.io/dstack-tee/dstack-key-recovery, run with
// `serve --no-addr --socket <path>`) asks the KMS for the epoch-0 app root inside
// the CVM and answers `GET /v0/key?path=P&root_epoch=0&app_epoch=0` with
// {api, key, public_key, signature_chain, root_epoch, app_epoch}. It listens on a unix
// socket only (no TCP, no ports), on a volume shared with this process alone.
//
// This client sends both epochs explicitly (an unset app_epoch selects the app's
// current epoch) and leaves `purpose` empty. It trusts nothing it reads:
// loadLegacyRoot verifies the answer under the pinned epoch-0 root and a canary.
import { request as httpRequest } from 'http';
import type { LegacySidecarTransport, SidecarKeyResponse } from './legacy-root';

export interface SidecarTransportOptions {
  /** Absolute path of the sidecar's unix socket. */
  socketPath: string;
  /** Per-call limit. Default 20 s. */
  timeoutMs?: number;
}

const MAX_BODY_BYTES = 64 * 1024;

/** Bytes fields are hex strings; an optional `0x` prefix is accepted. */
function hexBytes(value: unknown, name: string): Uint8Array {
  const stripped = typeof value === 'string' ? value.replace(/^0x/, '') : undefined;
  if (stripped === undefined || !/^(?:[0-9a-fA-F]{2})+$/.test(stripped)) {
    throw new Error(`sidecar answer field ${name} is not hex`);
  }
  return new Uint8Array(Buffer.from(stripped, 'hex'));
}

/** The counter, `undefined` when the field is absent, an error when it is present but not a counter. */
function counter(value: unknown, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new Error(`sidecar answer field ${name} is not a counter`);
  }
  return value;
}

export function createSidecarTransport(options: SidecarTransportOptions): LegacySidecarTransport {
  const timeoutMs = options.timeoutMs ?? 20_000;
  return {
    getKey({ path, rootEpoch, appEpoch }): Promise<SidecarKeyResponse> {
      if (path.length === 0) {
        return Promise.reject(new Error('the key path is empty'));
      }
      const query = new URLSearchParams({ path, root_epoch: String(rootEpoch), app_epoch: String(appEpoch) });
      return new Promise((resolve, reject) => {
        const req = httpRequest(
          { socketPath: options.socketPath, path: `/v0/key?${query.toString()}`, method: 'GET', timeout: timeoutMs },
          (res) => {
            const chunks: Buffer[] = [];
            let size = 0;
            res.on('data', (chunk: Buffer) => {
              size += chunk.length;
              if (size > MAX_BODY_BYTES) {
                req.destroy(new Error('sidecar answer is too large'));
                return;
              }
              chunks.push(chunk);
            });
            res.on('end', () => {
              if (res.statusCode === undefined || res.statusCode < 200 || res.statusCode > 299) {
                reject(new Error(`sidecar answered ${res.statusCode}`));
                return;
              }
              try {
                const body: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
                if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new Error('not an object');
                const answer = body as Record<string, unknown>;
                const chain = answer['signature_chain'];
                if (!Array.isArray(chain)) throw new Error('signature_chain is not a list');
                resolve({
                  api: typeof answer['api'] === 'string' ? answer['api'] : undefined,
                  key: hexBytes(answer['key'], 'key'),
                  publicKey: hexBytes(answer['public_key'], 'public_key'),
                  signatureChain: chain.map((link, index) => hexBytes(link, `signature_chain[${index}]`)),
                  rootEpoch: counter(answer['root_epoch'], 'root_epoch'),
                  appEpoch: counter(answer['app_epoch'], 'app_epoch'),
                });
              } catch {
                reject(new Error('sidecar answer is malformed'));
              }
            });
          },
        );
        req.on('timeout', () => req.destroy(new Error('sidecar request timed out')));
        req.on('error', reject);
        req.end();
      });
    },
  };
}
