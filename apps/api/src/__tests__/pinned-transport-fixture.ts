import { once } from 'node:events';
import http from 'node:http';
import net from 'node:net';

// A stand-in for `node:tls` `connect` that lets the real pinned HTTPS transport
// (parser, size cap, redirect rule, identity check, pin) run against a local
// plain-HTTP origin. The transport dials the address it was given; the stand-in
// records that address and the TLS server name, then connects to the local
// origin and presents a certificate for `certificateName` (the requested host by
// default). Use it with `mockModules({ 'node:tls': () => ({ connect: fixtureConnect }) })`.

export type Dial = { host: string; port: number; servername: string | undefined };
export type OriginHandler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

export const fixture = {
  /** Every socket the transport asked for. */
  dialed: [] as Dial[],
  /** Every HTTP request that reached the local origin. */
  requests: [] as string[],
  handler: ((_req, res) => { res.end('{}'); }) as OriginHandler,
  /** The name the presented certificate carries; unset presents the requested one. */
  certificateName: undefined as string | undefined,
  port: 0,
};

export function resetFixture(): void {
  fixture.dialed = [];
  fixture.requests = [];
  fixture.handler = (_req, res) => { res.end('{}'); };
  fixture.certificateName = undefined;
}

export function fixtureConnect(options: { host: string; port: number; servername?: string }): net.Socket {
  fixture.dialed.push({ host: options.host, port: options.port, servername: options.servername });
  const socket = net.connect({ host: '127.0.0.1', port: fixture.port }) as net.Socket & Record<string, unknown>;
  const name = fixture.certificateName ?? options.servername;
  socket.authorized = true;
  socket.getPeerCertificate = () => ({
    raw: Buffer.from('fixture'),
    subject: { CN: name ?? options.host },
    subjectaltname: name ? `DNS:${name}` : `IP Address:${options.host}`,
  });
  socket.once('connect', () => queueMicrotask(() => socket.emit('secureConnect')));
  return socket;
}

export async function startOrigin(): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    fixture.requests.push(req.url ?? '');
    fixture.handler(req, res);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  fixture.port = (server.address() as net.AddressInfo).port;
  return server;
}
