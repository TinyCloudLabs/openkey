import assert from 'node:assert/strict';
import dns, { type LookupAddress, type LookupAllOptions } from 'node:dns';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { createConnection, createServer as createTcpServer, type Socket } from 'node:net';
import { canonicalManifestSha256Hex, fetchAndBindWellKnownManifest } from '../apps/api/src/services/manifest-origin-fetch';
import { pinnedHttpsGet } from '../apps/api/src/services/pinned-https-fetch';

const fixture = process.argv[2];
const pin = '8.8.4.4';
const maxBytes = 64 * 1024;
const manifest = { name: 'Fixture', app_id: 'test.manifest' };
const requests: { path: string | undefined; host: string | undefined }[] = [];
let trickleWrites = 0;
let trickleTimer: NodeJS.Timeout | undefined;
const key = readFileSync(`${fixture}/key.pem`);
const cert = readFileSync(`${fixture}/cert.pem`);
const server = createServer({ key, cert }, (req, res) => {
  requests.push({ path: req.url, host: req.headers.host });
  switch (req.url) {
    case '/.well-known/openkey-manifest.json':
      res.end(JSON.stringify(manifest));
      break;
    case '/redirect':
      res.writeHead(302, { location: '/destination' }).end();
      break;
    case '/limit':
      res.end(Buffer.alloc(maxBytes));
      break;
    case '/over-limit':
      res.write(Buffer.alloc(maxBytes));
      res.end('!');
      break;
    case '/slow': {
      res.write('start');
      const timer = trickleTimer = setInterval(() => {
        res.write('.');
        trickleWrites++;
      }, 200);
      res.on('close', () => clearInterval(timer));
      break;
    }
    default:
      res.end('fixture');
  }
});

const untrustedRequests: (string | undefined)[] = [];
const untrusted = createServer(
  { key: readFileSync(`${fixture}/untrusted-key.pem`), cert: readFileSync(`${fixture}/untrusted-cert.pem`) },
  (req, res) => {
    untrustedRequests.push(req.url);
    res.end(JSON.stringify(manifest));
  },
);

let fixturePort: number;
let acceptedAt: string | undefined;
let clientHello: Buffer | undefined;
const connections = new Set<Socket>();
const gate = createTcpServer((client) => {
  // Capture the first TLS record independently of the HTTPS server's API.
  if (acceptedAt === undefined) {
    acceptedAt = client.localAddress;
    let pending = Buffer.alloc(0);
    const record = (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length < 5 || pending.length < 5 + pending.readUInt16BE(3)) return;
      clientHello = pending.subarray(0, 5 + pending.readUInt16BE(3));
      client.off('data', record);
    };
    client.on('data', record);
  }
  const upstream = createConnection({ host: '127.0.0.1', port: fixturePort });
  connections.add(client);
  connections.add(upstream);
  client.on('error', () => upstream.destroy());
  upstream.on('error', () => client.destroy());
  client.on('close', () => {
    connections.delete(client);
    upstream.destroy();
  });
  upstream.on('close', () => {
    connections.delete(upstream);
    client.destroy();
  });
  client.pipe(upstream).pipe(client);
});

const resolver: { lookup(hostname: string, options: LookupAllOptions): Promise<LookupAddress[]> } = dns.promises;
const savedLookup = resolver.lookup;
const savedTlsEnv = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
let lookups = 0;
resolver.lookup = async () => [{ address: ++lookups === 1 ? pin : '127.0.0.1', family: 4 }];
try {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const fixtureAddress = server.address();
  assert(fixtureAddress && typeof fixtureAddress !== 'string');
  fixturePort = fixtureAddress.port;
  gate.listen(0, pin);
  await once(gate, 'listening');
  const address = gate.address();
  assert(address && typeof address !== 'string');
  const origin = `https://manifest.test:${address.port}`;
  const result = await fetchAndBindWellKnownManifest({ reportedOrigin: origin, declaredDigest: canonicalManifestSha256Hex(manifest) });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(lookups, 1);
  assert.equal(acceptedAt, pin);
  // server_name extension: 18 bytes, one 13-byte DNS name.
  const expectedSni = Buffer.concat([Buffer.from([0, 0, 0, 18, 0, 16, 0, 0, 13]), Buffer.from('manifest.test')]);
  assert(clientHello?.includes(expectedSni), 'the first TLS request sends manifest.test as SNI');
  assert.deepEqual(requests, [{ path: '/.well-known/openkey-manifest.json', host: `manifest.test:${address.port}` }]);
  console.log('PASS: manifest GET uses the validated address, SNI and Host');

  const wrongHost = new URL(`https://other.test:${address.port}/wrong-host`);
  assert.deepEqual(await pinnedHttpsGet(wrongHost, pin, maxBytes), { ok: false, kind: 'request' });
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  assert.deepEqual(await pinnedHttpsGet(wrongHost, pin, maxBytes), { ok: false, kind: 'request' });
  assert.equal(requests.length, 1);
  if (savedTlsEnv === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedTlsEnv;
  console.log('PASS: TLS rejects a wrong hostname with either environment setting');

  assert.deepEqual(await pinnedHttpsGet(new URL('/redirect', origin), pin, maxBytes), { ok: false, kind: 'status', status: 302 });
  assert.equal(requests.at(-1)?.path, '/redirect');
  assert(!requests.some(({ path }) => path === '/destination'));
  console.log('PASS: redirect target receives no request');

  const exact = await pinnedHttpsGet(new URL('/limit', origin), pin, maxBytes);
  assert(exact.ok && exact.bytes.byteLength === maxBytes);
  assert.deepEqual(await pinnedHttpsGet(new URL('/over-limit', origin), pin, maxBytes), { ok: false, kind: 'limit' });
  console.log('PASS: body size limit accepts 64 KiB and refuses 64 KiB + 1');

  const start = performance.now();
  assert.deepEqual(await pinnedHttpsGet(new URL('/slow', origin), pin, maxBytes), { ok: false, kind: 'body' });
  const elapsed = performance.now() - start;
  assert(elapsed >= 4_900 && elapsed < 7_000, `deadline took ${elapsed} ms`);
  assert(trickleWrites >= 3, 'the fixture sends body bytes before the deadline');
  console.log(`PASS: body deadline after ${Math.round(elapsed)} ms (Bun ${Bun.version})`);

  // A certificate for manifest.test that is not in NODE_EXTRA_CA_CERTS: the hostname matches, the chain is untrusted.
  untrusted.listen(0, '127.0.0.1');
  await once(untrusted, 'listening');
  const untrustedAddress = untrusted.address();
  assert(untrustedAddress && typeof untrustedAddress !== 'string');
  const untrustedUrl = new URL(`https://manifest.test:${untrustedAddress.port}/untrusted`);
  assert.deepEqual(await pinnedHttpsGet(untrustedUrl, '127.0.0.1', maxBytes), { ok: false, kind: 'request' });
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  assert.deepEqual(await pinnedHttpsGet(untrustedUrl, '127.0.0.1', maxBytes), { ok: false, kind: 'request' });
  if (savedTlsEnv === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedTlsEnv;
  assert.equal(untrustedRequests.length, 0);
  console.log('PASS: TLS rejects an untrusted certificate for the right hostname before any request');
} finally {
  resolver.lookup = savedLookup;
  if (savedTlsEnv === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  else process.env.NODE_TLS_REJECT_UNAUTHORIZED = savedTlsEnv;
  clearInterval(trickleTimer);
  for (const connection of connections) connection.destroy();
  server.closeAllConnections();
  gate.close();
  server.close();
  untrusted.closeAllConnections();
  untrusted.close();
}
