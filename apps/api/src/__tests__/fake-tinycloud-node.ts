// A loopback stand-in for the TinyCloud node endpoints the TinyCloud bootstrap uses (TC-1608).
// It keeps the node state the bootstrap depends on: which spaces are hosted, and which delegations
// the node already holds. A fresh host delegation (a SIWE granting `tinycloud.space/host`) hosts its
// space and lists it as `activated`; a fresh session delegation is `skipped` for every space that is
// not hosted yet; a delegation the node already holds is answered with empty `activated` and
// `skipped`, as the real node does (v1.21.5). Every request is recorded, so a test can count the
// host delegations a space received.

export const FAKE_PEER_ID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

export interface RecordedDelegation {
  spaceId: string;
  authorization: string;
}

export interface FakeTinyCloudNode {
  /** Origin without a trailing slash: usable as TINYCLOUD_BOOTSTRAP_HOST and as the request host. */
  url: string;
  hosted: Set<string>;
  hostPosts: RecordedDelegation[];
  sessionPosts: RecordedDelegation[];
  peerGets: string[];
  invokes: number;
  /** Awaited before a host delegation is applied; a pending promise is a slow or hung node. */
  beforeHost?: (spaceId: string) => Promise<void>;
  /** Awaited before a peer-id response; a pending promise is a hung node. */
  beforePeer?: (spaceId: string) => Promise<void>;
  /** Awaited before a session delegation is answered; a pending promise is a hung node. */
  beforeSession?: () => Promise<void>;
  /** Status for host delegations: anything but 200 makes the node refuse to host the space. */
  hostStatus: number;
  /** false: the node answers a host delegation with 200 but neither hosts the space nor lists it as activated. */
  hostActivates: boolean;
  /** Delegations (by authorization header) the node already stores, like the real node's content-addressed rows. */
  known: Set<string>;
  /** Status for /invoke and encryption requests: 200 unless a test makes the node fail the seeding. */
  invokeStatus: number;
  stop: () => void;
}

interface Recap {
  att?: Record<string, Record<string, unknown>>;
}

export function recapOf(authorization: string): Record<string, Record<string, unknown>> {
  // The authorization is CBOR around the SIWE; the recap is a base64url run inside it, followed
  // by the next CBOR field. Trim until what remains decodes to the recap JSON.
  const decoded = Buffer.from(authorization, 'base64').toString('latin1');
  let candidate = /urn:recap:([A-Za-z0-9_-]+)/.exec(decoded)?.[1];
  if (!candidate) throw new Error('delegation carries no recap');
  for (; candidate.length > 0; candidate = candidate.slice(0, -1)) {
    try {
      return (JSON.parse(Buffer.from(candidate, 'base64url').toString('utf8')) as Recap).att ?? {};
    } catch {
      // Still includes bytes of the next field.
    }
  }
  throw new Error('delegation recap is not JSON');
}

export function startFakeTinyCloudNode(): FakeTinyCloudNode {
  const node: FakeTinyCloudNode = {
    url: '',
    hosted: new Set(),
    known: new Set(),
    hostPosts: [],
    sessionPosts: [],
    peerGets: [],
    invokes: 0,
    hostStatus: 200,
    hostActivates: true,
    invokeStatus: 200,
    stop: () => server.stop(true),
  };

  const server = Bun.serve({
    port: 0,
    hostname: '127.0.0.1',
    async fetch(request) {
      const { pathname } = new URL(request.url);
      if (request.method === 'GET' && pathname.startsWith('/peer/generate/')) {
        const spaceId = decodeURIComponent(pathname.slice('/peer/generate/'.length));
        node.peerGets.push(spaceId);
        await node.beforePeer?.(spaceId);
        return new Response(FAKE_PEER_ID);
      }
      if (request.method === 'POST' && pathname === '/delegate') {
        const authorization = request.headers.get('authorization') ?? '';
        const att = recapOf(authorization);
        const resources = Object.entries(att);
        const hostResource = resources.find(([, abilities]) => 'tinycloud.space/host' in abilities);
        const known = node.known.has(authorization);
        if (hostResource) {
          const spaceId = hostResource[0].replace(/\/space$/, '');
          node.hostPosts.push({ spaceId, authorization });
          await node.beforeHost?.(spaceId);
          if (node.hostStatus !== 200) return new Response('node refused the host delegation', { status: node.hostStatus });
          if (known || !node.hostActivates) return Response.json({ cid: 'bafy-host', activated: [], skipped: [] });
          node.known.add(authorization);
          node.hosted.add(spaceId);
          return Response.json({ cid: 'bafy-host', activated: [spaceId], skipped: [] });
        }
        const spaceIds = [...new Set(resources.map(([resource]) => resource.split('/')[0]!))];
        for (const spaceId of spaceIds) node.sessionPosts.push({ spaceId, authorization });
        await node.beforeSession?.();
        // tinycloud-core db.rs:1873-1884, 2907-2913: a delegation the node already holds is answered
        // from its row, with nothing activated and nothing skipped, whether or not its space is hosted.
        if (known) return Response.json({ cid: 'bafy-session', activated: [], skipped: [] });
        node.known.add(authorization);
        return Response.json({
          cid: 'bafy-session',
          activated: spaceIds.filter((spaceId) => node.hosted.has(spaceId)),
          skipped: spaceIds.filter((spaceId) => !node.hosted.has(spaceId)),
        });
      }
      if (pathname === '/invoke' || pathname.startsWith('/encryption/')) {
        node.invokes += 1;
        return new Response('{}', { status: node.invokeStatus });
      }
      return new Response('not found', { status: 404 });
    },
  });
  node.url = `http://127.0.0.1:${server.port}`;
  return node;
}
