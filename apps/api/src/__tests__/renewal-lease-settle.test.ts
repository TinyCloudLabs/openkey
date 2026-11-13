// TC-2946: settling a lease record never undoes what an approval confirmed meanwhile. The confirm can commit while
// a settle is between reading the record and writing it (on Postgres the approval's save doesn't take the owner's
// lock); this drives that order deterministically against an in-memory record. The Postgres race itself runs in
// renewal-lease-stop.integration.test.ts with OPENKEY_TEST_POSTGRES_URL.
import { describe, expect, test } from 'bun:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { revokeRenewalLeases } from '../services/renewal-lease-revocation';

type Row = {
  leaseCid: string; userId: string; sessionId: string | null; ownerDid: string; nodeOrigin: string; leaseExpiresAt: Date; createdAt: Date;
  admittedAt: Date | null; revokedAt: Date | null; neverAdmittedAt: Date | null; leaseAuthorization: string | null;
};

/** Just enough of Prisma's `where` for these records: equality and `{ gt }`, plus `null`. */
function matches(row: Row, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([field, condition]) => {
    const value = row[field as keyof Row];
    if (condition && typeof condition === 'object' && !(condition instanceof Date) && 'gt' in condition) return value instanceof Date && value > (condition.gt as Date);
    return condition === null ? value === null : value === condition;
  });
}

function database(row: Row) {
  const renewalLease = {
    findMany: async ({ where }: { where: Record<string, unknown> }) => (matches(row, where) ? [{ ...row }] : []),
    updateMany: async ({ where, data }: { where: Record<string, unknown>; data: Partial<Row> }) => {
      if (!matches(row, where)) return { count: 0 };
      Object.assign(row, data);
      return { count: 1 };
    },
  };
  return {
    renewalLease,
    ethereumKey: { findMany: async () => [{ address: row.ownerDid.split(':').at(-1)!, keyType: 'MANAGED', sealedBlob: 'sealed', userId: row.userId, sealingContext: null }] },
    $transaction: async (run: (tx: unknown) => Promise<void>) => run({ $queryRaw: async () => [], renewalLease }),
  } as never;
}

describe('settling a lease record', () => {
  test('an approval confirming the lease while it is settled is never overwritten as never admitted', async () => {
    // The node refuses the replayed admission and says it holds no such lease, as when the approval's own admission
    // has not landed yet; meanwhile the approval confirms the record.
    const server = createServer((request, response) => {
      if (request.url === '/delegate') row.admittedAt = new Date();
      response.writeHead(403, { 'content-type': 'text/plain' });
      response.end(request.url === '/revoke' ? 'Cannot find parent delegation' : 'Delegation refused');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const row: Row = {
      leaseCid: `bafkr4i${'a'.repeat(52)}`, userId: 'owner', sessionId: null, ownerDid: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
      nodeOrigin: origin, leaseExpiresAt: new Date(Date.now() + 3_600_000), createdAt: new Date(),
      admittedAt: null, revokedAt: null, neverAdmittedAt: null, leaseAuthorization: 'sealed-lease',
    };
    try {
      const report = await revokeRenewalLeases(database(row), 'owner', { kind: 'all' }, {
        signManaged: async () => `0x${'ab'.repeat(65)}`, fetch, now: () => new Date(), seal: async (value) => value, open: async () => 'signed-lease',
      });
      expect(report).toEqual({ stopped: [], notStopped: [{ leaseCid: row.leaseCid, reason: 'node_unavailable' }] });
      expect(row.admittedAt).not.toBeNull();
      expect(row.neverAdmittedAt).toBeNull();
    } finally {
      server.close();
    }
  });
});
