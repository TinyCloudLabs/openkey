// OpenKey DB - Prisma client export
import { PrismaClient } from './generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { DEFAULT_PGLITE_DATABASE_URL, isPgliteConnectionString, resolvePgliteDataDir } from './pglite-url';

const pgliteClients = new Map<string, { client: PGlite; refs: number }>();

function resolveConnectionString(opts?: { connectionString?: string }) {
  const connStr = opts?.connectionString ?? process.env.DATABASE_URL;
  if (connStr) {
    return connStr;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('DATABASE_URL environment variable is not set');
  }
  return DEFAULT_PGLITE_DATABASE_URL;
}

function getPgliteClient(connectionString: string) {
  const dataDir = resolvePgliteDataDir(connectionString);
  const existingEntry = pgliteClients.get(dataDir);
  if (existingEntry) {
    existingEntry.refs += 1;
    return { dataDir, client: existingEntry.client };
  }

  const client = new PGlite(dataDir);
  void client.waitReady.then(() => {
    process.exitCode = undefined;
  });
  pgliteClients.set(dataDir, { client, refs: 1 });
  return { dataDir, client };
}

async function releasePgliteClient(dataDir: string) {
  const entry = pgliteClients.get(dataDir);
  if (!entry) {
    return;
  }

  entry.refs -= 1;
  if (entry.refs > 0) {
    return;
  }

  pgliteClients.delete(dataDir);
  await entry.client.close();
  process.exitCode = undefined;
}

export function createPrismaClient(opts?: { connectionString?: string; log?: Array<'query' | 'info' | 'warn' | 'error'> }) {
  const connStr = resolveConnectionString(opts);
  if (isPgliteConnectionString(connStr)) {
    const { dataDir, client } = getPgliteClient(connStr);
    const prisma = new PrismaClient({ adapter: new PrismaPGlite(client), log: opts?.log });
    const disconnect = prisma.$disconnect.bind(prisma);
    let released = false;
    prisma.$disconnect = async () => {
      try {
        await disconnect();
      } finally {
        if (!released) {
          released = true;
          await releasePgliteClient(dataDir);
        }
      }
    };
    return prisma;
  }

  const adapter = new PrismaPg({ connectionString: connStr });
  return new PrismaClient({ adapter, log: opts?.log });
}

// Lazy singleton - only connects when first accessed
let _prisma: PrismaClient | undefined;
export function getPrisma() {
  if (!_prisma) {
    _prisma = createPrismaClient();
  }
  return _prisma;
}

export { PrismaClient };
export * from './generated/prisma/client';
