export interface BootstrapSpaceRef {
  name: string;
  spaceId: string;
}

export interface SpaceIndexRow {
  spaceId: string;
  name: string;
  ownerDid: string;
  type: string;
  permissionsJson: string;
  status: string;
  registeredAt: string | null;
  updatedAt: string;
  expiresAt: string | null;
}

export type RegistryRead = { found: true; body: string } | { found: false };

export interface SpaceRegistryStore {
  read(key: string): Promise<RegistryRead>;
  createOnly(key: string, body: string): Promise<void>;
  writeIndex(rows: SpaceIndexRow[]): Promise<void>;
}

export function kvSpaceRegistryStore(
  send: (req: { path: string; action: string; body?: string; headers?: Record<string, string> }) => Promise<Response>,
  writeIndex: (rows: SpaceIndexRow[]) => Promise<void>,
): SpaceRegistryStore {
  return {
    async read(key) {
      const response = await send({ path: key, action: KV.GET });
      if (response.ok) return { found: true, body: await response.text() };
      if (response.status === 404) return { found: false };
      throw new Error(`TinyCloud kv ${key} get failed: HTTP ${response.status}`);
    },
    async createOnly(key, body) {
      const response = await send({
        path: key,
        action: KV.PUT,
        body,
        headers: { 'if-none-match': '*' },
      });
      if (!response.ok) {
        throw new Error(`TinyCloud kv ${key} put failed: HTTP ${response.status} ${await response.text()}`);
      }
    },
    writeIndex,
  };
}

export async function registerMissingBootstrapSpaces(
  store: SpaceRegistryStore,
  spaces: readonly BootstrapSpaceRef[],
  ownerDid: string,
  now: string,
): Promise<{ created: number; preserved: number }> {
  const keys = spaces.map(({ spaceId }) => `spaces/${spaceId}`);
  // Read all keys before the first mutation. A failed read leaves the registry untouched.
  const initialRecords = await Promise.all(keys.map((key) => store.read(key)));
  const finalBodies = new Array<string>(spaces.length);
  const missing: Array<{ index: number; key: string; body: string }> = [];
  let preserved = 0;

  for (let index = 0; index < spaces.length; index += 1) {
    const existing = initialRecords[index]!;
    if (existing.found) {
      finalBodies[index] = existing.body;
      preserved += 1;
      continue;
    }
    const { name, spaceId } = spaces[index]!;
    missing.push({
      index,
      key: keys[index]!,
      body: JSON.stringify({
        space_id: spaceId,
        name,
        owner_did: ownerDid,
        type: 'owned',
        permissions: ['*'],
        status: 'active',
        registered_at: now,
        updated_at: now,
      }),
    });
  }

  const createResults = await Promise.all(missing.map(async ({ index, key, body }) => {
    try {
      await store.createOnly(key, body);
      finalBodies[index] = body;
      return { created: true as const };
    } catch (createError) {
      try {
        const raced = await store.read(key);
        if (raced.found) {
          finalBodies[index] = raced.body;
          return { created: false as const, preserved: true as const };
        }
      } catch {
        // Preserve the original create failure as the useful cause of this attempt.
      }
      return { created: false as const, error: createError };
    }
  }));

  const failed = createResults.find((result) => 'error' in result);
  if (failed && 'error' in failed) throw failed.error;

  const rows = spaces.map(({ spaceId }, index) => spaceIndexRow(finalBodies[index]!, spaceId, now));
  await store.writeIndex(rows);
  return {
    created: createResults.filter((result) => result.created).length,
    preserved: preserved + createResults.filter((result) => 'preserved' in result).length,
  };
}

function spaceIndexRow(body: string, fallbackSpaceId: string, now: string): SpaceIndexRow {
  let record: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      record = parsed as Record<string, unknown>;
    }
  } catch {
    // Keep malformed records intact in KV and use the SDK's normal fallbacks for the index.
  }

  const spaceId = stringValue(record.space_id ?? record.spaceId) ?? fallbackSpaceId;
  const name = stringValue(record.name) ?? spaceId.split(':').at(-1) ?? fallbackSpaceId;
  const permissions = Array.isArray(record.permissions) ? record.permissions : [];
  const expiresAt = toIsoDate(record.expires_at ?? record.expiresAt);
  return {
    spaceId,
    name,
    ownerDid: stringValue(record.owner_did ?? record.ownerDid ?? record.owner) ?? '',
    type: stringValue(record.type) ?? 'discovered',
    permissionsJson: JSON.stringify(permissions),
    status: stringValue(record.status) ?? 'active',
    registeredAt: stringValue(record.registered_at ?? record.registeredAt ?? record.updated_at) ?? null,
    updatedAt: stringValue(record.updated_at ?? record.updatedAt) ?? now,
    expiresAt,
  };
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function toIsoDate(value: unknown): string | null {
  if (typeof value !== 'string' && typeof value !== 'number' && !(value instanceof Date)) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}
import { KV } from '@tinycloud/bootstrap';

