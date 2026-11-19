import { randomUUID } from 'node:crypto';
import { open, readFile, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import type { KeyResealCounts, KeyResealKind } from './key-reseal';

export interface KeyResealCursor {
  version: 1;
  writeKid: number;
  kind: KeyResealKind;
  afterId: string | null;
  completed: boolean;
  counts: KeyResealCounts;
}

export interface KeyResealCursorStore {
  load(): Promise<KeyResealCursor | null>;
  save(cursor: KeyResealCursor): Promise<void>;
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function validateCursor(value: unknown): asserts value is KeyResealCursor {
  if (typeof value !== 'object' || value === null) throw new Error('Invalid maintenance checkpoint');
  const cursor = value as Partial<KeyResealCursor>;
  if (cursor.version !== 1 || !isCount(cursor.writeKid) || cursor.writeKid > 0xffffffff
    || (cursor.kind !== 'ethereum' && cursor.kind !== 'nostr')
    || (cursor.afterId !== null && typeof cursor.afterId !== 'string')
    || typeof cursor.completed !== 'boolean'
    || typeof cursor.counts !== 'object' || cursor.counts === null
    || !isCount(cursor.counts.scanned) || !isCount(cursor.counts.alreadyCurrent)
    || !isCount(cursor.counts.resealed) || !isCount(cursor.counts.raced)
    || !isCount(cursor.counts.failed) || !isCount(cursor.counts.remainingOldGeneration)) {
    throw new Error('Invalid maintenance checkpoint');
  }
}

/** Explicit absolute path on an operator-supplied durable volume; one owner. */
export class FileKeyResealCursorStore implements KeyResealCursorStore {
  constructor(private readonly path: string) {
    if (!isAbsolute(path)) throw new Error('Maintenance checkpoint requires an absolute path');
  }

  async load(): Promise<KeyResealCursor | null> {
    try {
      const cursor: unknown = JSON.parse(await readFile(this.path, 'utf8'));
      validateCursor(cursor);
      return cursor;
    } catch (error) {
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') return null;
      throw new Error('Maintenance checkpoint read failed');
    }
  }

  async save(cursor: KeyResealCursor): Promise<void> {
    validateCursor(cursor);
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    try {
      // A same-directory rename is atomic. Flush both the file contents and the
      // directory entry before reporting a durable checkpoint to the caller.
      const file = await open(temporary, 'wx', 0o600);
      try {
        await file.writeFile(JSON.stringify(cursor), 'utf8');
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(temporary, this.path);
      const directory = await open(dirname(this.path), 'r');
      try { await directory.sync(); } finally { await directory.close(); }
    } catch {
      throw new Error('Maintenance checkpoint write failed');
    } finally {
      await unlink(temporary).catch(() => {});
    }
  }
}
