import { OpenKeyNativeError } from '@openkey/core';
import type { ISessionStorage, PersistedSessionData } from '@tinycloud/web-sdk';
import type { OpenKeyCapacitorPlugin } from './plugin';

/** TinyCloud session storage backed only by the native secure store. */
export class NativeSessionStorage implements ISessionStorage {
  private readonly present = new Set<string>();
  private active?: string;

  constructor(
    private readonly plugin: OpenKeyCapacitorPlugin,
    private readonly namespace: string,
    private readonly serializeWrite?: (session: PersistedSessionData, write: () => Promise<void>) => Promise<void>,
  ) {}

  // One active TinyCloud session per OpenKey client. A fixed key lets signOut
  // remove an Android-backup record even when the old Keystore key is gone.
  private get key(): string { return `${this.namespace}:tinycloud:session`; }

  async save(address: string, session: PersistedSessionData): Promise<void> {
    try {
      const write = () => this.plugin.secureStoreSet({ key: this.key, value: JSON.stringify(session) });
      if (this.serializeWrite) await this.serializeWrite(session, write);
      else await write();
    }
    catch (error) {
      if (error instanceof OpenKeyNativeError && error.code === 'NOT_SIGNED_IN') throw error;
      throw new OpenKeyNativeError('SERVER', 'TinyCloud secure store write failed');
    }
    this.present.clear();
    this.present.add(address.toLowerCase());
    this.active = address;
  }

  async load(address: string): Promise<PersistedSessionData | null> {
    let value: string | null;
    try { ({ value } = await this.plugin.secureStoreGet({ key: this.key })); }
    catch { throw new OpenKeyNativeError('SERVER', 'TinyCloud secure store read failed'); }
    if (value === null) {
      this.present.delete(address.toLowerCase());
      return null;
    }
    let session: PersistedSessionData;
    try { session = JSON.parse(value) as PersistedSessionData; }
    catch { throw new OpenKeyNativeError('SERVER', 'Stored TinyCloud session is invalid'); }
    if (session.address?.toLowerCase() !== address.toLowerCase()) return null;
    this.present.add(address.toLowerCase());
    this.active = address;
    return session;
  }

  async clear(address: string): Promise<void> {
    const session = await this.load(address);
    if (session) await this.clearAll();
  }

  /** Remove the fixed secure-store key without decrypting its contents. */
  async clearAll(): Promise<void> {
    try { await this.plugin.secureStoreRemove({ key: this.key }); }
    catch { throw new OpenKeyNativeError('SERVER', 'TinyCloud secure store wipe failed'); }
    this.present.clear();
    this.active = undefined;
  }

  exists(address: string): boolean { return this.present.has(address.toLowerCase()); }
  isAvailable(): boolean { return true; }
  activeAddress(): string | undefined { return this.active; }
}
