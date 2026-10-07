import type { ISessionStorage, PersistedSessionData } from '@tinycloud/web-sdk';
import type { OpenKeyCapacitorPlugin } from './plugin';

/** TinyCloud session storage backed only by the native secure store. */
export class NativeSessionStorage implements ISessionStorage {
  private readonly present = new Set<string>();
  private active?: string;

  constructor(private readonly plugin: OpenKeyCapacitorPlugin, private readonly namespace: string) {}

  private key(address: string): string {
    return `${this.namespace}:tinycloud:${address.toLowerCase()}`;
  }

  async save(address: string, session: PersistedSessionData): Promise<void> {
    await this.plugin.secureStoreSet({ key: this.key(address), value: JSON.stringify(session) });
    this.present.add(address.toLowerCase());
    this.active = address;
  }

  async load(address: string): Promise<PersistedSessionData | null> {
    const { value } = await this.plugin.secureStoreGet({ key: this.key(address) });
    if (value === null) {
      this.present.delete(address.toLowerCase());
      return null;
    }
    const session = JSON.parse(value) as PersistedSessionData;
    this.present.add(address.toLowerCase());
    this.active = address;
    return session;
  }

  async clear(address: string): Promise<void> {
    await this.plugin.secureStoreRemove({ key: this.key(address) });
    this.present.delete(address.toLowerCase());
    if (this.active?.toLowerCase() === address.toLowerCase()) this.active = undefined;
  }

  exists(address: string): boolean { return this.present.has(address.toLowerCase()); }
  isAvailable(): boolean { return true; }
  activeAddress(): string | undefined { return this.active; }
}
