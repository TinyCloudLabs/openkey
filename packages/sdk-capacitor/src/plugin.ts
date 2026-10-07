import { registerPlugin } from '@capacitor/core';
import { OpenKeyNativeError } from '@openkey/core';

export interface OpenKeyCapacitorPlugin {
  openAuthSession(options: { url: string; callbackScheme: string; callbackUrl?: string; expectedState?: string; ephemeral?: boolean }): Promise<{ url: string }>;
  secureStoreGet(options: { key: string }): Promise<{ value: string | null }>;
  secureStoreSet(options: { key: string; value: string }): Promise<void>;
  secureStoreRemove(options: { key: string }): Promise<void>;
}

const unavailable = async (): Promise<never> => {
  throw new OpenKeyNativeError('UNAVAILABLE', 'OpenKey native sign-in is unavailable on web');
};

export const OpenKeyCapacitor = registerPlugin<OpenKeyCapacitorPlugin>('OpenKeyCapacitor', {
  web: () => Promise.resolve({
    openAuthSession: unavailable,
    secureStoreGet: unavailable,
    secureStoreSet: unavailable,
    secureStoreRemove: unavailable,
  }),
});

export const secureStore = {
  async get(key: string): Promise<string | null> {
    return (await OpenKeyCapacitor.secureStoreGet({ key })).value;
  },
  async set(key: string, value: string): Promise<void> {
    await OpenKeyCapacitor.secureStoreSet({ key, value });
  },
  async remove(key: string): Promise<void> {
    await OpenKeyCapacitor.secureStoreRemove({ key });
  },
};
