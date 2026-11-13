// @ts-expect-error bun:test is runtime-only in this package's tsconfig
import { expect, test } from 'bun:test';
import { OpenKey } from './index';

test('ordinary authorization requests/results keep their own-property shapes', async () => {
  const sdk = new OpenKey({ host: 'https://openkey.test', appName: 'fixture', passkeysSupported: false });
  (sdk as any).lastAuth = { address: '0xowner', keyId: 'key', keyType: 'MANAGED' };
  (sdk as any).openFlow = async (_action: string, message: any) => {
    expect(Object.hasOwn(message, 'signInContinuation')).toBe(false);
    return { address: '0xowner', signature: '0xsig', signedMessage: 'siwe',
      selectedActionKeys: [], permissions: [], keyId: 'extra-key', keyType: 'MANAGED' };
  };
  const result = await (sdk as any).authorizeTinyCloudFlow({ protocolVersion: 1, siwe: 'siwe' }, {}, null);
  expect(Object.keys(result).sort()).toEqual(['protocolVersion', 'address', 'signature',
    'signedMessage', 'selectedActionKeys', 'permissions'].sort());
});

test('ordinary external authorization preserves its original two-argument call', async () => {
  const sdk = new OpenKey({ host: 'https://openkey.test', appName: 'fixture', passkeysSupported: false });
  (sdk as any).lastAuth = { address: '0xowner', keyId: 'key', keyType: 'EXTERNAL' };
  (sdk as any).authorizeTinyCloudExternal = async (...args: unknown[]) => {
    expect(args).toHaveLength(2);
    return { address: '0xowner' };
  };
  await (sdk as any).authorizeTinyCloudFlow({ protocolVersion: 1, siwe: 'siwe' }, {}, { window: {} });
});
