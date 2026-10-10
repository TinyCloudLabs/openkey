import { afterAll, beforeAll, expect, test } from 'bun:test';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { Window } from 'happy-dom';
import { privateKeyToAccount } from 'viem/accounts';
import { initialized as webWasmReady, tinycloud as webWasm } from '@tinycloud/web-sdk-wasm';
import type { TinyCloudDelegation } from '@openkey/core';
import { verifyTinyCloudDelegation } from '../src/verify';

// verifyTinyCloudDelegation without injected bindings loads
// `new (await import('@tinycloud/web-sdk')).BrowserWasmBindings()`, the path apps take.
// web-sdk touches DOM classes at module load, so this test installs happy-dom globals.

interface Signer {
  label: string;
  prepareSession(config: unknown): { siwe: string };
  completeSessionSetup(config: unknown): { delegationHeader: { Authorization: string }; delegationCid: string };
  ready?: Promise<unknown>;
}

const require = createRequire(import.meta.url);
const webSdkVersion: string = require('@tinycloud/web-sdk/package.json').version;

function nodeWasmSigner(label: string, from: string): Signer {
  const req = createRequire(from);
  const wasm = req('@tinycloud/node-sdk-wasm');
  const { version } = req('@tinycloud/node-sdk-wasm/package.json');
  return { label: `${label} node-sdk-wasm ${version}`, prepareSession: wasm.prepareSession, completeSessionSetup: wasm.completeSessionSetup };
}

const signers: Signer[] = [
  // The OpenKey API signs native delegations with this build.
  nodeWasmSigner('apps/api', join(import.meta.dir, '../../../apps/api/package.json')),
  // The build web-sdk's own node-sdk ships.
  nodeWasmSigner('web-sdk/node-sdk', createRequire(require.resolve('@tinycloud/web-sdk')).resolve('@tinycloud/node-sdk')),
  {
    label: `web-sdk-wasm ${require('@tinycloud/web-sdk-wasm/package.json').version}`,
    prepareSession: webWasm.prepareSession,
    completeSessionSetup: webWasm.completeSessionSetup,
    ready: webWasmReady,
  },
];

const domGlobals = ['window', 'document', 'HTMLElement', 'customElements', 'navigator', 'localStorage', 'sessionStorage', 'Element', 'Node', 'Event', 'CustomEvent', 'EventTarget', 'MutationObserver', 'getComputedStyle', 'location', 'DOMParser'] as const;
const saved = new Map<string, PropertyDescriptor | undefined>();
const realFetch = globalThis.fetch;
let happy: Window;

beforeAll(() => {
  happy = new Window({ url: 'http://127.0.0.1/' });
  for (const key of domGlobals) {
    if (key in globalThis && key !== 'window' && key !== 'document') continue;
    saved.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value: Reflect.get(happy, key) });
  }
  // Verification is offline; fail rather than reach the network.
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    throw new Error(`unexpected fetch: ${String(input instanceof Request ? input.url : input)}`);
  }) as unknown as typeof fetch;
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  for (const [key, descriptor] of saved) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
  await happy.happyDOM.close();
});

test(`production path verifies delegations with @tinycloud/web-sdk ${webSdkVersion} BrowserWasmBindings`, async () => {
  let total = 0;
  let padded = 0;
  for (const signer of signers) {
    await signer.ready;
    for (let i = 0; i < 12; i++) {
      const account = privateKeyToAccount(`0x${(0xabc00 + i + 1).toString(16).padStart(64, '0')}`);
      const address = account.address;
      const prepared = signer.prepareSession({
        abilities: { kv: { [`app/threads/${'x'.repeat(i)}`]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } },
        address, chainId: 1, domain: 'openkey.so',
        issuedAt: new Date().toISOString(),
        expirationTime: new Date(Date.now() + 3_600_000).toISOString(),
        spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
      });
      const signature = await account.signMessage({ message: prepared.siwe });
      const signed = signer.completeSessionSetup({ ...prepared, signature });
      const delegation = {
        siwe: prepared.siwe, signature,
        delegationHeader: signed.delegationHeader,
        delegationCid: signed.delegationCid,
      } as TinyCloudDelegation;
      if (signed.delegationHeader.Authorization.includes('=')) padded++;

      await verifyTinyCloudDelegation(delegation);
      await expect(verifyTinyCloudDelegation({ ...delegation, delegationCid: 'wrong' }), signer.label).rejects.toMatchObject({ code: 'SERVER' });
      const flipped = signature.replace(/.$/, c => (c === '0' ? '1' : '0'));
      await expect(verifyTinyCloudDelegation({ ...delegation, signature: flipped }), signer.label).rejects.toMatchObject({ code: 'SERVER' });
      total++;
    }
  }
  expect(total).toBe(signers.length * 12);
  expect(padded).toBeGreaterThan(0);
});
