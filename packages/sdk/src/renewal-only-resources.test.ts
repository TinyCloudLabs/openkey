// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { expect, test } from 'bun:test';
import { OpenKey, type TinyCloudAuthorizationRequestV1 } from './index';

const WIDGET_ORIGIN = 'https://openkey.test';
const NETWORK = 'urn:tinycloud:encryption:did:pkh:eip155:1:0xABC:default';
const KEY = `${NETWORK}/secrets/api_key`;
const LONG_KEY_PREFIX = 'urn:tinycloud:encryption:did:key:';
const LONG_KEY_SUFFIX = ':default/secrets/long_key';
const LONG_KEY = LONG_KEY_PREFIX + 'a'.repeat(512 - LONG_KEY_PREFIX.length - LONG_KEY_SUFFIX.length) + LONG_KEY_SUFFIX;
const REQUEST = {
  protocolVersion: 1,
  siwe: 'suggested SIWE',
  renewal: { version: 1, leaseLifetimeSeconds: 3600, purpose: 'standing' },
  expiryChangeable: true,
} satisfies TinyCloudAuthorizationRequestV1;

function popupHarness(keyType: 'MANAGED' | 'EXTERNAL') {
  const globals = globalThis as unknown as { window: unknown };
  const oldWindow = globals.window;
  const addresses: string[] = [];
  const posted: Array<{ message: Record<string, unknown>; origin: string }> = [];
  let keyLookups = 0;
  let listener: ((event: { data: unknown; origin: string; source: unknown }) => void) | undefined;
  const popup = {
    closed: false,
    location: { href: '' },
    close() { this.closed = true; },
    postMessage(message: Record<string, unknown>, origin: string) { posted.push({ message, origin }); },
  };
  globals.window = {
    location: { origin: 'https://app.test' },
    open(url: string) { addresses.push(url); popup.location.href = url; return popup; },
    addEventListener(type: string, handle: typeof listener) { if (type === 'message') listener = handle; },
    removeEventListener(type: string) { if (type === 'message') listener = undefined; },
  };
  const openkey = Object.create(OpenKey.prototype) as OpenKey;
  Object.assign(openkey, {
    host: WIDGET_ORIGIN,
    activeFlowCancellations: new Set(),
    lastAuth: { address: '0xABC', keyId: 'key-id', keyType },
    fetchKnownKeysIfNeeded: async () => { keyLookups++; return []; },
  });
  return {
    openkey, addresses, posted,
    get keyLookups() { return keyLookups; },
    send(data: unknown) { listener?.({ data, origin: WIDGET_ORIGIN, source: popup }); },
    restore() {
      Reflect.apply(Reflect.get(openkey, 'cancelActiveFlows'), openkey, []);
      globals.window = oldWindow;
    },
  };
}

test('managed authorization posts the exact resource strings alongside renewal and returns the signed SIWE', async () => {
  const widget = popupHarness('MANAGED');
  try {
    const resources = [KEY, LONG_KEY, ...Array.from({ length: 62 }, (_, i) => `${NETWORK}/secrets/scoped/app/key_${i}`)];
    const result = widget.openkey.authorizeTinyCloud({ ...REQUEST, renewalOnlyResources: resources }, { mode: 'popup' });
    void result.catch(() => {});
    await Promise.resolve();
    widget.send({ type: 'openkey:ready' });

    const post = widget.posted[0]!;
    expect(widget.posted).toHaveLength(1);
    expect(post.origin).toBe(WIDGET_ORIGIN);
    expect(post.message).toMatchObject({
      type: 'openkey:sign:request',
      protocolVersion: 1,
      message: REQUEST.siwe,
      expiryChangeable: true,
      renewal: REQUEST.renewal,
      renewalOnlyResources: resources,
    });
    widget.send({
      type: 'openkey:sign:response', success: true, requestId: post.message.requestId, protocolVersion: 1,
      signedMessage: 'narrowed SIWE', selectedActionKeys: [], permissions: [], signature: 'sig', address: '0xABC',
      renewalChoice: 'finite',
    });
    const signed = await result;
    expect(signed.signedMessage).toBe('narrowed SIWE');
    expect(signed).not.toHaveProperty('renewalOnlyResources');
  } finally {
    widget.restore();
  }
});

test('external-wallet authorization posts the same renewal-only field in its widget preview request', async () => {
  const widget = popupHarness('EXTERNAL');
  try {
    const result = widget.openkey.authorizeTinyCloud({ ...REQUEST, renewalOnlyResources: [KEY] }, { mode: 'popup' });
    void result.catch(() => {});
    await Promise.resolve();
    widget.send({ type: 'openkey:ready' });
    const post = widget.posted[0]!;
    expect(post.message).toMatchObject({
      type: 'openkey:sign:request', protocolVersion: 1, externalSign: true,
      expiryChangeable: true, renewal: REQUEST.renewal, renewalOnlyResources: [KEY],
    });
    widget.send({ type: 'openkey:close', requestId: post.message.requestId, protocolVersion: 1 });
    await expect(result).rejects.toMatchObject({ code: 'USER_CANCELLED' });
  } finally {
    widget.restore();
  }
});

test('invalid renewal-only resources fail before popup reservation, key lookup or widget messaging', async () => {
  const widget = popupHarness('MANAGED');
  try {
    const invalidResources: unknown[] = [
      null, KEY, [null], [''], Array(1), [KEY, KEY], [LONG_KEY + 'a'],
      Array.from({ length: 65 }, (_, i) => `${NETWORK}/secrets/key_${i}`),
      ['default'], [NETWORK], [`${NETWORK}/secrets`], [`${NETWORK}/secrets/`], [`${KEY}/`],
      ['urn:tinycloud:kv:did:pkh:eip155:1:0xABC:default/vault/secrets'], [`${KEY}?query`],
    ];
    for (const renewalOnlyResources of invalidResources) {
      await expect(widget.openkey.authorizeTinyCloud({
        ...REQUEST, renewalOnlyResources: renewalOnlyResources as string[],
      }, { mode: 'popup' })).rejects.toBeInstanceOf(TypeError);
    }
    for (const fields of [
      { renewal: undefined }, { expiryChangeable: undefined }, { expiryChangeable: false },
      { renewal: { ...REQUEST.renewal, leaseLifetimeSeconds: 0 } },
    ]) {
      await expect(widget.openkey.authorizeTinyCloud({
        ...REQUEST, ...fields, renewalOnlyResources: [KEY],
      }, { mode: 'popup' })).rejects.toBeInstanceOf(TypeError);
    }
    expect(widget.addresses).toEqual([]);
    expect(widget.keyLookups).toBe(0);
    expect(widget.posted).toEqual([]);
  } finally {
    widget.restore();
  }
});
