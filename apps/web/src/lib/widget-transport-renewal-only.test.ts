// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { expect, it, spyOn } from 'bun:test';
import { createWidgetTransport, type WidgetRequest } from './widget-transport';

const origin = 'https://caller.example';
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;
const key = `${network}/secrets/api_key`;
const listWarning = '[widget-transport] dropping malformed renewal-only resources';

function deliver(fields: Record<string, unknown>) {
  const opener = { postMessage() {} };
  const browser = Object.assign(new EventTarget(), { opener });
  const globals = globalThis as unknown as { window: unknown };
  const savedWindow = globals.window;
  const warning = spyOn(console, 'warn').mockImplementation(() => {});
  globals.window = browser;
  const received: WidgetRequest[] = [];
  try {
    const transport = createWidgetTransport({
      container: 'popup', origin, onRequest: (request) => received.push(request), onClose() {},
    });
    browser.dispatchEvent(Object.assign(new Event('message'), {
      origin, source: opener,
      data: {
        type: 'openkey:sign:request', requestId: 'renewal-only', protocolVersion: 1, message: 'siwe',
        expiryChangeable: true, renewal: { version: 1, leaseLifetimeSeconds: 600 },
        renewalOnlyResources: [key],
        ...fields,
      },
    }));
    transport.destroy();
    expect(received).toHaveLength(1);
    expect(received[0]?.data.message).toBe('siwe');
    return { data: received[0]?.data, warnings: warning.mock.calls.flat() };
  } finally {
    globals.window = savedWindow;
    warning.mockRestore();
  }
}

it('forwards a valid exact key', () => {
  const { data, warnings } = deliver({});
  expect(data?.renewalOnlyResources).toEqual([key]);
  expect(warnings).toEqual([]);
});

const invalidLists: Array<[string, unknown[]]> = [
  ['65 entries', Array.from({ length: 65 }, (_, i) => `${network}/secrets/key_${i}`)],
  ['duplicate entries', [key, key]],
  ['an entry over 512 characters', [key, `urn:tinycloud:encryption:did:pkh:eip155:1:${'a'.repeat(512)}:default/secrets/api_key`]],
  ['an empty string', [key, '']],
  ['a non-string entry', [key, 42]],
  ['a prefix URN', [key, `${network}/secrets/`]],
  ['a network URN', [key, network]],
  ['a KV vault resource', [key, `tinycloud:pkh:eip155:1:${address}:secrets/kv/vault/secrets`]],
  ['the bare secrets path on the default network', [key, `${network}/secrets`]],
  ['a trailing slash on an exact key', [key, `${key}/`]],
  ['a double slash', [key, `${network}/secrets//other_key`]],
  ['a dot-dot segment', [key, `${network}/secrets/../other_key`]],
  ['an encoded dot', [key, `${network}/secrets/%2e`]],
  ['whitespace', [key, `${network}/secrets/other key`]],
  ['an uppercase scheme', [key, key.replace(/^urn:/, 'URN:')]],
];

for (const [label, resources] of invalidLists) {
  it(`drops the whole list and warns when it contains ${label}`, () => {
    const { data, warnings } = deliver({ renewalOnlyResources: resources });
    expect(data?.renewalOnlyResources).toBeUndefined();
    expect(warnings).toContain(listWarning);
  });
}

it('ignores the list without renewal', () => {
  const { data } = deliver({ renewal: undefined });
  expect(data?.renewalOnlyResources).toBeUndefined();
});

it('ignores the list unless expiryChangeable is literally true', () => {
  for (const expiryChangeable of [undefined, false, 'true', 1]) {
    const { data } = deliver({ expiryChangeable });
    expect(data?.renewalOnlyResources).toBeUndefined();
  }
});
