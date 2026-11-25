// @ts-expect-error bun:test is a runtime-only module
import { afterEach, describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

const HOST = 'https://openkey.test';

type Harness = {
  client: OpenKey;
  posted: () => any;
  opened: string[];
  frames: string[];
  send: (data: any) => void;
};

const previous = { window: globalThis.window, document: globalThis.document };
afterEach(() => {
  (globalThis as any).window = previous.window;
  (globalThis as any).document = previous.document;
});

function harness(options: { blockPopup?: boolean } = {}): Harness {
  const listeners = new Set<(event: any) => void>();
  let posted: any;
  const opened: string[] = [];
  const frames: string[] = [];
  const source = { closed: false, close() {}, postMessage(value: any) { posted = value; } };
  const element = (): any => ({
    style: {}, contentWindow: source, children: [],
    set src(value: string) { frames.push(value); },
    setAttribute() {}, addEventListener() {}, remove() {},
    appendChild(child: any) { this.children.push(child); return child; },
    attachShadow: element,
  });
  (globalThis as any).document = { createElement: element, body: element() };
  (globalThis as any).window = {
    location: { origin: 'https://app.test', hostname: 'app.test' },
    navigator: { userAgent: 'test' },
    screenX: 0, screenY: 0, outerWidth: 1024, outerHeight: 768,
    innerHeight: 800, matchMedia: () => ({ matches: false }),
    open: (url: string) => { opened.push(url); return options.blockPopup ? null : source; },
    addEventListener(type: string, callback: any) { if (type === 'message') listeners.add(callback); },
    removeEventListener(type: string, callback: any) { if (type === 'message') listeners.delete(callback); },
    dispatchEvent() {},
  };
  return {
    client: new OpenKey({ host: HOST }),
    posted: () => posted,
    opened,
    frames,
    send: (data: any) => { for (const callback of [...listeners]) callback({ origin: HOST, source, data }); },
  };
}

describe('setupAccount', () => {
  test('opens the account setup page, takes only the answer to its own request and resolves with the outcome only', async () => {
    const { client, posted, opened, send } = harness();
    const result = client.setupAccount({ keyId: 'key_1' });
    try {
      expect(opened[0]).toStartWith(`${HOST}/widget/account-setup?origin=`);
      send({ type: 'openkey:ready' });
      const request = posted();
      expect(request).toMatchObject({ type: 'openkey:account-setup:request', protocolVersion: 1, keyId: 'key_1' });
      expect(typeof request.requestId).toBe('string');

      // Another request's answer, or another version, is not this one's.
      send({ type: 'openkey:account-setup:response', requestId: 'other', protocolVersion: 1, success: true, outcome: 'present' });
      send({ type: 'openkey:account-setup:response', requestId: request.requestId, protocolVersion: 2, success: true, outcome: 'present' });
      send({
        type: 'openkey:account-setup:response', requestId: request.requestId, protocolVersion: 1, success: true,
        outcome: 'published', address: '0xabc', nodeUrl: 'https://node.example',
      });
      expect(await result).toEqual({ outcome: 'published' });
    } finally {
      (client as any).cancelActiveFlows();
    }
  });

  test('an unavailable setup rejects with its code and where the owner finishes setup', async () => {
    const { client, posted, send } = harness();
    const result = client.setupAccount();
    try {
      send({ type: 'openkey:ready' });
      const { requestId } = posted();
      send({
        type: 'openkey:account-setup:response', requestId, protocolVersion: 1, success: false,
        error: { code: 'ACCOUNT_SETUP_UNAVAILABLE', message: 'Finish setup in TinyCloud One.', setupUrl: 'https://tinycloud.one/?finish-setup=registry' },
      });
      await expect(result).rejects.toMatchObject({
        code: 'ACCOUNT_SETUP_UNAVAILABLE', setupUrl: 'https://tinycloud.one/?finish-setup=registry',
      });
    } finally {
      (client as any).cancelActiveFlows();
    }
  });

  test('a blocked popup opens the embedded hand-off card', async () => {
    const { client, posted, frames, send } = harness({ blockPopup: true });
    const result = client.setupAccount();
    try {
      // The fallback opens once the blocked popup's rejection has settled.
      for (let turn = 0; turn < 20 && frames.length === 0; turn += 1) await Promise.resolve();
      expect(frames[0]).toStartWith(`${HOST}/widget/embed/account-setup?origin=`);
      send({ type: 'openkey:ready' });
      const { requestId } = posted();
      send({ type: 'openkey:account-setup:response', requestId, protocolVersion: 1, success: true, outcome: 'present' });
      expect(await result).toEqual({ outcome: 'present' });
    } finally {
      (client as any).cancelActiveFlows();
    }
  });
});

describe('a sign request refused after the owner set the account up', () => {
  test('reaches the app as ACCOUNT_SETUP_COMPLETED', () => {
    // handleWidgetError is the private step every widget failure passes through before the app's promise rejects.
    const openkey = Object.create(OpenKey.prototype) as unknown as { handleWidgetError(error: unknown): unknown };
    expect(openkey.handleWidgetError({ code: 'UNKNOWN', message: 'ACCOUNT_SETUP_COMPLETED' }))
      .toEqual({ code: 'ACCOUNT_SETUP_COMPLETED', message: 'ACCOUNT_SETUP_COMPLETED' });
  });
});
