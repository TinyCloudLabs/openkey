// @ts-expect-error bun:test is runtime-only in the web tsconfig
import { expect, test } from 'bun:test';
import { createWidgetTransport } from './widget-transport';

test('continuation messages retain exact origin/source/token/request checks', () => {
  const previous = (globalThis as any).window;
  const opener = { postMessage() {} };
  let receive!: (event: any) => void;
  const invalid: string[] = [];
  (globalThis as any).window = { opener,
    addEventListener: (_type: string, listener: any) => { receive = listener; }, removeEventListener() {} };
  try {
    const transport = createWidgetTransport({ origin: 'https://app.test', container: 'popup',
      continuation: () => ({ requestId: 'request', token: 'token' }),
      onRequest: () => { throw new Error('A continuation is not an ordinary sign request'); },
      onClose() {}, onInvalid: reason => invalid.push(reason),
    });
    const data = { type: 'openkey:signin:finalize', protocolVersion: 1, requestId: 'request', token: 'token' };
    receive({ origin: 'https://other.test', source: opener, data });
    receive({ origin: 'https://app.test', source: {}, data });
    receive({ origin: 'https://app.test', source: opener, data: { ...data, token: 'wrong' } });
    expect(invalid).toEqual(['wrong-origin', 'wrong-source', 'unknown-message-type']);
    receive({ origin: 'https://app.test', source: opener, data });
    receive({ origin: 'https://app.test', source: opener, data: { ...data, type: 'openkey:signin:cancel' } });
    expect(invalid).toHaveLength(3);
    transport.destroy();
  } finally { (globalThis as any).window = previous; }
});
