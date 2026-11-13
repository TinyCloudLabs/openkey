import { expect, test } from 'bun:test';
import { acceptRequesterHello } from '../src/lib/requester-window';
const opener = {} as Window;
const expected = { source: opener, requestId: 'request', purpose: 'share-create' as const };
const hello = { type: 'openkey:share:hello', protocolVersion: 1, purpose: 'share-create', requestId: 'request', intent: { key: 'value' } };
const event = { source: opener, origin: 'https://actual.example', data: hello };
test('only the expected opener/parent can establish the observed HTTPS origin', () => {
  expect(acceptRequesterHello(event, expected)?.origin).toBe('https://actual.example');
  expect(acceptRequesterHello({ ...event, source: {} as Window }, expected)).toBeNull();
  expect(acceptRequesterHello(event, { ...expected, source: null })).toBeNull();
  expect(acceptRequesterHello({ ...event, origin: 'http://actual.example' }, expected)).toBeNull();
  expect(acceptRequesterHello({ ...event, origin: 'null' }, expected)).toBeNull();
});
test('request, purpose, protocol and URL/body claims cannot override event.origin', () => {
  for (const data of [{ ...hello, requestId: 'other' }, { ...hello, purpose: 'tinycloud-signin' },
    { ...hello, protocolVersion: 2 }, { ...hello, origin: 'https://claimed.example' },
    { ...hello, intent: { origin: 'https://claimed.example' } }]) {
    expect(acceptRequesterHello({ ...event, data }, expected)).toBeNull();
  }
  expect(acceptRequesterHello(event, { ...expected, originHint: 'https://claimed.example' })).toBeNull();
  expect(acceptRequesterHello(event, { ...expected, purpose: 'tinycloud-signin' })).toBeNull();
});
