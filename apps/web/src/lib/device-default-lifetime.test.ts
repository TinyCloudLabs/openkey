// @ts-expect-error bun:test is supplied by Bun, not the browser type environment.
import { expect, test } from 'bun:test';
import { deviceRequestDefaultSeconds, type DeviceRequestRecord } from './device-authorization';

function record(max: number, suggested?: number): DeviceRequestRecord {
  return {
    id: 'device-fixture', userCode: 'ABCDEFGH', sessionDid: 'did:key:fixture',
    publicJwk: {}, relayPublicJwk: {}, permissions: [],
    nodeOrigin: 'https://node.example.test', shareOrigin: 'https://share.example.test',
    delegationExpiresAt: '2030-01-08T00:00:00.000Z', transactionExpiresAt: '2030-01-01T00:00:00.000Z',
    delegationTtlSeconds: max,
    ...(suggested !== undefined ? { suggestedTtlSeconds: suggested } : {}),
  };
}

test('a seven-day request starts at the one-hour review option rather than its maximum', () => {
  expect(deviceRequestDefaultSeconds(record(604_800))).toBe(3_600);
});

test('a maximum shorter than the review presets is never lengthened', () => {
  expect(deviceRequestDefaultSeconds(record(600))).toBe(600);
});

test('a smaller requester suggestion is never lengthened to a preset', () => {
  expect(deviceRequestDefaultSeconds(record(604_800, 1_800))).toBe(1_800);
});
