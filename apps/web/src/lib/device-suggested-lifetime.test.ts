// TC-2274: a device request may carry a suggested default lifetime below its signed maximum.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { deviceLifetimeOptions, deviceRequestSuggestedSeconds, type DeviceRequestRecord } from './device-authorization';

const day = 86_400;
const record = (fields: Partial<DeviceRequestRecord>): DeviceRequestRecord => ({
  id: 't', userCode: 'ABCD-EFGH', sessionDid: 'did:key:x', publicJwk: {}, relayPublicJwk: {}, permissions: [],
  nodeOrigin: 'https://node.example', shareOrigin: 'https://share.example',
  delegationExpiresAt: '2030-01-01T00:00:00.000Z', transactionExpiresAt: '2029-12-01T00:00:00.000Z', ...fields,
} as DeviceRequestRecord);

describe('deviceRequestSuggestedSeconds', () => {
  test('is the suggestion when there is one, otherwise the maximum', () => {
    expect(deviceRequestSuggestedSeconds(record({ delegationTtlSeconds: 365 * day, suggestedTtlSeconds: 7 * day }))).toBe(7 * day);
    expect(deviceRequestSuggestedSeconds(record({ delegationTtlSeconds: 365 * day }))).toBe(365 * day);
  });
  test('never exceeds the maximum, whatever the server sent', () => {
    expect(deviceRequestSuggestedSeconds(record({ delegationTtlSeconds: 3600, suggestedTtlSeconds: 7 * day }))).toBe(3600);
    expect(deviceRequestSuggestedSeconds(record({ delegationTtlSeconds: 3600, suggestedTtlSeconds: 0 }))).toBe(3600);
  });
});

describe('deviceLifetimeOptions with a suggestion', () => {
  test('a year-long maximum lists the usual steps, the suggestion and the maximum, in order', () => {
    const options = deviceLifetimeOptions(365 * day, 7 * day);
    expect(options.map((option) => option.seconds)).toEqual([day, 7 * day, 30 * day, 365 * day]);
    expect(options.find((option) => option.seconds === 7 * day)?.label).toBe('7 days (suggested)');
    expect(options.at(-1)?.label).toBe('365 days (requested maximum)');
  });
  test('a suggestion between the steps gets its own entry', () => {
    expect(deviceLifetimeOptions(365 * day, 3 * day).map((option) => option.seconds)).toEqual([day, 3 * day, 7 * day, 30 * day, 365 * day]);
  });
  test('a suggestion equal to the maximum is just the maximum', () => {
    expect(deviceLifetimeOptions(7 * day, 7 * day)).toEqual(deviceLifetimeOptions(7 * day));
  });
  test('without a suggestion nothing changes', () => {
    expect(deviceLifetimeOptions(30 * day).map((option) => option.seconds)).toEqual([day, 7 * day, 30 * day]);
  });
});

describe('long lifetimes read plainly (TC-2274)', () => {
  test('two years or more read as years; a year or less stays in days', async () => {
    const { formatDeviceLifetime } = await import('./device-authorization');
    expect(formatDeviceLifetime(365 * day)).toBe('365 days');
    expect(formatDeviceLifetime(729 * day)).toBe('729 days');
    expect(formatDeviceLifetime(730 * day)).toBe('2 years');
    expect(formatDeviceLifetime(2_920_812 * day)).toBe('8002 years');
    expect(deviceLifetimeOptions(5 * 365 * day).at(-1)?.label).toBe('5 years (requested maximum)');
  });

  test('the notice gives the end date and flags more than a year', async () => {
    const { deviceLifetimeNotice } = await import('./device-authorization');
    const now = Date.UTC(2026, 9, 31, 12);
    expect(deviceLifetimeNotice(7 * day, now)).toEqual({ ends: 'Nov 7, 2026, 12:00 PM UTC', long: false });
    expect(deviceLifetimeNotice(365 * day, now).long).toBe(false);
    expect(deviceLifetimeNotice(365 * day + 1, now).long).toBe(true);
  });
});
