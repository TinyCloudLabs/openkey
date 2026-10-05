// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import type { EthereumKey } from './api';
import { autoSelectKey } from './delegate-key-selection';

const key = (id: string, address: string): EthereumKey => ({
  id, address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', createdAt: '',
});
const a = key('a', '0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa');
const b = key('b', '0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb');

describe('autoSelectKey (TC-659)', () => {
  test('selects the only key when the request names no wallet', () => {
    expect(autoSelectKey([a], null)).toBe(a);
  });
  test('shows the picker for several keys and no requested wallet', () => {
    expect(autoSelectKey([a, b], null)).toBeNull();
    expect(autoSelectKey([], null)).toBeNull();
  });
  test('selects the requested wallet case-insensitively', () => {
    expect(autoSelectKey([a, b], b.address.toLowerCase())).toBe(b);
  });
  test('never selects a single key that is not the requested wallet', () => {
    expect(autoSelectKey([a], b.address.toLowerCase())).toBeNull();
  });
});
