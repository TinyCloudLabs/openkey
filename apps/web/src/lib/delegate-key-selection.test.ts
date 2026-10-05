// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import type { EthereumKey } from './api';
import { autoSelectKey, keyPickerLayout, primaryKey } from './delegate-key-selection';

const key = (id: string, address: string, extra: Partial<EthereumKey> = {}): EthereumKey => ({
  id, address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', createdAt: '', ...extra,
});
const a = key('a', '0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa');
const b = key('b', '0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb');
const primary = key('p', '0xCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCcCc', { isPrimary: true });
const external = key('e', '0xDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDdDd', { keyType: 'EXTERNAL', isPrimary: false });

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

describe('primary key preselection (TC-703)', () => {
  test('preselects the primary key when the request names no wallet', () => {
    expect(autoSelectKey([a, primary, b, external], null)).toBe(primary);
  });
  test('a named wallet still wins over the primary key', () => {
    expect(autoSelectKey([a, primary, b], b.address.toLowerCase())).toBe(b);
  });
  test('a named wallet the user lacks never falls back to the primary key', () => {
    expect(autoSelectKey([primary, b], a.address.toLowerCase())).toBeNull();
  });
  test('without a primary key, several keys still show the plain picker', () => {
    expect(primaryKey([a, b, external])).toBeNull();
    expect(autoSelectKey([a, b, external], null)).toBeNull();
  });
  test('only isPrimary === true marks the primary key', () => {
    expect(primaryKey([a, external])).toBeNull();
    expect(primaryKey([external, primary])).toBe(primary);
  });
});

describe('keyPickerLayout (TC-703)', () => {
  test('with no wallet named, offers the primary key and holds the others back', () => {
    const layout = keyPickerLayout([a, primary, b, external], null);
    expect(layout.kind).toBe('primary');
    if (layout.kind !== 'primary') throw new Error('expected the primary layout');
    expect(layout.primary).toBe(primary);
    // Never hidden for good: every other key is still reachable.
    expect(layout.others).toEqual([a, b, external]);
  });
  test('a named wallet keeps the plain list, primary included', () => {
    expect(keyPickerLayout([a, primary, b], b.address.toLowerCase())).toEqual({ kind: 'list', keys: [a, primary, b] });
  });
  test('without a primary key, every key is listed', () => {
    expect(keyPickerLayout([a, b, external], null)).toEqual({ kind: 'list', keys: [a, b, external] });
  });
});
