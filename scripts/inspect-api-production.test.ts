import { describe, expect, test } from 'bun:test';
import { ETHEREUM_KEYS_ROW_THRESHOLD, ethereumKeysRowReport } from './inspect-api-production';

describe('ethereumKeysRowReport', () => {
  test('the stop line is one million rows', () => {
    expect(ETHEREUM_KEYS_ROW_THRESHOLD).toBe(1_000_000);
  });

  test('reports the count and a false flag at and below the stop line', () => {
    expect(ethereumKeysRowReport(0)).toEqual({ ethereum_keys_rows: 0, ethereum_keys_rows_over_threshold: false });
    expect(ethereumKeysRowReport(1_000_000)).toEqual({ ethereum_keys_rows: 1_000_000, ethereum_keys_rows_over_threshold: false });
  });

  test('flags a table over the stop line', () => {
    expect(ethereumKeysRowReport(1_000_001)).toEqual({ ethereum_keys_rows: 1_000_001, ethereum_keys_rows_over_threshold: true });
  });

  test('reports nothing but the count and the flag', () => {
    expect(Object.keys(ethereumKeysRowReport(5)).sort()).toEqual(['ethereum_keys_rows', 'ethereum_keys_rows_over_threshold']);
  });
});
