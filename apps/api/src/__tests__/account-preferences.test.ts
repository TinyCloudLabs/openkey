import { describe, expect, test } from 'bun:test';
import { parseAutoSignPreferencePatch } from '../routes/account-preferences';

describe('parseAutoSignPreferencePatch', () => {
  test('accepts boolean Auto-Sign preferences', () => {
    expect(parseAutoSignPreferencePatch({ autoSignEnabled: true })).toEqual({
      autoSignEnabled: true,
    });
    expect(parseAutoSignPreferencePatch({ autoSignEnabled: false })).toEqual({
      autoSignEnabled: false,
    });
  });

  test('rejects missing or non-boolean Auto-Sign preferences', () => {
    expect(() => parseAutoSignPreferencePatch({})).toThrow('autoSignEnabled must be a boolean');
    expect(() => parseAutoSignPreferencePatch({ autoSignEnabled: 'true' })).toThrow(
      'autoSignEnabled must be a boolean',
    );
    expect(() => parseAutoSignPreferencePatch(null)).toThrow('Request body must be an object');
  });
});
