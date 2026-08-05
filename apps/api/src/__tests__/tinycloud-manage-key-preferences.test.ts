import { describe, expect, test } from 'bun:test';
import { parseTinyCloudManageKeyAppPreferencePatch } from '../services/tinycloud-manage-key-preferences';

describe('TinyCloud manage-key app preference patch', () => {
  test('accepts an explicit boolean only', () => {
    expect(parseTinyCloudManageKeyAppPreferencePatch({ enabled: false })).toEqual({ enabled: false });
    expect(() => parseTinyCloudManageKeyAppPreferencePatch({})).toThrow('enabled must be a boolean');
    expect(() => parseTinyCloudManageKeyAppPreferencePatch({ enabled: 'false' })).toThrow('enabled must be a boolean');
  });
});
