// TC-966: the mock TEE client seals under deterministic dev keys, so it must
// never be selected implicitly.
import { describe, expect, test } from 'bun:test';
import { resolveTeeMode } from '../src/index';

describe('resolveTeeMode fails closed (TC-966)', () => {
  test('TEE_MODE=production selects dstack', () => {
    expect(resolveTeeMode({ TEE_MODE: 'production', NODE_ENV: 'production' })).toBe('production');
    expect(resolveTeeMode({ TEE_MODE: 'production' })).toBe('production');
  });

  test('the mock needs an explicit TEE_MODE=development outside production', () => {
    expect(resolveTeeMode({ TEE_MODE: 'development' })).toBe('development');
    expect(resolveTeeMode({ TEE_MODE: 'development', NODE_ENV: 'test' })).toBe('development');
  });

  test('TEE_MODE=development is refused with NODE_ENV=production', () => {
    expect(() => resolveTeeMode({ TEE_MODE: 'development', NODE_ENV: 'production' })).toThrow(
      'TEE_MODE=development is not allowed with NODE_ENV=production',
    );
  });

  for (const mode of [undefined, '', 'prod', 'Production', ' production', 'dev']) {
    for (const nodeEnv of ['production', undefined]) {
      test(`TEE_MODE=${JSON.stringify(mode)} with NODE_ENV=${nodeEnv} throws`, () => {
        expect(() => resolveTeeMode({ TEE_MODE: mode, NODE_ENV: nodeEnv })).toThrow(
          'refusing to fall back to mock sealing keys',
        );
      });
    }
  }
});
