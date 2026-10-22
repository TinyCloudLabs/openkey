import { describe, expect, test } from 'bun:test';
import {
  DECRYPT_LIFETIME_FLAG,
  DECRYPT_LIFETIME_REFUSAL,
  DECRYPT_STEPUP_ADMIT_FLAG,
  DecryptLifetimeError,
  assertDecryptLifetime,
  assertDecryptLifetimeIfEnforced,
  decryptLifetimeEnforcementEnabled,
  decryptLifetimeFlagLines,
  decryptStepupAdmitEnabled,
  logDecryptLifetimeFlagOnce,
  type DecryptPolicyEntry,
} from '../services/decrypt-lifetime-policy';

const ON = { [DECRYPT_LIFETIME_FLAG]: 'true' } as NodeJS.ProcessEnv;
const ADMIT_ON = { [DECRYPT_STEPUP_ADMIT_FLAG]: 'true' } as NodeJS.ProcessEnv;
const BOTH_ON = {
  [DECRYPT_LIFETIME_FLAG]: 'true',
  [DECRYPT_STEPUP_ADMIT_FLAG]: 'true',
} as NodeJS.ProcessEnv;
const OFF = {} as NodeJS.ProcessEnv;
const NOW = Date.UTC(2026, 0, 1, 12, 0, 0);
const WEEK_SECONDS = 7 * 24 * 60 * 60;

const decryptEntry: DecryptPolicyEntry = {
  service: 'tinycloud.encryption',
  space: 'default',
  path: '',
  actions: ['tinycloud.encryption/decrypt'],
};
const kvEntry: DecryptPolicyEntry = {
  service: 'tinycloud.kv',
  space: 'applications',
  path: '',
  actions: ['tinycloud.kv/get'],
};
const networkCreateEntry: DecryptPolicyEntry = {
  service: 'tinycloud.encryption',
  space: 'default',
  path: '',
  actions: ['tinycloud.encryption/network.create'],
};

function refuses(fn: () => void): boolean {
  try {
    fn();
    return false;
  } catch (error) {
    expect(error).toBeInstanceOf(DecryptLifetimeError);
    expect((error as Error).message).toBe(DECRYPT_LIFETIME_REFUSAL);
    return true;
  }
}

describe('decrypt lifetime flag parse', () => {
  test.each([
    [undefined, false],
    ['', false],
    ['false', false],
    ['0', false],
    ['TRUE', false],
    ['yes', false],
    [' true', false],
    ['TRUE ', false],
    ['True', false],
    ['ture', false],
    ['truee', false],
    ['on', false],
    ['enabled', false],
    ['1 ', false],
    ['0 ', false],
    ['true', true],
    ['1', true],
  ])('enforce value %p enables enforcement: %p', (value, expected) => {
    const env = value === undefined ? {} : { [DECRYPT_LIFETIME_FLAG]: value };
    expect(decryptLifetimeEnforcementEnabled(env as NodeJS.ProcessEnv)).toBe(expected);
  });

  test.each([
    [undefined, false],
    ['', false],
    ['false', false],
    ['0', false],
    ['TRUE', false],
    ['yes', false],
    [' true', false],
    ['TRUE ', false],
    ['True', false],
    ['on', false],
    ['true', true],
    ['1', true],
  ])('admit value %p enables admission: %p', (value, expected) => {
    const env = value === undefined ? {} : { [DECRYPT_STEPUP_ADMIT_FLAG]: value };
    expect(decryptStepupAdmitEnabled(env as NodeJS.ProcessEnv)).toBe(expected);
  });
});

describe('startup flag log', () => {
  test('both flags off print both states and no warning', () => {
    expect(decryptLifetimeFlagLines(OFF)).toEqual([`${DECRYPT_STEPUP_ADMIT_FLAG}=off`, `${DECRYPT_LIFETIME_FLAG}=off`]);
  });

  test('admit on with enforce off prints both states and no warning', () => {
    expect(decryptLifetimeFlagLines(ADMIT_ON)).toEqual([`${DECRYPT_STEPUP_ADMIT_FLAG}=on`, `${DECRYPT_LIFETIME_FLAG}=off`]);
  });

  test('both on print both states and no warning', () => {
    expect(decryptLifetimeFlagLines(BOTH_ON)).toEqual([`${DECRYPT_STEPUP_ADMIT_FLAG}=on`, `${DECRYPT_LIFETIME_FLAG}=on`]);
  });

  test('enforce on without admit prints the warning', () => {
    const lines = decryptLifetimeFlagLines(ON);
    expect(lines).toHaveLength(3);
    expect(lines[2]).toBe(
      `WARNING: ${DECRYPT_LIFETIME_FLAG}=on without ${DECRYPT_STEPUP_ADMIT_FLAG}=on; lone own-network decrypt requests are refused`,
    );
  });

  test('the once logger prints the state exactly once, on the first call only', () => {
    const lines: string[] = [];
    logDecryptLifetimeFlagOnce((line) => lines.push(line), ON);
    logDecryptLifetimeFlagOnce((line) => lines.push(line), BOTH_ON);
    expect(lines).toEqual(decryptLifetimeFlagLines(ON));
  });
});

describe('assertDecryptLifetime', () => {
  test('explicit 3600 s decrypt alone is accepted', () => {
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry], requestedTtlSeconds: 3600 }))).toBe(false);
  });

  test('explicit 3601 s decrypt alone is refused', () => {
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry], requestedTtlSeconds: 3601 }))).toBe(true);
  });

  test('7-day decrypt on a delegation is refused', () => {
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry], requestedTtlSeconds: WEEK_SECONDS }))).toBe(true);
  });

  test('decrypt with no explicit lifetime is refused, including the 7-day default', () => {
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry] }))).toBe(true);
  });

  test('decrypt plus another entry is refused even at 3600 s', () => {
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry, kvEntry], requestedTtlSeconds: 3600 }))).toBe(true);
  });

  test('decrypt and network.create in one entry is refused', () => {
    const bundled: DecryptPolicyEntry = {
      service: 'tinycloud.encryption',
      space: 'default',
      path: '',
      actions: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create'],
    };
    expect(refuses(() => assertDecryptLifetime({ entries: [bundled], requestedTtlSeconds: 3600 }))).toBe(true);
  });

  test('bundle without decrypt is unchanged, even with a 7-day lifetime', () => {
    expect(refuses(() => assertDecryptLifetime({ entries: [kvEntry, networkCreateEntry], requestedTtlSeconds: WEEK_SECONDS }))).toBe(false);
  });

  test('named-key decrypt is treated the same as default-network decrypt', () => {
    const named: DecryptPolicyEntry = { service: 'tinycloud.encryption', space: 'default', path: 'named-key', actions: ['tinycloud.encryption/decrypt'] };
    expect(refuses(() => assertDecryptLifetime({ entries: [named], requestedTtlSeconds: 3600 }))).toBe(false);
    expect(refuses(() => assertDecryptLifetime({ entries: [named], requestedTtlSeconds: WEEK_SECONDS }))).toBe(true);
  });

  test('short service name encryption with decrypt is treated as decrypt', () => {
    const short: DecryptPolicyEntry = { service: 'encryption', actions: ['decrypt'] };
    expect(refuses(() => assertDecryptLifetime({ entries: [short], requestedTtlSeconds: WEEK_SECONDS }))).toBe(true);
    expect(refuses(() => assertDecryptLifetime({ entries: [short], requestedTtlSeconds: 3600 }))).toBe(false);
  });

  test('absolute expiry exactly one hour from signing time is accepted', () => {
    const expiresAt = new Date(NOW + 3600 * 1000);
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry], expiresAt, now: NOW }))).toBe(false);
  });

  test('absolute expiry one second past one hour is refused', () => {
    const expiresAt = new Date(NOW + 3601 * 1000);
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry], expiresAt, now: NOW }))).toBe(true);
  });

  test('absolute expiry in the past is refused', () => {
    const expiresAt = new Date(NOW - 1000);
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry], expiresAt, now: NOW }))).toBe(true);
  });

  test('unparseable absolute expiry is refused', () => {
    expect(refuses(() => assertDecryptLifetime({ entries: [decryptEntry], expiresAt: 'not-a-date', now: NOW }))).toBe(true);
  });
});

describe('assertDecryptLifetimeIfEnforced', () => {
  test('flag OFF: 7-day decrypt is not refused', () => {
    expect(refuses(() => assertDecryptLifetimeIfEnforced({ entries: [decryptEntry], requestedTtlSeconds: WEEK_SECONDS }, OFF))).toBe(false);
  });

  test('flag ON: 7-day decrypt is refused', () => {
    expect(refuses(() => assertDecryptLifetimeIfEnforced({ entries: [decryptEntry], requestedTtlSeconds: WEEK_SECONDS }, ON))).toBe(true);
  });
});
