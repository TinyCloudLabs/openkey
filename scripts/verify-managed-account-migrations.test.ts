import { expect, test } from 'bun:test';
import { validateRequiredTriggers, type TriggerRow } from './verify-managed-account-migrations';

const accessTrigger: TriggerRow = {
  name: 'oauth_access_token_tenant_lifecycle_guard',
  relation: 'oauth_access_token',
  function: 'openkey_oauth_tenant_lifecycle_guard',
  enabled: 'O',
  deferrable: false,
  initiallyDeferred: false,
};

const refreshTrigger: TriggerRow = {
  ...accessTrigger,
  name: 'oauth_refresh_token_tenant_lifecycle_guard',
  relation: 'oauth_refresh_token',
};

test('migration verification rejects a missing OAuth lifecycle trigger', () => {
  const failures = validateRequiredTriggers([refreshTrigger]);
  expect(failures).toContain('Missing security trigger: oauth_access_token_tenant_lifecycle_guard');
});

test('migration verification rejects a disabled OAuth lifecycle trigger', () => {
  const failures = validateRequiredTriggers([
    { ...accessTrigger, enabled: 'D' },
    refreshTrigger,
  ]);
  expect(failures.some((failure) => failure.startsWith('Invalid security trigger oauth_access_token_tenant_lifecycle_guard:'))).toBe(true);
});
