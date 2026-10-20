import { expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({});

// Query-string import: each test file gets its own module instance (mock-module.ts).
const { qaRegistrationAuthorized, QA_REGISTRATION_HEADER } = await import('../services/qa-registration?tc1632-qa' as string);

const env = {
  OPENKEY_QA_REGISTRATION_SECRET: 'current-secret-value',
  OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS: 'previous-secret-value',
} as NodeJS.ProcessEnv;

test('the header name is fixed and lowercase', () => {
  expect(QA_REGISTRATION_HEADER).toBe('x-openkey-qa-registration');
});

test('the current secret is accepted', () => {
  expect(qaRegistrationAuthorized('current-secret-value', env)).toBe(true);
});

test('the previous secret is accepted during rotation', () => {
  expect(qaRegistrationAuthorized('previous-secret-value', env)).toBe(true);
});

test('a wrong secret is rejected, including one that differs only in length', () => {
  expect(qaRegistrationAuthorized('current-secret-valu', env)).toBe(false);
  expect(qaRegistrationAuthorized('current-secret-value-x', env)).toBe(false);
  expect(qaRegistrationAuthorized('CURRENT-SECRET-VALUE', env)).toBe(false);
});

test('a missing header is rejected', () => {
  expect(qaRegistrationAuthorized(null, env)).toBe(false);
  expect(qaRegistrationAuthorized('', env)).toBe(false);
});

test('with no secret configured nothing matches, including an empty header', () => {
  expect(qaRegistrationAuthorized('', {} as NodeJS.ProcessEnv)).toBe(false);
  expect(qaRegistrationAuthorized('anything', {} as NodeJS.ProcessEnv)).toBe(false);
});

test('after rotation with no previous secret, the old value stops working', () => {
  const rotated = { OPENKEY_QA_REGISTRATION_SECRET: 'new-secret-value' } as NodeJS.ProcessEnv;
  expect(qaRegistrationAuthorized('new-secret-value', rotated)).toBe(true);
  expect(qaRegistrationAuthorized('current-secret-value', rotated)).toBe(false);
});
