import { expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({});

// Query-string import: each test file gets its own module instance (mock-module.ts).
const { qaEligibleEmail, qaRegistrationAuthorized, qaRegistrationSecretTooShort, QA_REGISTRATION_HEADER, QA_SECRET_MIN_LENGTH } = await import(
  '../services/qa-registration?tc1632-qa' as string
);

// Secrets are base64url of 32 random bytes in practice: 43 characters.
const CURRENT = 'c'.repeat(43);
const PREVIOUS = 'p'.repeat(43);

const env = {
  OPENKEY_QA_REGISTRATION_SECRET: CURRENT,
  OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS: PREVIOUS,
} as NodeJS.ProcessEnv;

test('the header name is fixed and lowercase', () => {
  expect(QA_REGISTRATION_HEADER).toBe('x-openkey-qa-registration');
});

test('the current secret is accepted', () => {
  expect(qaRegistrationAuthorized(CURRENT, env)).toBe(true);
});

test('the previous secret is accepted during rotation', () => {
  expect(qaRegistrationAuthorized(PREVIOUS, env)).toBe(true);
});

test('a wrong secret is rejected, including one that differs only in length or case', () => {
  expect(qaRegistrationAuthorized(CURRENT.slice(1), env)).toBe(false);
  expect(qaRegistrationAuthorized(`${CURRENT}x`, env)).toBe(false);
  expect(qaRegistrationAuthorized(CURRENT.toUpperCase(), env)).toBe(false);
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
  const rotated = { OPENKEY_QA_REGISTRATION_SECRET: 'n'.repeat(43) } as NodeJS.ProcessEnv;
  expect(qaRegistrationAuthorized('n'.repeat(43), rotated)).toBe(true);
  expect(qaRegistrationAuthorized(CURRENT, rotated)).toBe(false);
});

test('a configured secret shorter than the minimum never matches, even exactly', () => {
  const short = { OPENKEY_QA_REGISTRATION_SECRET: 'short-secret' } as NodeJS.ProcessEnv;
  expect(QA_SECRET_MIN_LENGTH).toBe(43);
  expect(qaRegistrationAuthorized('short-secret', short)).toBe(false);
  expect(qaRegistrationSecretTooShort(short)).toBe(true);
});

test('an unset or minimum-length secret is not reported as too short', () => {
  expect(qaRegistrationSecretTooShort({} as NodeJS.ProcessEnv)).toBe(false);
  expect(qaRegistrationSecretTooShort(env)).toBe(false);
});

test('only emails matching a QA-eligible pattern are eligible', () => {
  expect(qaEligibleEmail('tcqa-7f3a@mailinator.com')).toBe(true);
  expect(qaEligibleEmail('TCQA-7F3A@mailinator.com')).toBe(true);
  expect(qaEligibleEmail('qa-clr-0123456789ab@mailinator.com')).toBe(true);
  expect(qaEligibleEmail('tc1384qa-abc123@mailinator.com')).toBe(true);
});

test('a pattern marked not eligible, and any other address, is not QA-eligible', () => {
  expect(qaEligibleEmail('qaabcdefghijklmno@mailinator.com')).toBe(false);
  expect(qaEligibleEmail('new@example.com')).toBe(false);
  expect(qaEligibleEmail('tcqa-7f3a@mailinator.com.evil.example')).toBe(false);
});
