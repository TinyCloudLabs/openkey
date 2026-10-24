import { expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({});

// Query-string import: each test file gets its own module instance (mock-module.ts).
const {
  parseTestAccountRegistry,
  qaEligibleEmail,
  qaRegistrationAuthorized,
  qaRegistrationSecretTooShort,
  QA_REGISTRATION_HEADER,
  QA_SECRET_MIN_LENGTH,
} = await import('../services/qa-registration?tc1632-qa' as string);

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

// Synthetic fixtures only: real registry values are supplied at runtime, never in the repo.
const fixtureRegistry = parseTestAccountRegistry(
  JSON.stringify({
    userIds: [],
    clientIds: [],
    emailDomains: ['example.test'],
    patterns: [
      { name: 'fixture-qa', regex: '^fixture-qa-[a-z0-9]+@example\\.test$', qaEligible: true },
      { name: 'fixture-reference', regex: '^fixture-ref[a-z0-9]+@example\\.test$', qaEligible: false },
    ],
  }),
).registry;

test('only emails matching a QA-eligible pattern are eligible', () => {
  expect(qaEligibleEmail('fixture-qa-7f3a@example.test', fixtureRegistry.qaEligiblePatterns)).toBe(true);
  expect(qaEligibleEmail('FIXTURE-QA-7F3A@example.test', fixtureRegistry.qaEligiblePatterns)).toBe(true);
});

test('a pattern marked not eligible, and any other address, is not QA-eligible', () => {
  expect(qaEligibleEmail('fixture-ref0123@example.test', fixtureRegistry.qaEligiblePatterns)).toBe(false);
  expect(qaEligibleEmail('new@example.com', fixtureRegistry.qaEligiblePatterns)).toBe(false);
  expect(qaEligibleEmail('fixture-qa-7f3a@example.test.evil.example', fixtureRegistry.qaEligiblePatterns)).toBe(false);
});

test('an unset registry is empty and not a problem', () => {
  const unset = parseTestAccountRegistry(undefined);
  expect(unset.problem).toBe(false);
  expect(unset.registry.qaEligiblePatterns).toEqual([]);
  expect(unset.registry.emailDomains).toEqual([]);
});

test('invalid registry JSON, shape, or pattern yields an empty registry and a problem, never a throw', () => {
  const invalid = [
    '{not json',
    '[]',
    JSON.stringify({ userIds: [], clientIds: [], patterns: 'nope' }),
    JSON.stringify({ userIds: [], clientIds: [], patterns: [{ name: 'bad', regex: '[', qaEligible: true }] }),
  ];
  for (const raw of invalid) {
    const load = parseTestAccountRegistry(raw);
    expect(load.problem).toBe(true);
    expect(load.registry.qaEligiblePatterns).toEqual([]);
    expect(load.registry.emailDomains).toEqual([]);
  }
});

test('email domains are lowercased and default to empty when absent', () => {
  const load = parseTestAccountRegistry(JSON.stringify({ userIds: [], clientIds: [], patterns: [], emailDomains: ['Example.TEST'] }));
  expect(load.registry.emailDomains).toEqual(['example.test']);
  expect(parseTestAccountRegistry(JSON.stringify({ userIds: [], clientIds: [], patterns: [] })).registry.emailDomains).toEqual([]);
});

// Synthetic patterns only. Each raw registry has one QA-eligible pattern.
const registryWith = (regex: string, qaEligible = true) =>
  JSON.stringify({ userIds: [], clientIds: [], emailDomains: [], patterns: [{ name: 'fixture', regex, qaEligible }] });

test('a QA-eligible pattern anchored at both ends and ending in a literal domain is loaded and usable', () => {
  const valid = [
    '^qa-[a-z0-9]+@example\\.test$',
    '^(?:qa-a|qa-b)@example\\.test$',
    '^qa-[|]x@example\\.test$',
    '^qa-[0-9]+@qa\\.example\\.com$',
    '^qa\\+.*@qa-team\\.example\\.com$',
    '^qa-[0-9]+@notgmail\\.com$',
  ];
  for (const regex of valid) {
    const load = parseTestAccountRegistry(registryWith(regex));
    expect(load.problem).toBe(false);
    expect(load.refusal).toBeUndefined();
    expect(load.registry.qaEligiblePatterns).toHaveLength(1);
  }
  const pattern = parseTestAccountRegistry(registryWith('^qa-[0-9]+@qa\\.example\\.com$')).registry.qaEligiblePatterns;
  expect(qaEligibleEmail('qa-123@qa.example.com', pattern)).toBe(true);
  expect(qaEligibleEmail('qa-123@qa.example.com.evil.example', pattern)).toBe(false);
});

test('a QA-eligible pattern that is not anchored at both ends is refused at load', () => {
  const unanchored = [
    'qa-[a-z0-9]+@example\\.test$',
    '^qa-[a-z0-9]+@example\\.test',
    'qa-[a-z0-9]+@example\\.test',
    '^qa-[a-z0-9]+@example\\.test\\$',
    '^qa-a@example\\.test$|qa-b@example\\.test',
    '^qa-a@example\\.test|qa-b@example\\.test$',
    '^qa-a@example\\.test$|^qa-b@example\\.test$',
  ];
  for (const regex of unanchored) {
    const load = parseTestAccountRegistry(registryWith(regex));
    expect(load.problem).toBe(true);
    expect(load.refusal).toBe('unanchored_pattern');
    expect(load.registry.qaEligiblePatterns).toEqual([]);
    expect(load.registry.userIds).toEqual([]);
  }
});

test('a QA-eligible pattern whose domain is not a literal domain is refused at load', () => {
  const unqualified = [
    '^qa\\+.*@.*$',
    '^qa-[0-9]+@.*$',
    '^z.*@g[m]ail\\.com$',
    '^x[a-z]*@.*\\.com$',
    '^.*$',
    '^.+@.+$',
    '^[a-z0-9-]+@[a-z.]+$',
    '^[a-z0-9-]+@[a-z]+\\.com$',
    '^qa-[a-z0-9]+@(?:example|other)\\.test$',
    '^qa-[a-z0-9]+@example\\.t+est$',
    '^qa-[a-z0-9]+@example.test$',
    '^qa-[a-z0-9]+@example\\.test$\\.com$',
    '^qa-[a-z0-9]+@localhost$',
    '^qa-[a-z0-9]+@Example\\.test$',
    '^qa-[a-z0-9]+$',
  ];
  for (const regex of unqualified) {
    const load = parseTestAccountRegistry(registryWith(regex));
    expect(load.problem).toBe(true);
    expect(load.refusal).toBe('unqualified_domain_pattern');
    expect(load.registry.qaEligiblePatterns).toEqual([]);
  }
});

test('a QA-eligible pattern whose literal domain is a public mail domain or a subdomain of one is refused at load', () => {
  const publicDomains = [
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'proton.me', 'protonmail.com',
    'googlemail.com', 'aol.com', 'gmx.com', 'gmx.de', 'gmx.net', 'mail.com', 'yandex.com', 'yandex.ru',
    'zoho.com', 'fastmail.com', 'fastmail.fm',
  ];
  for (const domain of publicDomains) {
    const escaped = domain.replaceAll('.', '\\.');
    for (const regex of [`^qa-[a-z0-9]+@${escaped}$`, `^.+@${escaped}$`, `^qa-[0-9]+@eu\\.${escaped}$`]) {
      const load = parseTestAccountRegistry(registryWith(regex));
      expect(load.problem).toBe(true);
      expect(load.refusal).toBe('public_mail_domain_pattern');
      expect(load.registry.qaEligiblePatterns).toEqual([]);
    }
  }
});

test('a refused pattern leaves no email eligible for the exemption', async () => {
  const { loadTestAccountRegistry } = await import('../services/qa-registration?tc1632-qa' as string);
  const load = loadTestAccountRegistry({ TEST_ACCOUNT_REGISTRY_JSON: registryWith('^qa-[a-z0-9]+@gmail\\.com$') } as NodeJS.ProcessEnv);
  expect(load.problem).toBe(true);
  expect(qaEligibleEmail('qa-7f3a@gmail.com', load.registry.qaEligiblePatterns)).toBe(false);
});

test('the checks apply to QA-eligible patterns only', () => {
  const load = parseTestAccountRegistry(registryWith('^.+@gmail\\.com', false));
  expect(load.problem).toBe(false);
  expect(load.registry.qaEligiblePatterns).toEqual([]);
});
