// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { checkRequesterScope, isRequesterScopePolicy, pathFits, type RequesterScopePolicy, type RequesterScopeRule } from './requester-scope-policy';

const KV = 'tinycloud.kv';
const GET = 'tinycloud.kv/get';
const PREFIX = 'vault/secrets/';

// A pattern the shape check admits (two unbounded and four quantified atoms) that backtracks the worst on a miss.
const WORST = '^A[A-Z]*[A-Z]*[A-Z]{0,64}[A-Z]{0,64}$';
const ruleOf = (pattern: string): RequesterScopeRule => ({ kind: 'path', service: KV, spaces: ['secrets'], actions: [GET], pathPrefixes: [PREFIX], segmentPatterns: [pattern] });
const policyOf = (pattern: string): RequesterScopePolicy => ({ maxLifetimeSeconds: 3600, rules: [ruleOf(pattern)] });
const readOf = (path: string) => ({ permissions: [{ service: KV, space: 'secrets', path, actions: [GET] }], grantLifetimeSeconds: 3600 });
const reasonOf = (policy: RequesterScopePolicy, path: string) => {
  const verdict = checkRequesterScope(policy, readOf(path));
  return verdict.ok ? null : verdict.reason;
};
const timed = <T>(run: () => T): { result: T; ms: number } => {
  const start = performance.now();
  const result = run();
  return { result, ms: performance.now() - start };
};

describe('the length cap on a path matched against segment patterns', () => {
  test('the worst pattern the shape check admits is refused quickly by length on an 800-character miss', () => {
    expect(isRequesterScopePolicy(policyOf(WORST))).toBe(true);
    const miss = `${PREFIX}${'A'.repeat(799)}0`;
    const direct = timed(() => pathFits(ruleOf(WORST), miss));
    expect(direct.result).toBe(false);
    expect(direct.ms).toBeLessThan(100);
    const checked = timed(() => reasonOf(policyOf(WORST), miss));
    expect(checked.result).toBe('path');
    expect(checked.ms).toBeLessThan(100);
  });

  test('a path that would match is refused too once it is past the cap', () => {
    // Every character fits the pattern: only the length refuses it.
    const long = `${PREFIX}${'A'.repeat(300)}`;
    expect(pathFits(ruleOf(WORST), long)).toBe(false);
    expect(pathFits(ruleOf('^[A-Z]+$'), long)).toBe(false);
  });

  test('255 characters after the prefix are matched as before and 256 are refused', () => {
    const rule = ruleOf('^[A-Z]+$');
    expect(pathFits(rule, `${PREFIX}${'A'.repeat(255)}`)).toBe(true);
    expect(pathFits(rule, `${PREFIX}${'A'.repeat(256)}`)).toBe(false);
    // A 255-character segment that does not match the pattern is still a miss, not a pass.
    expect(pathFits(rule, `${PREFIX}${'A'.repeat(254)}a`)).toBe(false);
    expect(reasonOf(policyOf('^[A-Z]+$'), `${PREFIX}${'A'.repeat(255)}`)).toBeNull();
    expect(reasonOf(policyOf('^[A-Z]+$'), `${PREFIX}${'A'.repeat(256)}`)).toBe('path');
  });

  test('the cap counts the characters after the prefix, over all the segments', () => {
    const two: RequesterScopeRule = { ...ruleOf('^[A-Z]+$'), segmentPatterns: ['^[A-Z]+$', '^[a-z]+$'] };
    expect(pathFits(two, `${PREFIX}${'A'.repeat(127)}/${'b'.repeat(127)}`)).toBe(true);
    expect(pathFits(two, `${PREFIX}${'A'.repeat(128)}/${'b'.repeat(127)}`)).toBe(false);
  });

  test('both patterns One uses still pass, and a name past the cap is refused', () => {
    const one: RequesterScopePolicy = {
      maxLifetimeSeconds: 3600,
      rules: [
        ruleOf('^[A-Z][A-Z0-9_]*$'),
        { kind: 'encryption-network', service: 'tinycloud.encryption', spaces: ['encryption'], actions: ['tinycloud.encryption/decrypt'], network: 'default', wholeNetwork: true, keyPrefixes: ['secrets/'], keyNamePattern: '^(?!scoped$)[a-z0-9][a-z0-9_-]*$' },
      ],
    };
    expect(isRequesterScopePolicy(one)).toBe(true);
    const owner = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
    const network = `urn:tinycloud:encryption:${owner}:default`;
    const decrypt = (name: string) => ({ service: 'tinycloud.encryption', space: 'encryption', path: `${network}/secrets/${name}`, actions: ['tinycloud.encryption/decrypt'] });
    const ok = (permissions: unknown[]) => checkRequesterScope(one, { permissions, grantLifetimeSeconds: 3600 }).ok;
    const read = (name: string) => ({ service: KV, space: 'secrets', path: `${PREFIX}${name}`, actions: [GET] });
    expect(ok([read('OPENAI_API_KEY'), decrypt('openai_api_key')])).toBe(true);
    expect(ok([read('A'), decrypt('a')])).toBe(true);
    expect(ok([read(`A${'B'.repeat(254)}`)])).toBe(true);
    expect(ok([read(`A${'B'.repeat(255)}`)])).toBe(false);
    expect(ok([decrypt('Scoped')])).toBe(false);
    expect(ok([decrypt('scoped')])).toBe(false);
  });
});
