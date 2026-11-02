import { expect, test } from 'bun:test';
import { excludedAccountIds, parseExclusions } from '../services/scoreboard-exclusions';

const address = '0xabcdef0000000000000000000000000000000001';
const accounts = [
  { id: 'listed', email: 'person@example.net', ethereumKeys: [] },
  { id: 'own', email: 'QA@TEAM.EXAMPLE', ethereumKeys: [] },
  { id: 'mailbox', email: 'test@DISPOSABLE.EXAMPLE', ethereumKeys: [] },
  { id: 'exact', email: 'PERSON@EXAMPLE.ORG', ethereumKeys: [] },
  { id: 'key-owner', email: 'key@example.net', ethereumKeys: [{ address: address.toUpperCase() }] },
  { id: 'agent-owner', email: 'service@example.net', ethereumKeys: [] },
  { id: 'unsure', email: 'unsure@example.net', ethereumKeys: [] },
  { id: 'real', email: 'real@sub.team.example', ethereumKeys: [] },
];
const rules = (entries: unknown[]) => parseExclusions(JSON.stringify(entries));

test('an explicit user id excludes one account', () => {
  expect([...excludedAccountIds(accounts, rules([{ kind: 'user_id', value: 'listed' }]))]).toEqual(['listed']);
});
test('own and throwaway domains match case-insensitively and exactly, not subdomains', () => {
  expect([...excludedAccountIds(accounts, rules([
    { kind: 'email_domain', value: 'Team.Example' },
    { kind: 'email_domain', value: 'DISPOSABLE.EXAMPLE' },
  ]))]).toEqual(['own', 'mailbox']);
});
test('exact emails are case-insensitive', () => {
  expect([...excludedAccountIds(accounts, rules([{ kind: 'email', value: 'person@example.org' }]))]).toEqual(['exact']);
});
test('overlapping rules exclude an account once', () => {
  expect(excludedAccountIds(accounts, rules([
    { kind: 'user_id', value: 'own' }, { kind: 'email_domain', value: 'team.example' },
  ])).size).toBe(1);
});
test('empty configuration excludes nobody', () => {
  expect(excludedAccountIds(accounts, parseExclusions(undefined)).size).toBe(0);
  expect(excludedAccountIds(accounts, rules([])).size).toBe(0);
  expect(excludedAccountIds(accounts, parseExclusions('  ')).size).toBe(0);
});
test('EVM addresses and pkh DIDs match keys including archived keys and ignore chain for account lookup', () => {
  for (const entry of [
    { kind: 'evm_address', value: address },
    { kind: 'did', value: `did:pkh:eip155:137:${address}` },
  ]) expect([...excludedAccountIds(accounts, rules([entry]))]).toEqual(['key-owner']);
});
test('did:key entries affect only accounts mapped by OpenKey records', () => {
  const entries = rules([{ kind: 'did', value: 'did:key:zSyntheticAgent' }]);
  expect([...excludedAccountIds(accounts, entries, new Set(['agent-owner']))]).toEqual(['agent-owner']);
  expect(excludedAccountIds(accounts, entries).size).toBe(0);
});
test('unsure entries never exclude accounts, even when otherwise matching', () => {
  const entries = rules([
    { kind: 'user_id', value: 'unsure', status: 'UNSURE' },
    { kind: 'email', value: 'unsure@example.net', confidence: 'unsure' },
    { kind: 'email_domain', value: 'example.net', decision: 'unsure' },
  ]);
  expect(excludedAccountIds(accounts, entries).size).toBe(0);
});
test('invalid configuration fails without exposing entry values', () => {
  expect(() => parseExclusions('{broken')).toThrow('Invalid scoreboard exclusions');
  expect(() => rules([{ kind: 'unknown', value: 'private-value' }])).toThrow('Invalid scoreboard exclusions');
  expect(() => rules([{ kind: 'evm_address', value: 'bad-address' }])).toThrow('Invalid scoreboard exclusions');
});
