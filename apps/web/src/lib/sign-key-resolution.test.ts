// @ts-expect-error bun:test is a runtime-only module; svelte-check does not ship its types.
import { describe, expect, test } from 'bun:test';
import type { EthereumKey } from './api';
import { resolveSigningKey } from './sign-key-resolution';

const A = '0xd559cCd9EB87c530A9a349262669386dE93cf412';
const B = '0x1111111111111111111111111111111111111111';
const key = (id: string, address: string, extra: Partial<EthereumKey> = {}): EthereumKey => ({
  id, address, publicKey: '0x02', keyIndex: 0, label: null, keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z', ...extra,
});
const siwe = (address: string) => [
  'inbox.example wants you to sign in with your Ethereum account:', address, '',
  'URI: https://inbox.example', 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-11-08T00:00:00.000Z',
].join('\n');

describe('resolveSigningKey', () => {
  test('a plain message: the only signing key is used; several are a choice; none is none', () => {
    expect(resolveSigningKey([key('a', A)], 'hello')).toEqual({ kind: 'resolved', key: key('a', A) });
    expect(resolveSigningKey([key('a', A), key('b', B)], 'hello')).toEqual({ kind: 'choose', keys: [key('a', A), key('b', B)] });
    expect(resolveSigningKey([], 'hello')).toEqual({ kind: 'none' });
  });

  test('archived keys and linked wallets never sign, even as the only key', () => {
    const archived = key('archived', A, { archivedAt: '2026-02-01T00:00:00Z' });
    const wallet = key('wallet', B, { keyType: 'EXTERNAL' });
    expect(resolveSigningKey([archived, wallet], 'hello')).toEqual({ kind: 'none' });
    expect(resolveSigningKey([archived, wallet, key('b', B)], 'hello')).toEqual({ kind: 'resolved', key: key('b', B) });
  });

  test('a SIWE fits only the key whose address it names (any letter case), never a choice and never another key', () => {
    expect(resolveSigningKey([key('a', A), key('b', B)], siwe(A.toLowerCase()))).toEqual({ kind: 'resolved', key: key('a', A) });
    expect(resolveSigningKey([key('b', B)], siwe(A))).toEqual({ kind: 'none' });
    expect(resolveSigningKey([key('a', A, { keyType: 'EXTERNAL' }), key('b', B)], siwe(A))).toEqual({ kind: 'none' });
  });

  test('a SIWE-shaped message that names no readable address fits no key', () => {
    expect(resolveSigningKey([key('a', A)], siwe('not-an-address'))).toEqual({ kind: 'none' });
    expect(resolveSigningKey([key('a', A)], `URI: https://inbox.example\nNonce: abcdef123456\n${A}`)).toEqual({ kind: 'none' });
  });
});
