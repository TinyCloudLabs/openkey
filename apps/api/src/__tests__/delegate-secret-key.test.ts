import { describe, expect, test } from 'bun:test';
import { DelegateRequestError } from '../routes/delegate-validation';
import {
  parsePreparedRecap,
  prepareDelegationSession,
  type DelegationPermissionEntry,
} from '../routes/delegate-session';

// TC-3800: a request may name one secret's own key, `default/secrets/<name>` or
// `default/secrets/scoped/<scope>/<name>`, for decrypt and key.create, in the
// signer's own account only. Every other named key or folder keeps its rule.

const address = '0xA8763f2b67aa9C807d2277a698cb071e3D86204A';
const chainId = 1;
const ownerDid = `did:pkh:eip155:${chainId}:${address}`;
const keyUrn = (tail: string, did = ownerDid) => `urn:tinycloud:encryption:${did}:default/${tail}`;
const space = `tinycloud:pkh:eip155:${chainId}:${address}:secrets`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const DECRYPT = 'tinycloud.encryption/decrypt';
const CREATE = 'tinycloud.encryption/key.create';

function request(path: string, actions: string[] = [DECRYPT]): DelegationPermissionEntry[] {
  return [
    { service: 'tinycloud.kv', space, path: 'vault/secrets/OPENAI_API_KEY', actions: ['tinycloud.kv/get'] },
    { service: 'tinycloud.encryption', space: 'encryption', path, actions },
  ];
}

function prepare(permissions: DelegationPermissionEntry[]) {
  return prepareDelegationSession({ address, chainId, prefix: 'default', jwk, permissions, expiryMs: 60 * 60 * 1000 });
}

function recapAtt(siwe: string): Record<string, Record<string, unknown[]>> {
  const encoded = /^- urn:recap:(.+)$/m.exec(siwe)?.[1];
  if (!encoded) throw new Error('SIWE has no ReCap resource');
  return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')).att;
}

function refusal(permissions: DelegationPermissionEntry[]): DelegateRequestError {
  let error: unknown;
  try {
    prepare(permissions);
  } catch (caught) {
    error = caught;
  }
  if (!(error instanceof DelegateRequestError)) throw new Error('expected a DelegateRequestError');
  expect(error.code).toBe('invalid_permissions');
  return error;
}

describe('prepareDelegationSession — one secret\'s own key (TC-3800)', () => {
  test('signs decrypt and key.create on a global and a scoped secret key as raw resources', () => {
    for (const tail of ['secrets/openai_api_key', 'secrets/scoped/work.team/openai_api_key']) {
      const path = keyUrn(tail);
      const siwe = prepare(request(path, [DECRYPT, CREATE])).prepared.siwe;
      expect(recapAtt(siwe)[path], tail).toEqual({ [DECRYPT]: [{}], [CREATE]: [{}] });
      expect(parsePreparedRecap(siwe)).toContainEqual({ service: 'encryption', space: 'encryption', path, actions: [DECRYPT, CREATE] });
    }
  });

  test('refuses another owner\'s secret key, another chain, and a non-canonical owner', () => {
    const paths = [
      keyUrn('secrets/openai_api_key', 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001'),
      keyUrn('secrets/openai_api_key', `did:pkh:eip155:10:${address}`),
      keyUrn('secrets/openai_api_key', `did:pkh:eip155:1:${address.toLowerCase()}`),
    ];
    for (const path of paths) {
      for (const actions of [[DECRYPT], [CREATE]]) {
        expect(refusal(request(path, actions)).details?.[0]?.path, `${path} ${actions}`).toBe('permissions[1].path');
      }
    }
  });

  test('refuses a secret key path that is not exactly one lowercase secret', () => {
    const tails = [
      'secrets/OPENAI_API_KEY',
      'secrets/Openai_api_key',
      'secrets/scoped/Work/openai_api_key',
      'secrets/scoped/work',
      'secrets/scoped/work/',
      'secrets/scoped/work/a/b',
      'secrets/a/b',
      'secrets/.hidden',
      'secrets/..',
      'secrets/',
      'secrets//x',
      `secrets/${'a'.repeat(65)}`,
    ];
    for (const tail of tails) {
      const error = refusal(request(keyUrn(tail)));
      expect(error.details?.[0]?.path, tail).toBe('permissions[1].path');
    }
    expect(refusal(request(keyUrn('secrets/OPENAI_API_KEY'))).message).toContain('names an invalid secret key');
  });

  test('keeps key.create refused on a whole network, the share folder and a share key', () => {
    const paths = [
      `urn:tinycloud:encryption:${ownerDid}:default`,
      keyUrn('share/'),
      keyUrn('share/0123456789abcdef0123456789abcdef'),
    ];
    for (const path of paths) {
      expect(refusal(request(path, [CREATE])).details?.[0]?.path, path).toBe('permissions[1].actions[0]');
    }
  });

  test('a secret key grants decrypt and key.create only', () => {
    for (const action of ['tinycloud.encryption/key.block', 'tinycloud.encryption/key.delete', 'tinycloud.kv/put']) {
      expect(refusal(request(keyUrn('secrets/openai_api_key'), [action])).details?.[0]?.path, action).toBe('permissions[1].actions[0]');
    }
  });
});
