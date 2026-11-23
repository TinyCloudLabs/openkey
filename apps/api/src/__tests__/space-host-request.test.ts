// What a message lets a site do with spaces, read from the ReCap's own resources (the keys route's fail-closed input).

import { describe, expect, test } from 'bun:test';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { spaceHostRequest, type SpaceHostRequest } from '../services/tinycloud-siwe';
import { escapedHostSpellings, withRawRecap } from './space-host-recap';

const address = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const space = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
const host = (name: string) => generateHostSIWEMessage({
  address, chainId: 1, domain: 'app.example.test', issuedAt: new Date().toISOString(), spaceId: space(name),
  peerId: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
});
const withResources = (message: string, att: Record<string, Record<string, unknown[]>>) => {
  // The recap parser checks the statement against the resources, so write the statement the resources imply.
  const lines = Object.entries(att).sort(([a], [b]) => a.localeCompare(b)).flatMap(([resource, abilities]) =>
    Object.keys(abilities).sort().map((ability) => `'${ability.slice(0, ability.indexOf('/'))}': '${ability.slice(ability.indexOf('/') + 1)}' for '${resource}'`));
  const statement = `I further authorize the stated URI to perform the following actions on my behalf: ${lines.map((line, i) => `(${i + 1}) ${line}.`).join(' ')}`;
  const recap = `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`;
  return message.replace(/I further authorize[^\n]*/, statement).replace(/urn:recap:[A-Za-z0-9_-]+/, recap);
};

describe('spaceHostRequest', () => {
  test('reads each host target as an owner, a chain and a name', () => {
    expect(spaceHostRequest(host('public'))).toEqual({ kind: 'hosts', targets: [{ address, chainId: 1, name: 'public' }] });
  });

  test('reads a name that merely contains "default" as that name', () => {
    expect(spaceHostRequest(host('not-default'))).toEqual({ kind: 'hosts', targets: [{ address, chainId: 1, name: 'not-default' }] });
  });

  test('reads every target of a message that names several', () => {
    const message = withResources(host('public'), {
      [`${space('public')}/space`]: { 'tinycloud.space/host': [{}] },
      [`${space('default')}/space`]: { 'tinycloud.space/host': [{}] },
    });
    const request = spaceHostRequest(message);
    expect(request.kind).toBe('hosts');
    expect(request.kind === 'hosts' && request.targets.map((target) => target.name).sort()).toEqual(['default', 'public']);
  });

  test('finds the same targets in the 0x hex form of the message', () => {
    expect(spaceHostRequest(`0x${Buffer.from(host('public')).toString('hex')}`)).toEqual(spaceHostRequest(host('public')));
  });

  test('a message with no space ability names no host target', () => {
    expect(spaceHostRequest('Sign in to the app')).toEqual({ kind: 'none' });
  });

  test('a wildcard, another space ability, or a target that is not a space id is unreadable', () => {
    const unreadable: Array<Record<string, Record<string, unknown[]>>> = [
      { [`${space('public')}/space`]: { 'tinycloud.space/*': [{}] } },
      { [`${space('public')}/space`]: { 'tinycloud.space/host': [{}], 'tinycloud.space/other': [{}] } },
      { '*': { 'tinycloud.space/host': [{}] } },
      { [`tinycloud:pkh:eip155:1:*:public/space`]: { 'tinycloud.space/host': [{}] } },
    ];
    for (const att of unreadable) {
      expect(spaceHostRequest(withResources(host('public'), att))).toEqual({ kind: 'unreadable' });
    }
  });

  test('a ReCap that mentions the host ability and cannot be read is unreadable', () => {
    const unreadable = host('public').replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from('not json tinycloud.space/host').toString('base64url')}`);
    expect(spaceHostRequest(unreadable)).toEqual({ kind: 'unreadable' });
  });

  const asHex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

  test('reads every JSON spelling of the same host capability as the same target, as text and as hex', () => {
    for (const name of ['default', 'public']) {
      for (const { label, json } of escapedHostSpellings(`${space(name)}/space`)) {
        const message = withRawRecap(host(name), json, `${space(name)}/space`);
        const expected: SpaceHostRequest = { kind: 'hosts', targets: [{ address, chainId: 1, name }] };
        expect([label, spaceHostRequest(message)]).toEqual([label, expected]);
        expect([label, spaceHostRequest(asHex(message))]).toEqual([label, expected]);
      }
    }
  });

  test('reads a space name spelled with a unicode escape as the name it decodes to', () => {
    const json = `{"att":{"${space('d\\u0065fault')}/space":{"tinycloud.space/host":[{}]}},"prf":[]}`;
    const message = withRawRecap(host('default'), json, `${space('default')}/space`);
    expect(spaceHostRequest(message)).toEqual({ kind: 'hosts', targets: [{ address, chainId: 1, name: 'default' }] });
  });

  test('an ability in another case, or with an escape that decodes to another case, is unreadable', () => {
    const resource = `${space('default')}/space`;
    const json = `{"att":{"${resource}":{"TINYCLOUD.SPACE/HOST":[{}]}},"prf":[]}`;
    expect(spaceHostRequest(withRawRecap(host('default'), json, resource, 'TINYCLOUD.SPACE/HOST'))).toEqual({ kind: 'unreadable' });
  });

  test('a ReCap with a repeated key, padded or standard base64, or a recap resource the parser rejects is unreadable', () => {
    const resource = `${space('default')}/space`;
    const message = host('default');
    const duplicate = `{"att":{"${resource}":{"tinycloud.space/host":[{}]},"${resource}":{"tinycloud.kv/get":[{}]}},"prf":[]}`;
    const json = JSON.stringify({ att: { [resource]: { 'tinycloud.space/host': [{}] } }, prf: [] });
    const encoded = Buffer.from(json).toString('base64url');
    const standard = Buffer.from(json).toString('base64');
    expect(spaceHostRequest(withRawRecap(message, duplicate, resource))).toEqual({ kind: 'unreadable' });
    expect(spaceHostRequest(message.replace(encoded, `${encoded}${'='.repeat((4 - (encoded.length % 4)) % 4 || 2)}`))).toEqual({ kind: 'unreadable' });
    expect(spaceHostRequest(message.replace(encoded, standard))).toEqual({ kind: 'unreadable' });
    expect(spaceHostRequest(message.replace(encoded, 'AAAA'))).toEqual({ kind: 'unreadable' });
  });

  test('a second recap resource is read with the first, never skipped', () => {
    const other = Buffer.from(JSON.stringify({ att: { [`${space('public')}/kv`]: { 'tinycloud.kv/get': [{}] } }, prf: [] })).toString('base64url');
    const message = host('default').replace(/(- urn:recap:[A-Za-z0-9_-]+)/, `$1\n- urn:recap:${other}`);
    // Whatever the parser makes of two recap resources, the answer is never "no space ability".
    expect(spaceHostRequest(message)).not.toEqual({ kind: 'none' });
  });

  test('a message that mentions a recap resource and is not a SIWE is unreadable', () => {
    expect(spaceHostRequest('hello urn:recap:eyJhdHQiOnt9fQ')).toEqual({ kind: 'unreadable' });
  });
});
