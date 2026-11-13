import { test, expect } from 'bun:test';
import { Wallet } from 'ethers';
import { createResourceDeletionClient, DeletionNeedsOwnerReview } from './account-deletion-resource-http';
import type { DeletionHttpTransport } from './account-deletion-list-http';
const host = { hostId: 'node-test', url: 'https://node.example.test' };

test('resource routes sign exact host/owner/target and follow complete inventory', async () => {
  const wallet = Wallet.createRandom();
  const owner = `did:pkh:eip155:1:${wallet.address}`;
  const network = `urn:tinycloud:encryption:${owner}:default`;
  const key = `${network}/apps/example/key`;
  const purgeId = crypto.randomUUID();
  const operation = crypto.randomUUID();
  const requestKeys: string[] = [];
  const nonces = new Set<string>();
  const transport: DeletionHttpTransport = async (url, options) => {
    expect(options.redirect).toBe('error');
    const path = new URL(url).pathname;
    const body = JSON.parse(options.body as string);
    const headers = new Headers(options.headers);
    requestKeys.push(headers.get('Idempotency-Key')!);
    const invocation = JSON.parse(Buffer.from(headers.get('Authorization')!.split('.')[1]!, 'base64url').toString());
    nonces.add(invocation.nnc);
    const mutating = path.startsWith('/resource/purge');
    expect(invocation.att).toEqual({ [mutating ? key : owner]: { [mutating ? 'tinycloud.resource/delete' : path.endsWith('/list') ? 'tinycloud.resource/list' : 'tinycloud.resource/dependencies']: [{}] } });
    expect(invocation.fct).toEqual([{ idempotency_key: headers.get('Idempotency-Key'), hostId: host.hostId }]);
    if (path.endsWith('/list')) {
      expect(body.ownerDid).toBe(owner);
      return Response.json({ version: 1, hostId: host.hostId, ownerDid: owner, resources: [body.cursor === null ? network : key], nextCursor: body.cursor === null ? 'opaque' : null, lastPage: body.cursor !== null });
    }
    if (path.endsWith('/dependencies')) return Response.json({ version: 1, hostId: host.hostId, ownerHmac: 'a'.repeat(64), dependentResourceCount: 2, resourceHmacs: ['a'.repeat(64), 'b'.repeat(64)], targets: [ { resourceId: network, targetResourceHmac: 'a'.repeat(64), dependentCount: 1, dependencyFingerprint: 'c'.repeat(64), fingerprintKeyId: 'fingerprint-1' }, { resourceId: key, targetResourceHmac: 'b'.repeat(64), dependentCount: 1, dependencyFingerprint: 'd'.repeat(64), fingerprintKeyId: 'fingerprint-1' } ] });
    expect(body.resource_id).toBe(key);
    if (path.endsWith('/status')) expect(body.purge_id).toBe(purgeId);
    return Response.json({ version: 1, hostId: host.hostId, purge_id: purgeId, state: path.endsWith('/status') ? 'complete' : 'purging', accepted_at: '2026-11-13T00:00:00Z', updated_at: '2026-11-13T00:00:00Z' }, { status: path.endsWith('/status') ? 200 : 202 });
  };
  const client = createResourceDeletionClient(host, wallet.privateKey, transport);
  expect(await client.inventory()).toEqual([network, key]);
  const dependencies = await client.dependencies([network, key]);
  expect(dependencies.dependentResourceCount).toBe(2);
  expect(dependencies.targets[1]?.resourceId).toBe(key);
  expect((await client.purge(key, operation)).complete).toBe(false);
  await client.purge(key, operation);
  expect((await client.status(key, purgeId)).complete).toBe(true);
  expect(requestKeys[3]).toBe(operation);
  expect(requestKeys[4]).toBe(operation);
  expect(requestKeys[5]).not.toBe(operation);
  expect(nonces.size).toBe(6);
});

test('resource dependency conflict requires owner review; mismatched host cannot authorize it', async () => {
  const wallet = Wallet.createRandom();
  const resource = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:default`;
  const conflict = (hostId: string) => createResourceDeletionClient(host, wallet.privateKey, async () => Response.json({ error: { code: 'dependency_review_required' }, hostId }, { status: 409 }));
  await expect(conflict(host.hostId).purge(resource, crypto.randomUUID())).rejects.toBeInstanceOf(DeletionNeedsOwnerReview);
  await expect(conflict('wrong').purge(resource, crypto.randomUUID())).rejects.toThrow('Resource host mismatch');
});

test('incomplete resource pages, unknown dependency state and wrong-owner URNs stay pending', async () => {
  const wallet = Wallet.createRandom();
  const owner = `did:pkh:eip155:1:${wallet.address}`;
  const client = createResourceDeletionClient(host, wallet.privateKey, async () => Response.json({ version: 1, hostId: host.hostId, ownerDid: owner, resources: [], nextCursor: null, lastPage: false }));
  await expect(client.inventory()).rejects.toThrow();
  await expect(client.dependencies([])).rejects.toThrow();
  await expect(client.purge('urn:tinycloud:encryption:did:pkh:eip155:1:other:default', crypto.randomUUID())).rejects.toThrow();
});

test('resource purge carries authenticated proof unchanged without inventing authority', async () => {
  const wallet = Wallet.createRandom();
  const resource = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:default`;
  const fixture = await Bun.file(new URL('./fixtures/account-deletion-decision-jcs.json', import.meta.url)).json();
  const proof = fixture.vectors[0].proof;
  const client = createResourceDeletionClient(host, wallet.privateKey, async (_url, options) => {
    expect(JSON.parse(options.body as string).decisionProof).toEqual(proof);
    // Transporting a proof grants nothing locally: the node must verify it.
    return Response.json({ error: { code: 'dependency_review_required' }, hostId: host.hostId }, { status: 409 });
  });
  await expect(client.purge(resource, crypto.randomUUID(), proof)).rejects.toBeInstanceOf(DeletionNeedsOwnerReview);
});
