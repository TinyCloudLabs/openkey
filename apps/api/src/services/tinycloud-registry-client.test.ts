import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalLocationPayloadV2 } from '@tinycloud/sdk-core';
import { buildTinyCloudSetupPayload, TINYCLOUD_SETUP_PRIMARY_SPACE } from './tinycloud-registry-client';

const NODE = { nodeDid: 'did:key:z6MkmTNB9HkpvhCzsx6QYbzYuM3CpeoxztrLkTkHs4QefXjH', origin: 'https://node.test.local' };
const SUBJECT = 'did:pkh:eip155:1:0x00000000000000000000000000000000000000AA';
const FIXED_NOW = new Date('2026-11-21T14:00:00.000Z');

test('buildTinyCloudSetupPayload produces a canonical payload the server can sign', () => {
  const { payload, canonical, hash, space } = buildTinyCloudSetupPayload({ subject: SUBJECT, node: NODE, now: FIXED_NOW });
  assert.equal(payload.subject, SUBJECT);
  assert.deepEqual(payload.nodes, [{ did: NODE.nodeDid, url: NODE.origin }]);
  assert.equal(payload.spaces.length, 1);
  assert.equal(payload.spaces[0]?.space, space);
  assert.deepEqual(payload.spaces[0]?.nodes, [{ did: NODE.nodeDid, mode: 'read-write' }]);
  assert.equal(payload.encryptionNode, null);
  assert.equal(payload.sequence, 0);
  assert.equal(payload.updated_at, FIXED_NOW.toISOString());
  // Hash is the sha256 of the canonical bytes — the setup ticket binds to this exact value.
  assert.equal(hash, createHash('sha256').update(canonical, 'utf8').digest('hex'));
  // The space URI is derived from the subject and the fixed primary space name; no caller
  // field can shape it. Nothing from `requestingApp` enters the signed record.
  assert.equal(space, `tinycloud:pkh:eip155:1:${SUBJECT.split(':').pop()!.toLowerCase()}:${TINYCLOUD_SETUP_PRIMARY_SPACE}`);
});

test('the canonical bytes match sdk-core canonicalLocationPayloadV2 exactly', () => {
  const { payload, canonical } = buildTinyCloudSetupPayload({ subject: SUBJECT, node: NODE, now: FIXED_NOW });
  assert.equal(canonical, canonicalLocationPayloadV2(payload));
});

test('refuses a non-eip155 did:pkh subject', () => {
  let threw = false;
  try {
    buildTinyCloudSetupPayload({ subject: 'did:key:z6MkmTNB', node: NODE });
  } catch { threw = true; }
  assert.equal(threw, true);
});
