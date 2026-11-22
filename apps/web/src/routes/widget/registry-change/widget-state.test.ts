// TC-3893: unit tests for the registry-change consent screen state machine,
// origin verification, diff table builder, identity warnings, and Monica copy.
//
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  REGISTRY_CHANGE_COPY,
  applyCancel,
  applyPrepareResult,
  applyPublishResult,
  applyRequestMessage,
  buildDiffView,
  buildIdentityWarnings,
  initialState,
  screenOriginLine,
  screenTitle,
  type PrepareResponseBody,
  type RegistryRecordPayloadView,
} from './widget-state';

const NODE_A = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const NODE_B = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH';
const SUBJECT = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const SPACE_DEFAULT = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
const SPACE_NOTES = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:notes';
const SPACE_NEW = 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:photos';

const BEFORE: RegistryRecordPayloadView = {
  version: 2,
  subject: SUBJECT,
  nodes: [{ did: NODE_A, url: 'https://node-a.example' }],
  spaces: [
    { space: SPACE_DEFAULT, nodes: [{ did: NODE_A, mode: 'read-write' }] },
    { space: SPACE_NOTES, nodes: [{ did: NODE_A, mode: 'read-write' }] },
  ],
  encryptionNode: NODE_A,
  updated_at: '2026-11-22T15:00:00.000Z',
  sequence: 2,
};

const AFTER: RegistryRecordPayloadView = {
  version: 2,
  subject: SUBJECT,
  nodes: [
    { did: NODE_A, url: 'https://node-a.example' },
    { did: NODE_B, url: 'https://[2001:db8::1]:8443' },
  ],
  spaces: [
    { space: SPACE_DEFAULT, nodes: [{ did: NODE_B, mode: 'read-write' }] },
    { space: SPACE_NOTES, nodes: [{ did: NODE_A, mode: 'read-write' }] },
    { space: SPACE_NEW, nodes: [{ did: NODE_B, mode: 'read-write' }] },
  ],
  encryptionNode: NODE_B,
  updated_at: '2026-11-22T16:00:00.000Z',
  sequence: 3,
};

describe('registry-change widget state machine', () => {
  test('captures verifiedRequestingOrigin exclusively from event.origin and ignores spoofed payload origin', () => {
    const counterparty = { postMessage: () => {} };
    const start = initialState(null);
    const next = applyRequestMessage(start, {
      origin: 'https://real-app.example',
      source: counterparty,
      counterparty,
      configuredOrigin: 'https://real-app.example',
      data: {
        type: 'openkey:registry-change:request',
        requestId: 'req-1',
        protocolVersion: 1,
        requestingOrigin: 'https://spoofed.example',
        origin: 'https://spoofed-2.example',
        request: {
          requestingOrigin: 'https://spoofed-nested.example',
          nodes: [{ url: 'https://node-b.example:8443' }],
        },
      },
    });

    expect(next.phase).toBe('preparing');
    expect(next.verifiedRequestingOrigin).toBe('https://real-app.example');
    expect(next.requestPayload).toEqual({ nodes: [{ url: 'https://node-b.example:8443' }] });
    expect('requestingOrigin' in (next.requestPayload ?? {})).toBe(false);

    // Sealed: a second message from another window/origin is ignored.
    const second = applyRequestMessage(next, {
      origin: 'https://other.example',
      source: {},
      counterparty,
      configuredOrigin: 'https://real-app.example',
      data: {
        type: 'openkey:registry-change:request',
        requestId: 'req-2',
        protocolVersion: 1,
        request: { nodes: [{ url: 'https://evil.example' }] },
      },
    });
    expect(second).toBe(next);
  });

  test('buildDiffView formats canonical hosts (incl. IPv6 + port), No change, Not set, and encryption row', () => {
    const view = buildDiffView(BEFORE, AFTER, true);
    expect(view.encryptionBeforeHost).toBe('node-a.example');
    expect(view.encryptionAfterHost).toBe('[2001:db8::1]:8443');
    expect(view.diffRows).toEqual([
      { label: 'default', beforeHost: 'node-a.example', afterHost: '[2001:db8::1]:8443', changed: true, isEncryption: false },
      { label: 'notes', beforeHost: 'node-a.example', afterHost: REGISTRY_CHANGE_COPY.noChange, changed: false, isEncryption: false },
      { label: 'photos', beforeHost: REGISTRY_CHANGE_COPY.notSet, afterHost: '[2001:db8::1]:8443', changed: true, isEncryption: false },
      { label: REGISTRY_CHANGE_COPY.encryptionRowLabel, beforeHost: 'node-a.example', afterHost: '[2001:db8::1]:8443', changed: true, isEncryption: true },
    ]);
  });

  test('buildIdentityWarnings formats Monica unreachable and mismatch warnings and skips ok nodes', () => {
    const warnings = buildIdentityWarnings([
      { url: 'https://ok.example', did: NODE_A, status: 'ok' },
      { url: 'https://192.0.2.5:8443', did: NODE_B, status: 'unreachable' },
      { url: 'https://bad-id.example', did: NODE_B, status: 'mismatch' },
    ]);
    expect(warnings).toEqual([
      {
        url: 'https://192.0.2.5:8443',
        host: '192.0.2.5:8443',
        status: 'unreachable',
        message: "Couldn't reach 192.0.2.5:8443 to confirm what it is.",
      },
      {
        url: 'https://bad-id.example',
        host: 'bad-id.example',
        status: 'mismatch',
        message: "bad-id.example doesn't match the identity it was listed with.",
      },
    ]);
  });

  test('handles prepare invalid URL, stale publish, success publish, and cancel', () => {
    const counterparty = {};
    const preparing = applyRequestMessage(initialState(null), {
      origin: 'https://app.example',
      source: counterparty,
      counterparty,
      configuredOrigin: 'https://app.example',
      data: {
        type: 'openkey:registry-change:request',
        requestId: 'req-9',
        protocolVersion: 1,
        request: { nodes: [{ url: 'https://node-b.example' }] },
      },
    });

    const invalid = applyPrepareResult(preparing, {
      ok: false,
      status: 400,
      body: { error: 'registry_change_invalid_node' },
    });
    expect(invalid.phase).toBe('invalid');
    expect(invalid.error).toBe(REGISTRY_CHANGE_COPY.refusedUrl);

    const preparedBody: PrepareResponseBody = {
      changeId: 'chg-1',
      requestingOrigin: 'https://app.example',
      before: BEFORE,
      after: AFTER,
      recordHash: 'b'.repeat(64),
      identity: [{ url: 'https://[2001:db8::1]:8443', did: NODE_B, status: 'unreachable' }],
      encryptionChanged: true,
      passkey: { required: true, challengeToken: 'tok-1', options: {} },
    };
    const review = applyPrepareResult(preparing, { ok: true, body: preparedBody });
    expect(review.phase).toBe('review');
    expect(review.encryptionChanged).toBe(true);
    expect(review.warnings).toHaveLength(1);

    const stale = applyPublishResult(review, {
      ok: false,
      status: 409,
      body: { error: 'registry_change_stale' },
    });
    expect(stale.state.phase).toBe('stale');
    expect(stale.postBack).toBeNull();

    const published = applyPublishResult(review, {
      ok: true,
      body: { sequence: 3, recordHash: 'b'.repeat(64) },
    });
    expect(published.state.phase).toBe('done');
    expect(published.postBack).toEqual({
      type: 'openkey:registry-change:response',
      requestId: 'req-9',
      protocolVersion: 1,
      success: true,
      status: 'published',
      sequence: 3,
      recordHash: 'b'.repeat(64),
    });

    const cancelled = applyCancel(review);
    expect(cancelled.state.phase).toBe('cancelled');
    expect(cancelled.postBack).toEqual({
      type: 'openkey:registry-change:response',
      requestId: 'req-9',
      protocolVersion: 1,
      success: true,
      status: 'cancelled',
    });
  });

  test('undo/restore variants show TinyCloud One only for One origins and use {origin} otherwise', () => {
    const counterparty = {};
    const undoFromOne = applyRequestMessage(initialState(null), {
      origin: 'https://tinycloud.one',
      source: counterparty,
      counterparty,
      configuredOrigin: 'https://tinycloud.one',
      data: {
        type: 'openkey:registry-undo:request',
        requestId: 'req-undo-1',
        protocolVersion: 1,
        historyId: 'hist-1',
      },
    });
    expect(undoFromOne.mode).toBe('undo');
    expect(undoFromOne.historyId).toBe('hist-1');

    const undoLastReview = applyPrepareResult(undoFromOne, {
      ok: true,
      body: {
        changeId: 'chg-undo-1',
        requestingOrigin: 'https://tinycloud.one',
        before: AFTER,
        after: BEFORE,
        recordHash: 'c'.repeat(64),
        identity: [{ url: 'https://node-a.example', did: NODE_A, status: 'ok' }],
        encryptionChanged: true,
        passkey: { required: true, challengeToken: 'tok-u1', options: {} },
        undoKind: 'undo-last',
        restoredBeforeDate: '2026-11-22T15:00:00.000Z',
      },
    });
    expect(screenTitle(undoLastReview)).toBe('Undo the last change?');
    expect(screenOriginLine(undoLastReview)).toBe(
      'TinyCloud One wants to undo the last change to where your data lives.',
    );
    // Removed space (`photos`) is shown as `[2001:db8::1]:8443` -> `Not set`.
    expect(undoLastReview.diffRows.find((r) => r.label === 'photos')).toEqual({
      label: 'photos',
      beforeHost: '[2001:db8::1]:8443',
      afterHost: 'Not set',
      changed: true,
      isEncryption: false,
    });

    const restoreReview = applyPrepareResult(undoFromOne, {
      ok: true,
      body: {
        changeId: 'chg-undo-2',
        requestingOrigin: 'https://tinycloud.one',
        before: AFTER,
        after: BEFORE,
        recordHash: 'c'.repeat(64),
        identity: [{ url: 'https://node-a.example', did: NODE_A, status: 'ok' }],
        encryptionChanged: true,
        passkey: { required: true, challengeToken: 'tok-u2', options: {} },
        undoKind: 'restore',
        restoredBeforeDate: '2026-11-20T12:00:00.000Z',
      },
    });
    expect(screenTitle(restoreReview)).toBe('Restore an earlier version?');
    expect(screenOriginLine(restoreReview)).toBe(
      'TinyCloud One wants to put back where your data lived before 2026-11-20.',
    );

    // Non-One origin never renders "TinyCloud One".
    expect(
      screenOriginLine({
        mode: 'undo',
        undoKind: 'restore',
        verifiedRequestingOrigin: 'https://other.example',
        restoredBeforeDate: '2026-11-20T12:00:00.000Z',
      }),
    ).toBe('https://other.example wants to put back where your data lived before 2026-11-20.');
  });
});
