// The Nostr custody capability contract matrix.
//
// Two jobs:
//  1. Make missing Buzz payload support mechanically obvious: every named
//     Buzz web journey lists the capabilities it needs, and the union of
//     those requirements must equal the capability model exactly - if a
//     journey's capability is dropped, or an unrequired capability sneaks
//     in, this file fails.
//  2. Keep the mirrors in sync: the web widget cannot import @openkey/tee
//     (browser deployable vs node-only crypto), so it carries a mirrored
//     copy of the model plus consent copy. Drift fails here.
import { describe, expect, test } from 'bun:test';
import {
  DESTINATION_BOUND_NOSTR_KINDS,
  NOSTR_CAPABILITY_VERSION,
  SUPPORTED_NOSTR_KINDS,
  SUPPORTED_NOSTR_OPERATIONS,
  type NostrOperation,
} from '../packages/tee/src/nostr-capabilities';
import {
  DESTINATION_BOUND_NOSTR_KINDS as WIDGET_DESTINATION_BOUND,
  NOSTR_CAPABILITY_VERSION as WIDGET_CAPABILITY_VERSION,
  NOSTR_KIND_COPY,
  NOSTR_OPERATION_COPY,
  SUPPORTED_NOSTR_KINDS as WIDGET_KINDS,
  SUPPORTED_NOSTR_OPERATIONS as WIDGET_OPERATIONS,
  type NostrOperationName,
} from '../apps/web/src/lib/nostr-capabilities';
import { POLICY_KINDS } from '../apps/api/src/services/nostr-event-policy';
import type { NostrOperation as SdkNostrOperation } from '../packages/sdk/src/nostr';

// Compile-time documentation: the SDK's operation type and the TEE's must be
// identical. (Neither bun test nor the per-package typecheck gates cover this
// root tests/ directory, so the enforced sync check is the runtime mirror
// comparison below; these assignments surface drift to anyone editing here.)
const _sdkToTee: NostrOperation = null as unknown as SdkNostrOperation;
const _teeToSdk: SdkNostrOperation = null as unknown as NostrOperation;
const _widgetToTee: NostrOperation = null as unknown as NostrOperationName;
void _sdkToTee; void _teeToSdk; void _widgetToTee;

/**
 * Every Buzz web client journey that needs custody cryptography, with the
 * exact capabilities it requires. Derived from the pinned Buzz sources
 * (buzz/web src/lib + workspace-state); see docs/nostr-signing.md.
 */
const BUZZ_JOURNEYS: Record<string, { kinds?: number[]; operations?: NostrOperation[] }> = {
  'profile metadata': { kinds: [0] },
  'reactions': { kinds: [7] },
  'channel messages (legacy)': { kinds: [9] },
  'channel messages (v2, with attachments and replies)': { kinds: [40002] },
  'content reports': { kinds: [1984] },
  'relay auth (NIP-42)': { kinds: [22242] },
  'Blossom media upload/get authorization': { kinds: [24242] },
  'NIP-98 HTTP auth for invites and moderation reads': { kinds: [27235] },
  'presence': { kinds: [20001] },
  'encrypted reminders': { kinds: [30300], operations: ['nip44_encrypt', 'nip44_decrypt'] },
  'DM open': { kinds: [41010] },
  'direct messages (NIP-59 gift wrap)': { operations: ['nip59_wrap', 'nip59_unwrap'] },
  'agent observer frames (decrypt-only)': { operations: ['nip44_decrypt'] },
  'relay membership administration': { kinds: [9030, 9031, 9032] },
  'moderation commands': { kinds: [9040, 9041, 9042, 9043, 9044] },
};

describe('Buzz journey coverage', () => {
  test('every journey capability is in the model (no unsupported journey)', () => {
    for (const [journey, needs] of Object.entries(BUZZ_JOURNEYS)) {
      for (const kind of needs.kinds ?? []) {
        expect({ journey, kind, supported: SUPPORTED_NOSTR_KINDS.has(kind) })
          .toEqual({ journey, kind, supported: true });
      }
      for (const operation of needs.operations ?? []) {
        expect({ journey, operation, supported: (SUPPORTED_NOSTR_OPERATIONS as readonly string[]).includes(operation) })
          .toEqual({ journey, operation, supported: true });
      }
    }
  });

  test('the model contains nothing a journey does not require (no scope creep)', () => {
    const requiredKinds = new Set(Object.values(BUZZ_JOURNEYS).flatMap((j) => j.kinds ?? []));
    const requiredOperations = new Set(Object.values(BUZZ_JOURNEYS).flatMap((j) => j.operations ?? []));
    expect(new Set(SUPPORTED_NOSTR_KINDS)).toEqual(requiredKinds);
    expect(new Set(SUPPORTED_NOSTR_OPERATIONS)).toEqual(requiredOperations);
  });

  test('the exact kind list is the reviewed Buzz matrix', () => {
    expect([...SUPPORTED_NOSTR_KINDS].sort((a, b) => a - b)).toEqual([
      0, 7, 9, 1984, 9030, 9031, 9032, 9040, 9041, 9042, 9043, 9044,
      20001, 22242, 24242, 27235, 30300, 40002, 41010,
    ]);
    expect([...SUPPORTED_NOSTR_OPERATIONS].sort()).toEqual([
      'nip44_decrypt', 'nip44_encrypt', 'nip59_unwrap', 'nip59_wrap',
    ]);
    expect([...DESTINATION_BOUND_NOSTR_KINDS].sort((a, b) => a - b)).toEqual([22242, 24242, 27235]);
  });
});

describe('mirror synchronization', () => {
  test('the API policy registry covers exactly the capability model kinds', () => {
    expect(POLICY_KINDS).toEqual(new Set(SUPPORTED_NOSTR_KINDS));
  });

  test('the widget mirror matches the capability model', () => {
    expect(WIDGET_CAPABILITY_VERSION).toBe(NOSTR_CAPABILITY_VERSION);
    expect(new Set(WIDGET_KINDS)).toEqual(new Set(SUPPORTED_NOSTR_KINDS));
    expect([...WIDGET_OPERATIONS].sort()).toEqual([...SUPPORTED_NOSTR_OPERATIONS].sort());
    expect(new Set(WIDGET_DESTINATION_BOUND)).toEqual(new Set(DESTINATION_BOUND_NOSTR_KINDS));
  });

  test('every capability has non-empty consent copy in the widget', () => {
    for (const kind of SUPPORTED_NOSTR_KINDS) {
      const copy = NOSTR_KIND_COPY[kind];
      expect({ kind, hasCopy: !!copy && copy.title.length > 0 && copy.description.length > 0 })
        .toEqual({ kind, hasCopy: true });
    }
    for (const operation of SUPPORTED_NOSTR_OPERATIONS) {
      const copy = NOSTR_OPERATION_COPY[operation];
      expect({ operation, hasCopy: !!copy && copy.title.length > 0 && copy.description.length > 0 })
        .toEqual({ operation, hasCopy: true });
    }
  });

  test('decrypt-exposing operations are marked sensitive in consent copy', () => {
    expect(NOSTR_OPERATION_COPY.nip44_decrypt.sensitive).toBe(true);
    expect(NOSTR_OPERATION_COPY.nip59_unwrap.sensitive).toBe(true);
  });
});
