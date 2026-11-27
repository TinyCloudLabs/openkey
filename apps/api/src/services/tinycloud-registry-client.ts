// TC-3657: OpenKey server's V2 location-registry client. Writes the owner's
// `did:pkh`-signed location record using `@tinycloud/sdk-core@3.12.0-beta.22`'s
// publication primitives (already a prod dep per `apps/api/package.json`;
// subpath, so no existing registry client needs extending here).
//
// The server builds the canonical payload from inputs it fully controls:
//   - `subject`: owner's `did:pkh` from the authenticated session.
//   - `nodes`: the pair returned by `defaultTinyCloudBootstrapNode()` (env +
//     allowlisted); caller cannot influence.
//   - `spaces`: the owner's primary space URI, derived from the owner's
//     did:pkh + a fixed space name; caller cannot influence.
// None of `requestingApp.name` / `requestingApp.manifest` is read here; those fields are
// displayed on the setup screen as caller-asserted claims and never enter the record.

import {
  DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL,
  canonicalLocationPayloadV2,
  validateLocationRecordV2Payload,
  type LocationRecordSigner,
  type LocationRecordV2,
  type LocationRecordV2Payload,
} from '@tinycloud/sdk-core';
import { publishLocationRecordV2 } from '@tinycloud/sdk-core/registry-publication';
import { createHash } from 'node:crypto';
import type { TinyCloudBootstrapNode } from './tinycloud-hosts';

/** Fixed space name used for the brand-new owner's primary space. Keep in step with the
 *  web-sdk's primary-space convention (TC-3547 §3.3). The server never accepts a caller-supplied
 *  space; any customisation must come as a follow-up config change, never from the request body. */
export const TINYCLOUD_SETUP_PRIMARY_SPACE = 'default';

export interface TinyCloudSetupRecordInputs {
  readonly subject: string;                // did:pkh:eip155:<chainId>:<EIP-55 address>
  readonly node: TinyCloudBootstrapNode;   // from defaultTinyCloudBootstrapNode()
  readonly primarySpace?: string;          // override for tests; default `TINYCLOUD_SETUP_PRIMARY_SPACE`
  readonly now?: Date;                     // override for tests
}

/** Builds the exact canonical payload the server will sign. Returns the payload + the hex sha256
 *  the setup ticket binds to (the ticket must be bound to the record hash). The returned
 *  payload is immediately ready for `signLocationRecordV2` or `publishLocationRecordV2`. */
export function buildTinyCloudSetupPayload(inputs: TinyCloudSetupRecordInputs): { payload: LocationRecordV2Payload; canonical: string; hash: string; space: string } {
  const spaceName = inputs.primarySpace ?? TINYCLOUD_SETUP_PRIMARY_SPACE;
  const pkhMatch = /^did:pkh:eip155:([1-9][0-9]*):(0x[a-fA-F0-9]{40})$/.exec(inputs.subject);
  if (!pkhMatch) throw new Error('tinycloud setup: subject must be a did:pkh eip155 EIP-55 address');
  const chainId = pkhMatch[1];
  const address = pkhMatch[2]!.toLowerCase();
  const space = `tinycloud:pkh:eip155:${chainId}:${address}:${spaceName}`;
  const payload = validateLocationRecordV2Payload({
    version: 2,
    subject: inputs.subject,
    nodes: [{ did: inputs.node.nodeDid, url: inputs.node.origin }],
    spaces: [{ space, nodes: [{ did: inputs.node.nodeDid, mode: 'read-write' }] }],
    encryptionNode: null,
    updated_at: (inputs.now ?? new Date()).toISOString(),
    sequence: 0,
  });
  const canonical = canonicalLocationPayloadV2(payload);
  const hash = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return { payload, canonical, hash, space };
}

export interface TinyCloudSetupPublishInputs extends TinyCloudSetupRecordInputs {
  readonly signer: LocationRecordSigner;
  readonly registryUrl?: string;
  readonly fetch?: typeof fetch;
  /** Optional stricter fence; the default already refuses when `current !== null`, but the
   *  route layers an `onPrepared` that also asserts `sha256(canonical(prepared)) === recordHash`
   *  so the bytes we're about to sign exactly match what the ticket was bound to. */
  readonly onPrepared?: (prepared: LocationRecordV2Payload, current: LocationRecordV2 | null) => Promise<boolean> | boolean;
}

/** Publishes the setup record. Fails loudly on any mismatch (no-overwrite fence via
 *  `onPrepared: current === null`; TC-3547's own fence). The caller must have already minted
 *  + consumed a setup ticket bound to this subject + verified origin + the payload's hash. */
export async function publishTinyCloudSetupRecord(inputs: TinyCloudSetupPublishInputs): Promise<LocationRecordV2> {
  const { payload } = buildTinyCloudSetupPayload(inputs);
  return publishLocationRecordV2({
    registryUrl: inputs.registryUrl ?? DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL,
    subject: inputs.subject,
    signer: inputs.signer,
    memberships: payload.spaces.map((space) => ({
      space: space.space,
      node: { did: inputs.node.nodeDid, url: inputs.node.origin },
      mode: 'read-write',
    })),
    // Hard fence: refuse the publish if any record now exists for the owner.
    onPrepared: inputs.onPrepared ?? (async (_prepared, current) => current === null),
    ...(inputs.fetch ? { fetch: inputs.fetch } : {}),
    ...(inputs.now ? { now: () => inputs.now! } : {}),
  });
}
