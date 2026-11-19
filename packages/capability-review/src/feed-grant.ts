// The three grants a feed connect step requests (js-sdk `tinycloud feed
// connect`, step 3b of the tinycloud-feed skill):
//
//   tinycloud.sql    applications  xyz.tinycloud.tinychat/home_feed   read, write, schema
//   tinycloud.sql    applications  xyz.tinycloud.tinychat/feed/       read, write, schema
//   tinycloud.hooks  applications  sql/xyz.tinycloud.tinychat/feed/  subscribe
//
// Each is recognized by its exact service, space, path and verb set, on the
// signer's own `applications` space. That tuple is what the sentence is
// derived from: the paths name the TinyCloud One feed databases whoever asks
// for them, so the sentence describes the resource, never the requester.
// Any other path, verb set, owner or service keeps the generic rows.

import { FEED_CARDS_STATEMENT, FEED_NOTIFY_STATEMENT, FEED_REGISTRY_STATEMENT } from "./copy.js";
import type { CapabilityGrant } from "./model.js";

interface FeedGrantShape {
  service: string;
  verbs: ReadonlySet<string>;
  statement: string;
}

const SQL_ALL = new Set(["read", "write", "schema"]);

const FEED_GRANTS: Record<string, FeedGrantShape> = {
  "xyz.tinycloud.tinychat/home_feed": { service: "tinycloud.sql", verbs: SQL_ALL, statement: FEED_REGISTRY_STATEMENT },
  "xyz.tinycloud.tinychat/feed/": { service: "tinycloud.sql", verbs: SQL_ALL, statement: FEED_CARDS_STATEMENT },
  "sql/xyz.tinycloud.tinychat/feed/": { service: "tinycloud.hooks", verbs: new Set(["subscribe"]), statement: FEED_NOTIFY_STATEMENT },
};

const OWN_APPLICATIONS_SPACE = /^tinycloud:pkh:eip155:\d+:0x[a-fA-F0-9]{40}:applications$/;

/** The consent sentence when `grant` is exactly one of the feed connect grants, else null. */
export function feedGrantStatement(grant: CapabilityGrant): string | null {
  if (!Object.hasOwn(FEED_GRANTS, grant.path)) return null;
  const shape = FEED_GRANTS[grant.path]!;
  if (
    grant.service !== shape.service ||
    grant.serviceMismatch === true ||
    grant.appScopeNearMiss === true ||
    grant.ownedBySelf !== true ||
    !OWN_APPLICATIONS_SPACE.test(grant.space)
  ) {
    return null;
  }
  const abilities = new Set(grant.actions.map((action) => action.ability));
  const exact = [...shape.verbs].every((verb) => abilities.has(`${shape.service}/${verb}`));
  return exact && abilities.size === shape.verbs.size ? shape.statement : null;
}
