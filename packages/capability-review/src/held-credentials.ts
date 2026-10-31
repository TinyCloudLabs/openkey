// The ONE request the review names: credentials.org's held-credentials grant.
//
//   service  tinycloud.kv
//   space    the signer's own `credentials` space on eip155:1 (the chain the request names)
//   path     `v1/held/`
//   actions  exactly get, list, put, del
//
// This is a single exact request, not a rule about spaces or paths. Every
// deviation (another space, another owner, an unproven owner, any other path
// spelling, one action more or fewer, an alias such as `delete`, a short-form
// ability, a service mismatch) is NOT this shape and keeps the generic
// fallback. classify.ts and statements.ts both call this predicate so they
// cannot drift apart. The grant stays family `unknown`, so its severity is
// unchanged; only the words change.

const HELD_SPACE = /^tinycloud:pkh:eip155:1:0x[a-fA-F0-9]{40}:credentials$/;
const HELD_SERVICE = "tinycloud.kv";
const HELD_PATH = "v1/held/";
const HELD_ABILITIES: Record<string, true> = {
  "tinycloud.kv/get": true,
  "tinycloud.kv/list": true,
  "tinycloud.kv/put": true,
  "tinycloud.kv/del": true,
};
const HELD_ABILITY_COUNT = 4;

export interface HeldCredentialsCandidate {
  service: string;
  space: string;
  path: string;
  /** Fully qualified abilities, e.g. `tinycloud.kv/get`. */
  abilities: readonly string[];
  /** Ability-derived and resource-derived services disagree on the wire. */
  serviceMismatch?: boolean;
  /** Both the space owner and the signer are known and equal. */
  ownedBySigner: boolean;
}

export function isHeldCredentialsGrant(candidate: HeldCredentialsCandidate): boolean {
  if (candidate.serviceMismatch === true) return false;
  if (!candidate.ownedBySigner) return false;
  if (candidate.service !== HELD_SERVICE) return false;
  if (!HELD_SPACE.test(candidate.space)) return false;
  if (candidate.path !== HELD_PATH) return false;
  return (
    candidate.abilities.length === HELD_ABILITY_COUNT &&
    new Set(candidate.abilities).size === HELD_ABILITY_COUNT &&
    candidate.abilities.every((ability) => Object.hasOwn(HELD_ABILITIES, ability))
  );
}
