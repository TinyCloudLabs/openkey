// The Inbox one-sign-in request (TC-2230 plan, section 2.1): one ReCap over
// the owner's `messages` and `public` spaces and the `inbox` encryption
// network. Built by hand from the plan's table until the SDK-composed fixture
// from Inbox slice 3 exists. `recipientsResource` builds the
// `urn:tinycloud:recipients:` line the plan proposed, which OpenKey does not
// interpret: tests use it to show such a line changes nothing.

import { FIXTURE_META, makeRecapResource, siweWithResources } from "./index.js";

export const INBOX_OWNER = FIXTURE_META.address;
export const INBOX_SERVICE_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
export const INBOX_READER_DID = "did:key:z6MkfrQREa6VNDWqixj3YWnRTjA3ZRRMd1PQLtRDPvsUGB6p";

export const M = `tinycloud:pkh:eip155:1:${INBOX_OWNER}:messages`;
export const P = `tinycloud:pkh:eip155:1:${INBOX_OWNER}:public`;
export const N = `urn:tinycloud:encryption:did:pkh:eip155:1:${INBOX_OWNER}:inbox`;

const KV = ["get", "put", "del", "list", "metadata"].map((v) => `tinycloud.kv/${v}`);
const SQL = ["read", "write", "schema"].map((v) => `tinycloud.sql/${v}`);

/** ReCap `att`: resource URI → ability → caveats. */
export type Att = Record<string, Record<string, unknown[]>>;

function abilities(list: readonly string[]): Record<string, unknown[]> {
  return Object.fromEntries(list.map((ability) => [ability, [{}]]));
}

/** The signed ReCap of a sign-in. `firstSetup` adds the two `tinycloud.space/host` rows. */
export function inboxAtt(options: { firstSetup?: boolean } = {}): Att {
  return {
    [`${M}/sql/xyz.tinycloud.inbox/data`]: abilities(SQL),
    [`${M}/kv/xyz.tinycloud.inbox/media/`]: abilities(KV),
    [`${M}/kv/xyz.tinycloud.inbox/sessions/`]: abilities(KV),
    [`${M}/sql/xyz.tinycloud.inbox/triage`]: abilities(SQL),
    [N]: abilities(["tinycloud.encryption/decrypt", "tinycloud.encryption/network.create"]),
    [`${M}/capabilities`]: abilities(["tinycloud.capabilities/read"]),
    [`${P}/capabilities`]: abilities(["tinycloud.capabilities/read"]),
    [`${P}/kv/xyz.tinycloud.inbox/grants/`]: abilities(["tinycloud.kv/put"]),
    ...(options.firstSetup
      ? { [`${M}/space`]: abilities(["tinycloud.space/host"]), [`${P}/space`]: abilities(["tinycloud.space/host"]) }
      : {}),
  };
}

export type Tuple = [service: string, space: string, path: string, ability: string];

const tuples = (service: string, space: string, path: string, list: readonly string[]): Tuple[] =>
  list.map((ability) => [service, space, path, ability]);

/** What the plan's table gives each child. */
export function inboxRecipients(): Array<{ label: string; did: string; grants: Tuple[] }> {
  return [
    {
      label: "Inbox service",
      did: INBOX_SERVICE_DID,
      grants: [
        ...tuples("tinycloud.sql", M, "xyz.tinycloud.inbox/data", SQL),
        ...tuples("tinycloud.kv", M, "xyz.tinycloud.inbox/media/", KV),
        ...tuples("tinycloud.kv", M, "xyz.tinycloud.inbox/sessions/", KV),
        ["tinycloud.encryption", N, "", "tinycloud.encryption/decrypt"],
      ],
    },
    {
      label: "Fred's reader",
      did: INBOX_READER_DID,
      grants: [
        ["tinycloud.sql", M, "xyz.tinycloud.inbox/data", "tinycloud.sql/read"],
        ...tuples("tinycloud.kv", M, "xyz.tinycloud.inbox/media/", ["tinycloud.kv/get", "tinycloud.kv/list", "tinycloud.kv/metadata"]),
        ...tuples("tinycloud.sql", M, "xyz.tinycloud.inbox/triage", SQL),
      ],
    },
  ];
}

function base64Url(text: string): string {
  return Buffer.from(text, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A `urn:tinycloud:recipients:` resource for any JSON value, so tests can build malformed ones. */
export function recipientsResource(value: unknown): string {
  return `urn:tinycloud:recipients:${base64Url(typeof value === "string" ? value : JSON.stringify(value))}`;
}

/** The sign-in SIWE: any extra resource lines (`declarations`) first and the ReCap last. */
export function inboxSignIn(options: {
  att?: Att;
  declarations?: string[];
  recaps?: string[];
} = {}): string {
  const declarations = options.declarations ?? [];
  const recaps = options.recaps ?? [makeRecapResource(options.att ?? inboxAtt())];
  return siweWithResources([...declarations, ...recaps], { domain: "inbox.tinycloud.xyz" });
}
