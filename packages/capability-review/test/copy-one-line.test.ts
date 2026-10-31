// Every permission descriptor is one line on a phone (Sam, 2026-10-29; see
// ../README.md). Fails when a descriptor, statement, label or template is
// longer than one line, unless it is a named two-line exception below.
//
// LINE_LIMIT: measured on the real sheet at 390x844 (iPhone 12 to 16 width).
// A statement line there is 330px wide, set in 13px semibold system font,
// which averages 6.4px a character: 52 characters fit. 50 leaves room for
// wider glyphs. Two lines is 100. A row with the "Sensitive" pill has about
// 40 characters before it wraps.
//
// Checks:
// - every prose string literal in the copy sources (it starts with a capital
//   letter and has a space); a `{path}`, `{network}`, `{owner}`, `{data}` or
//   `${...}` placeholder counts as PLACEHOLDER_CHARS, the length of a short
//   name such as `notes/k1`;
// - every row and label the review renders for every combination of a
//   service's registry abilities in one request (each alone, each pair, up to
//   all of them), on the signer's own space and on another user's. This
//   covers rows composed from several actions (the fallback row).
//
// The one exemption: a row marked `showsRawText` lists unknown or
// mismatched actions raw. It is a safety display, not a descriptor: it must
// show every raw action, and may wrap. No registered-only request may
// produce one.

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { CAPABILITY_REGISTRY } from "@tinycloud/bootstrap";

import { buildStatements, parseCapabilityReview, type StatementEntry } from "../src/index.js";
import {
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from "./fixtures/index.js";

const LINE_LIMIT = 50;
const TWO_LINE_LIMIT = 100;
const PLACEHOLDER_CHARS = 8;

/**
 * Descriptors allowed a second line: exact source text (placeholders as in
 * the source) to a one-line reason. Keep this list short.
 */
const TWO_LINE_EXCEPTIONS: Record<string, string> = {
  "Open all your shared files, including ones you share later.":
    "Sam approved this exact future-share explanation on 2026-10-31 (ask/openkey-388-share-approval).",
};

const COPY_SOURCES = ["copy.ts", "statements.ts", "core-operations.ts", "classify.ts", "plain-words.ts"];

interface Descriptor {
  where: string;
  text: string;
  length: number;
  /** The row's `showsRawText` flag; such rows are exempt from the limit. */
  raw?: true;
}

function sourceDescriptors(): Descriptor[] {
  const found: Descriptor[] = [];
  for (const file of COPY_SOURCES) {
    const path = fileURLToPath(new URL(`../src/${file}`, import.meta.url));
    const source = ts.createSourceFile(file, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node): void => {
      let text: string | null = null;
      let placeholders = 0;
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        text = node.text;
      } else if (ts.isTemplateExpression(node)) {
        text = node.head.text + node.templateSpans.map((span) => "${}" + span.literal.text).join("");
        placeholders = node.templateSpans.length;
        for (const span of node.templateSpans) visit(span.expression);
      }
      if (text !== null && /^[A-Z]/.test(text) && text.includes(" ")) {
        const named = text.match(/\{(path|network|owner|data)\}/g)?.length ?? 0;
        const fixed = text.replace(/\$\{\}|\{(path|network|owner|data)\}/g, "").length;
        const line = source.getLineAndCharacterOfPosition(node.getStart()).line + 1;
        found.push({
          where: `src/${file}:${line}`,
          text,
          length: fixed + (placeholders + named) * PLACEHOLDER_CHARS,
        });
      }
      if (!ts.isTemplateExpression(node)) ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return found;
}

const ACCOUNT = FIXTURE_META.address;
const OTHER = "0x2222222222222222222222222222222222222222";
const space = (name: string, owner: string) =>
  `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${owner}:${name}`;

// The resources each service is normally requested on. Encryption is also
// requested on its network URN.
const RESOURCES: Record<string, Array<(owner: string) => string>> = {
  "tinycloud.kv": [(owner) => `${space("default", owner)}/kv/notes/`],
  "tinycloud.sql": [(owner) => `${space("default", owner)}/sql/notes`],
  "tinycloud.duckdb": [(owner) => `${space("default", owner)}/duckdb/analytics`],
  "tinycloud.vfs": [(owner) => `${space("default", owner)}/vfs/photos`],
  "tinycloud.hooks": [(owner) => `${space("default", owner)}/hooks/notes/`],
  "tinycloud.capabilities": [(owner) => `${space("default", owner)}/capabilities`],
  "tinycloud.delegation": [(owner) => `${space("account", owner)}/delegation`],
  "tinycloud.encryption": [
    (owner) => `${space("default", owner)}/encryption`,
    (owner) => `urn:tinycloud:encryption:did:pkh:eip155:${FIXTURE_META.chainId}:${owner}:default`,
  ],
  "tinycloud.space": [(owner) => `${space("courier", owner)}/space`],
};

// Registered encryption key abilities the node registry does not list.
const KEY_ABILITIES = [
  "tinycloud.encryption/key.create",
  "tinycloud.encryption/key.block",
  "tinycloud.encryption/key.unblock",
];

/** Every non-empty subset of `items`, in a stable order. */
function subsets<T>(items: readonly T[]): T[][] {
  return items.reduce<T[][]>((all, item) => [...all, ...all.map((set) => [...set, item])], [[]]).slice(1);
}

function review(resource: string, abilities: readonly string[]) {
  return parseCapabilityReview({
    message: siweWithResources([
      makeRecapResource({ [resource]: Object.fromEntries(abilities.map((ability) => [ability, [{}]])) }),
    ]),
    signer: { label: "Signer", address: ACCOUNT, chainId: FIXTURE_META.chainId, provenance: "managed" },
    editable: true,
    metadataTrust: { status: "unsigned", reason: "no manifest" },
    reason: { text: "", source: "none" },
    requester: {
      displayName: "cli.tinycloud.xyz",
      verifiedOrigin: "https://cli.tinycloud.xyz",
      appId: null,
      manifestName: null,
      manifestNameProvenance: "none",
      manifestId: null,
      manifestIdProvenance: "none",
      manifestDigest: null,
      domainWarning: false,
      originWarning: false,
    },
  });
}

interface Combination {
  where: string;
  requested: string[];
  other: boolean;
  grants: Array<{ label: string; composedLabel: boolean; rows: StatementEntry[] }>;
}

/**
 * Every non-empty combination of a service's abilities in one request, on
 * each of its resources, on the signer's own space and on another user's.
 * `extraAbility` adds one more ability to every request.
 */
function combinations(extraAbility?: (service: string) => string): Combination[] {
  const found: Combination[] = [];
  const services = [...new Set(CAPABILITY_REGISTRY.map((entry) => entry.service))];
  for (const service of services) {
    const resources = RESOURCES[service];
    if (!resources) throw new Error(`No resource for registry service ${service}; add it to RESOURCES`);
    const abilities = [
      ...CAPABILITY_REGISTRY.filter((entry) => entry.service === service).map((entry) => entry.urn),
      ...(service === "tinycloud.encryption" ? KEY_ABILITIES : []),
    ];
    for (const resource of resources) {
      for (const owner of [ACCOUNT, OTHER]) {
        const singleLabels = new Set(
          abilities.flatMap((ability) => review(resource(owner), [ability]).permissions.map((g) => g.displayLabel)),
        );
        for (const set of subsets(abilities)) {
          const requested = extraAbility ? [...set, extraAbility(service)] : set;
          found.push({
            where: `${resource(owner)} [${requested.join(", ")}]`,
            requested,
            other: owner === OTHER,
            grants: review(resource(owner), requested).permissions.map((grant) => ({
              label: grant.displayLabel,
              // A title no single ability of the request has was composed from several.
              composedLabel: requested.length > 1 && !singleLabels.has(grant.displayLabel),
              rows: buildStatements(grant),
            })),
          });
        }
      }
    }
  }
  return found;
}

function renderedDescriptors(extraAbility?: (service: string) => string): Descriptor[] {
  return combinations(extraAbility).flatMap((c) =>
    c.grants.flatMap((grant) => [
      { where: `${c.where} label`, text: grant.label, length: grant.label.length },
      ...grant.rows.map((row) => ({
        where: c.where,
        text: row.primaryText,
        length: row.primaryText.length,
        ...(row.showsRawText ? { raw: true as const } : {}),
      })),
    ]),
  );
}

/**
 * Consequences a row must never lose when it names several actions: each is
 * carried by these abilities, and named by a word matching `keyword`.
 */
const CONSEQUENCES: Array<{ name: string; abilities: string[]; keyword: RegExp }> = [
  {
    name: "delete",
    abilities: [
      "tinycloud.kv/del",
      "tinycloud.kv/delete",
      "tinycloud.sql/schema",
      "tinycloud.sql/*",
      "tinycloud.vfs/delete",
      "tinycloud.duckdb/import",
      "tinycloud.duckdb/*",
    ],
    keyword: /\b(delete|replace|anything)\b/i,
  },
  { name: "decrypt", abilities: ["tinycloud.encryption/decrypt"], keyword: /\bdecrypt\b/i },
  {
    name: "block or unblock keys",
    abilities: ["tinycloud.encryption/key.block", "tinycloud.encryption/key.unblock"],
    keyword: /\b(un)?block\b/i,
  },
  { name: "create keys", abilities: ["tinycloud.encryption/key.create"], keyword: /\bcreate\b/i },
  { name: "send outward (webhook)", abilities: ["tinycloud.hooks/register"], keyword: /\b(share|send)\b/i },
  {
    name: "decryption network",
    abilities: ["tinycloud.encryption/network.create", "tinycloud.encryption/network.revoke"],
    keyword: /\b(decryption|encryption)\b/i,
  },
];
const ANOTHER_USER = /\banother user's\b/i;

/** Every consequence a combination's rows (together) or composed title fail to name. */
function lostConsequences(c: Combination): string[] {
  const lost: string[] = [];
  for (const grant of c.grants) {
    const summary = grant.rows.map((row) => row.primaryText).join(" | ");
    const texts = [["rows", summary], ...(grant.composedLabel ? [["title", grant.label]] : [])];
    for (const consequence of CONSEQUENCES) {
      if (!c.requested.some((ability) => consequence.abilities.includes(ability))) continue;
      for (const [what, text] of texts) {
        if (!consequence.keyword.test(text!)) lost.push(`${c.where} ${what} drop ${consequence.name}: ${text}`);
      }
    }
    if (c.other) {
      for (const row of grant.rows) {
        if (!ANOTHER_USER.test(row.primaryText)) lost.push(`${c.where} row drops another user's: ${row.primaryText}`);
      }
      if (grant.composedLabel && !ANOTHER_USER.test(grant.label)) {
        lost.push(`${c.where} title drops another user's: ${grant.label}`);
      }
    }
  }
  return lost;
}

function overLimit(descriptors: Descriptor[]): string[] {
  return descriptors
    .filter((d) => {
      if (d.raw) return false;
      const limit = Object.hasOwn(TWO_LINE_EXCEPTIONS, d.text) ? TWO_LINE_LIMIT : LINE_LIMIT;
      return d.length > limit;
    })
    .map((d) => `${d.where} (${d.length} chars): ${d.text}`);
}

describe("permission copy is one line", () => {
  const source = sourceDescriptors();

  it("scans the copy sources", () => {
    // A guard against a scan that silently finds nothing.
    expect(source.length).toBeGreaterThan(100);
  });

  it(`every descriptor in the copy sources fits ${LINE_LIMIT} characters`, () => {
    expect(overLimit(source)).toEqual([]);
  });

  it(`every row and label rendered for any mix of registry abilities fits ${LINE_LIMIT} characters`, () => {
    const rendered = renderedDescriptors();
    expect(rendered.filter((d) => d.raw).map((d) => `${d.where}: ${d.text}`)).toEqual([]);
    expect(overLimit(rendered)).toEqual([]);
  });

  it("a row or composed title never loses deletion, decryption, key, sharing or another user's data", () => {
    expect(combinations().flatMap(lostConsequences)).toEqual([]);
  });

  it("a row with an unknown action is marked raw and shows that action", () => {
    // The registered-only test above proves no other row is marked raw.
    const cases = combinations((service) => `${service}/tc2216-unknown`);
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      for (const row of c.grants.flatMap((grant) => grant.rows)) {
        expect(row.showsRawText, c.where).toBe(true);
        expect(row.primaryText, c.where).toContain(c.requested.at(-1)!);
      }
    }
  });

  it("every two-line exception is still in the source, needs the second line, and has a reason", () => {
    for (const [text, reason] of Object.entries(TWO_LINE_EXCEPTIONS)) {
      const match = source.find((d) => d.text === text);
      expect(match, text).toBeDefined();
      expect(match!.length, text).toBeGreaterThan(LINE_LIMIT);
      expect(reason.trim().length, text).toBeGreaterThan(0);
    }
  });
});
