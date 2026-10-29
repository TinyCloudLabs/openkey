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
// Two checks:
// - every prose string literal in the copy sources (it starts with a capital
//   letter and has a space); a `{path}`, `{network}` or `${...}` placeholder
//   counts as PLACEHOLDER_CHARS, the length of a short name such as `notes/k1`;
// - every row and label the review renders for each TinyCloud registry
//   ability, on the signer's own space and on another user's, which covers
//   copy built from parts (the fallback row).

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { CAPABILITY_REGISTRY } from "@tinycloud/bootstrap";

import { buildStatements, parseCapabilityReview } from "../src/index.js";
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
const TWO_LINE_EXCEPTIONS: Record<string, string> = {};

const COPY_SOURCES = ["copy.ts", "statements.ts", "core-operations.ts", "classify.ts"];

interface Descriptor {
  where: string;
  text: string;
  length: number;
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
        const named = text.match(/\{(path|network)\}/g)?.length ?? 0;
        const fixed = text.replace(/\$\{\}|\{(path|network)\}/g, "").length;
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

// The resource each registry service is normally requested on.
const RESOURCE: Record<string, (owner: string) => string> = {
  "tinycloud.kv": (owner) => `${space("default", owner)}/kv/notes/`,
  "tinycloud.sql": (owner) => `${space("default", owner)}/sql/notes`,
  "tinycloud.duckdb": (owner) => `${space("default", owner)}/duckdb/analytics`,
  "tinycloud.vfs": (owner) => `${space("default", owner)}/vfs/photos`,
  "tinycloud.hooks": (owner) => `${space("default", owner)}/hooks/notes/`,
  "tinycloud.capabilities": (owner) => `${space("default", owner)}/capabilities`,
  "tinycloud.delegation": (owner) => `${space("account", owner)}/delegation`,
  "tinycloud.encryption": (owner) => `${space("default", owner)}/encryption`,
  "tinycloud.space": (owner) => `${space("courier", owner)}/space`,
};

function renderedDescriptors(): Descriptor[] {
  const found: Descriptor[] = [];
  for (const entry of CAPABILITY_REGISTRY) {
    const resource = RESOURCE[entry.service];
    if (!resource) throw new Error(`No resource for registry service ${entry.service}; add it to RESOURCE`);
    for (const owner of [ACCOUNT, OTHER]) {
      const model = parseCapabilityReview({
        message: siweWithResources([makeRecapResource({ [resource(owner)]: { [entry.urn]: [{}] } })]),
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
      const who = owner === ACCOUNT ? "own" : "other";
      for (const grant of model.permissions) {
        found.push({ where: `${entry.urn} (${who}) label`, text: grant.displayLabel, length: grant.displayLabel.length });
        for (const row of buildStatements(grant)) {
          found.push({ where: `${entry.urn} (${who})`, text: row.primaryText, length: row.primaryText.length });
        }
      }
    }
  }
  return found;
}

function overLimit(descriptors: Descriptor[]): string[] {
  return descriptors
    .filter((d) => {
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

  it(`every row and label rendered for a registry ability fits ${LINE_LIMIT} characters`, () => {
    expect(overLimit(renderedDescriptors())).toEqual([]);
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
