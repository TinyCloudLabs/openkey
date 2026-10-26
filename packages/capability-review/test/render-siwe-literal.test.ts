// The exact-SIWE view shows a line feed as a real line break and escapes every
// other character exactly as `renderLiteral` does, so the text on screen maps
// one-to-one onto the signed characters.

import { describe, expect, it } from "bun:test";

import { renderLiteral, renderSiweLiteral } from "../src/copy.js";
import { makeRecapResource } from "./fixtures/index.js";

const unescape = (text: string): string =>
  text.replace(/\\u([0-9a-f]{4})/gi, (_match, hex: string) => String.fromCharCode(parseInt(hex, 16)));

describe("renderSiweLiteral", () => {
  it("shows LF as a real line break", () => {
    expect(renderSiweLiteral("a\nb")).toBe("a\nb");
    expect(renderSiweLiteral("\n")).toBe("\n");
    expect(renderSiweLiteral("a\n\nb\n")).toBe("a\n\nb\n");
    expect(renderSiweLiteral("")).toBe("");
  });

  it("reads a CR before an LF as `\\u000d` plus a real line break", () => {
    expect(renderSiweLiteral("a\r\nb")).toBe("a\\u000d\nb");
    expect(renderSiweLiteral("a\rb")).toBe("a\\u000db");
  });

  it("escapes every other character as renderLiteral does", () => {
    const cases: Array<[string, string]> = [
      ["\t", "\\u0009"],
      ["\0", "\\u0000"],
      ["\x7f", "\\u007f"],
      ["\x85", "\\u0085"],
      ["\x9f", "\\u009f"],
      ["\u2028", "\\u2028"],
      ["\u2029", "\\u2029"],
      ["\u202e", "\\u202e"],
      ["\u2066", "\\u2066"],
      ["\u200b", "\\u200b"],
      ["\u200d", "\\u200d"],
      ["\ufeff", "\\ufeff"],
      ["\ud83d\ude00", "\\ud83d\\ude00"],
      ["<", "\\u003c"],
      [">", "\\u003e"],
      ["&", "\\u0026"],
      ['"', "\\u0022"],
      ["'", "\\u0027"],
      ["\\", "\\u005C"],
    ];
    for (const [input, escaped] of cases) {
      expect(renderSiweLiteral(`x${input}y`)).toBe(`x${escaped}y`);
      expect(renderSiweLiteral(`x${input}y`)).toBe(renderLiteral(`x${input}y`));
    }
  });

  it("keeps text that already spells an escape distinguishable from a real line break", () => {
    expect(renderSiweLiteral("a\\u000ab")).toBe("a\\u005Cu000ab");
  });

  it("equals renderLiteral output with only the LF escapes turned into line breaks", () => {
    let seed = 0x2123;
    const next = () => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed;
    };
    const pool = [0x0a, 0x0a, 0x0d, 0x09, 0x00, 0x7f, 0x85, 0x2028, 0x2029, 0x202e, 0x200b, 0x5c, 0x3c, 0x26, 0x22, 0x27, 0xd83d, 0xde00, 0x20, 0x41, 0x7e];
    for (let round = 0; round < 500; round += 1) {
      let input = "";
      const length = next() % 40;
      for (let i = 0; i < length; i += 1) {
        const pick = next() % 4;
        input += String.fromCharCode(pick === 0 ? next() % 0x3000 : pool[next() % pool.length]!);
      }
      const rendered = renderSiweLiteral(input);
      expect(rendered).toBe(renderLiteral(input).replaceAll("\\u000a", "\n"));
      // One real line break per LF, nothing else but printable ASCII, no markup.
      expect(rendered.split("\n").length).toBe(input.split("\n").length);
      expect(/^[\x20-\x7e\n]*$/.test(rendered)).toBe(true);
      expect(/[<>&"']/.test(rendered)).toBe(false);
      // Removing nothing but un-escaping gives the input back.
      expect(unescape(rendered)).toBe(input);
    }
  });

  it("round-trips a multi-line SIWE message", () => {
    const siwe = [
      "cli.tinycloud.xyz wants you to sign in with your Ethereum account:",
      "0xd559ccd9eb87c530a9a349262669386de93cf412",
      "",
      "I further authorize these capabilities.",
      "",
      "URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "Version: 1",
      "Chain ID: 1",
      "Nonce: abcdef123456",
      "Issued At: 2026-10-16T17:00:00.000Z",
      "Expiration Time: 2026-10-23T17:00:00.000Z",
      "Resources:",
      `- ${makeRecapResource({ "tinycloud:pkh:eip155:1:0xd559ccd9eb87c530a9a349262669386de93cf412:default/kv/notes/": { "tinycloud.kv/get": [{}] } })}`,
    ].join("\n");
    const rendered = renderSiweLiteral(siwe);
    expect(rendered).toBe(siwe);
    expect(rendered.split("\n")).toHaveLength(13);
    expect(unescape(rendered)).toBe(siwe);
    const crlf = siwe.replaceAll("\n", "\r\n");
    expect(renderSiweLiteral(crlf)).toBe(siwe.replaceAll("\n", "\\u000d\n"));
    expect(unescape(renderSiweLiteral(crlf))).toBe(crlf);
  });

  it("leaves renderLiteral unchanged: LF is still escaped there", () => {
    expect(renderLiteral("a\nb")).toBe("a\\u000ab");
  });
});
