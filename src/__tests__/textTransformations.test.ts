// WAFSim v3 — Text transformation tests
// Each transformation must match AWS WAF documented behavior.
// Docs: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-transformation.html

import { describe, expect, it } from "vitest";
import { applyTransformations } from "@/engines/textTransformations";
import type { TextTransformation } from "@/lib/types";

const t = (type: TextTransformation["type"], priority = 0): TextTransformation => ({ type, priority });
const run = (input: string, xforms: TextTransformation[]) => applyTransformations(input, xforms);

describe("TextTransformation — NONE", () => {
  it("passes string through unchanged", () => {
    expect(applyTransformations("Hello World", [t("NONE")])).toBe("Hello World");
  });
});

describe("TextTransformation — LOWERCASE", () => {
  it("lowercases ASCII letters", () => {
    expect(applyTransformations("Hello WORLD", [t("LOWERCASE")])).toBe("hello world");
  });
  it("preserves non-letters", () => {
    expect(applyTransformations("A1B2!@#", [t("LOWERCASE")])).toBe("a1b2!@#");
  });
});

describe("TextTransformation — URL_DECODE", () => {
  it("decodes percent-encoded sequences", () => {
    expect(applyTransformations("%3Cscript%3E", [t("URL_DECODE")])).toBe("<script>");
  });
  it("treats + as space (form encoding)", () => {
    expect(applyTransformations("hello+world", [t("URL_DECODE")])).toBe("hello world");
  });
});

describe("TextTransformation — HTML_ENTITY_DECODE", () => {
  it("decodes named entities", () => {
    expect(applyTransformations("&lt;b&gt;", [t("HTML_ENTITY_DECODE")])).toBe("<b>");
  });
  it("decodes numeric entities", () => {
    expect(applyTransformations("&#60;&#62;", [t("HTML_ENTITY_DECODE")])).toBe("<>");
  });
  it("decodes hex entities", () => {
    expect(applyTransformations("&#x3C;&#x3E;", [t("HTML_ENTITY_DECODE")])).toBe("<>");
  });
});

describe("TextTransformation — COMPRESS_WHITE_SPACE", () => {
  it("collapses multiple whitespace to single space", () => {
    expect(applyTransformations("a    b\t\tc\n\nd", [t("COMPRESS_WHITE_SPACE")])).toBe("a b c d");
  });
  it("trims leading/trailing whitespace", () => {
    expect(applyTransformations("  hello  ", [t("COMPRESS_WHITE_SPACE")])).toBe("hello");
  });
});

describe("TextTransformation — REMOVE_NULLS / REPLACE_NULLS", () => {
  it("REMOVE_NULLS strips NUL bytes", () => {
    expect(applyTransformations("a\0b\0c", [t("REMOVE_NULLS")])).toBe("abc");
  });
  it("REPLACE_NULLS swaps NULs for spaces", () => {
    expect(applyTransformations("a\0b", [t("REPLACE_NULLS")])).toBe("a b");
  });
});

describe("TextTransformation — transformation ordering", () => {
  it("applies transformations in priority order (lowest first)", () => {
    // URL_DECODE first produces "<SCRIPT>", then LOWERCASE produces "<script>"
    const result = applyTransformations("%3CSCRIPT%3E", [
      t("LOWERCASE", 1),
      t("URL_DECODE", 0),
    ]);
    expect(result).toBe("<script>");
  });

  it("different order produces different result when ops do not commute", () => {
    // LOWERCASE first produces "%3cscript%3e", then URL_DECODE produces "<script>"
    // Same final result here by coincidence, so use a case where ordering matters:
    // URL_DECODE of "%41" = "A". LOWERCASE of "A" = "a". 
    // But LOWERCASE of "%41" = "%41" (already lowercase hex letters are lowercase). URL_DECODE of "%41" = "A".
    // So order matters: URL_DECODE then LOWERCASE gives "a"; LOWERCASE then URL_DECODE gives "A".
    const decodeThenLower = applyTransformations("%41", [
      t("URL_DECODE", 0),
      t("LOWERCASE", 1),
    ]);
    const lowerThenDecode = applyTransformations("%41", [
      t("LOWERCASE", 0),
      t("URL_DECODE", 1),
    ]);
    expect(decodeThenLower).toBe("a");
    expect(lowerThenDecode).toBe("A");
  });
});

describe("TextTransformation — BASE64_DECODE", () => {
  it("decodes valid base64", () => {
    // "hello" base64 = "aGVsbG8="
    const result = applyTransformations("aGVsbG8=", [t("BASE64_DECODE")]);
    expect(result).toBe("hello");
  });
});

describe("TextTransformation — compound pipeline", () => {
  it("chains URL_DECODE + LOWERCASE + COMPRESS_WHITE_SPACE", () => {
    const input = "%3CSCRIPT%3E%20%20alert%281%29";
    const result = applyTransformations(input, [
      t("URL_DECODE", 0),
      t("LOWERCASE", 1),
      t("COMPRESS_WHITE_SPACE", 2),
    ]);
    expect(result).toBe("<script> alert(1)");
  });
});
