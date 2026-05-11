// WAFSim v3 — Nested statement round-trip tests
// Verifies that deeply nested AND/OR/NOT statements (3 levels) survive
// export → import round-trip and still evaluate correctly afterwards.

import { describe, expect, it } from "vitest";
import { evaluateWebACL } from "@/engines/wafEngine";
import { exportAsWebACLJson } from "@/engines/exportEngine";
import { importWebACLJson } from "@/engines/importEngine";
import type { Statement, Rule } from "@/lib/types";
import { baseRequest, makeRule, makeWebACL } from "./_fixtures";

describe("Nested statements — 3-level depth round-trip", () => {
  // (NOT geo=CA) AND ((geo=US AND method=POST) OR contains(uri, "/api"))
  const threeLevel: Statement = {
    type: "AndStatement",
    statements: [
      {
        type: "NotStatement",
        statement: { type: "GeoMatchStatement", countryCodes: ["CA"] },
      },
      {
        type: "OrStatement",
        statements: [
          {
            type: "AndStatement",
            statements: [
              { type: "GeoMatchStatement", countryCodes: ["US"] },
              {
                type: "ByteMatchStatement",
                searchString: "POST",
                fieldToMatch: { type: "METHOD" },
                textTransformations: [{ type: "NONE", priority: 0 }],
                positionalConstraint: "EXACTLY",
              },
            ],
          },
          {
            type: "ByteMatchStatement",
            searchString: "/api",
            fieldToMatch: { type: "URI_PATH" },
            textTransformations: [{ type: "NONE", priority: 0 }],
            positionalConstraint: "CONTAINS",
          },
        ],
      },
    ],
  } as Statement;

  const acl = makeWebACL({
    name: "nested-roundtrip",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "NestedBlock",
        priority: 0,
        action: "BLOCK",
        statement: threeLevel,
      }),
    ],
  });

  it("matches POST to /api from US (NOT-CA AND (US-AND-POST))", () => {
    const r = evaluateWebACL(
      baseRequest({ method: "POST", uri: "/api/users", country: "US" }),
      acl
    );
    expect(r.finalAction).toBe("BLOCK");
  });

  it("matches GET to /api from US (NOT-CA AND contains-/api)", () => {
    const r = evaluateWebACL(
      baseRequest({ method: "GET", uri: "/api/users", country: "US" }),
      acl
    );
    expect(r.finalAction).toBe("BLOCK");
  });

  it("does not match POST to /public from CA (fails NOT-CA)", () => {
    const r = evaluateWebACL(
      baseRequest({ method: "POST", uri: "/public", country: "CA" }),
      acl
    );
    expect(r.finalAction).toBe("ALLOW");
  });

  it("does not match GET to /home from US (no /api, not POST)", () => {
    const r = evaluateWebACL(
      baseRequest({ method: "GET", uri: "/home", country: "US" }),
      acl
    );
    expect(r.finalAction).toBe("ALLOW");
  });

  it("nested structure survives export → import round-trip", () => {
    const json = exportAsWebACLJson(acl);
    const imported = importWebACLJson(JSON.stringify(json));
    expect(imported.webACL).toBeDefined();
    if (!imported.webACL) return;

    // After round-trip, evaluation should give identical results on a
    // representative test request.
    const test = baseRequest({ method: "POST", uri: "/api/users", country: "US" });
    const original = evaluateWebACL(test, acl);
    const roundtripped = evaluateWebACL(test, imported.webACL);
    expect(original.finalAction).toBe(roundtripped.finalAction);
    expect(roundtripped.finalAction).toBe("BLOCK");
  });

  it("exported JSON preserves statement nesting depth", () => {
    const json = exportAsWebACLJson(acl);
    // Walk down: Rules[0].Statement.AndStatement.Statements[1].OrStatement.Statements[0].AndStatement
    const rule = json.Rules[0];
    const lvl0 = rule.Statement as Record<string, unknown>;
    expect(lvl0).toHaveProperty("AndStatement");
    const lvl0Inner = (lvl0.AndStatement as { Statements: unknown[] }).Statements;
    const orBlock = lvl0Inner[1] as Record<string, unknown>;
    expect(orBlock).toHaveProperty("OrStatement");
    const lvl2 = (orBlock.OrStatement as { Statements: unknown[] }).Statements;
    const innerAnd = lvl2[0] as Record<string, unknown>;
    expect(innerAnd).toHaveProperty("AndStatement");
    // We made it 3 levels deep without losing structure.
  });
});
