// WAFSim v3 — Core WebACL evaluation engine tests
// Validates that evaluateWebACL matches AWS WAFv2 documented semantics:
//   - Priority-ordered rule evaluation (lowest number first)
//   - COUNT does NOT terminate evaluation
//   - ALLOW, BLOCK, CAPTCHA, CHALLENGE all terminate
//   - Labels applied regardless of action (even for COUNT rules)
//   - Labels applied by earlier rules are visible to later rules
//   - WebACL default action applied only if no rule terminates

import { describe, expect, it } from "vitest";
import {
  evaluateWebACL,
  evaluateBatch,
  summarizeResults,
  validateWebACL,
} from "@/engines/wafEngine";
import type { HttpRequest, Rule } from "@/lib/types";
import { baseRequest, makeRule, makeWebACL } from "./_fixtures";

describe("evaluateWebACL — default action", () => {
  it("returns WebACL defaultAction when no rules match", () => {
    const acl = makeWebACL({
      name: "default-allow",
      defaultAction: "ALLOW",
      rules: [],
    });
    const result = evaluateWebACL(baseRequest(), acl);
    expect(result.finalAction).toBe("ALLOW");
    expect(result.terminatingRule).toBeNull();
  });

  it("returns defaultAction BLOCK when nothing matches", () => {
    const acl = makeWebACL({
      name: "default-block",
      defaultAction: "BLOCK",
      rules: [
        makeRule({
          name: "never-matches",
          priority: 0,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["ZZ"] } as Rule["statement"],
        }),
      ],
    });
    const result = evaluateWebACL(baseRequest({ country: "US" }), acl);
    expect(result.finalAction).toBe("BLOCK");
    expect(result.terminatingRule).toBeNull();
  });
});

describe("evaluateWebACL — priority ordering", () => {
  it("evaluates rules in ascending priority order (lowest first)", () => {
    const acl = makeWebACL({
      name: "priority-order",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "HighPriorityBlock",
          priority: 10,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
        makeRule({
          name: "LowPriorityAllow",
          priority: 0,
          action: "ALLOW",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
      ],
    });
    const result = evaluateWebACL(baseRequest({ country: "US" }), acl);
    expect(result.finalAction).toBe("ALLOW");
    expect(result.terminatingRule?.rule.name).toBe("LowPriorityAllow");
  });
});

describe("evaluateWebACL — termination semantics", () => {
  const matches = (name: string, priority: number, action: Rule["action"], labels: string[] = []): Rule =>
    makeRule({
      name,
      priority,
      action,
      ruleLabels: labels,
      statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
    });

  it("COUNT does NOT terminate — later rule still runs", () => {
    const acl = makeWebACL({
      name: "count-continues",
      defaultAction: "ALLOW",
      rules: [
        matches("CountFirst", 0, "COUNT"),
        matches("BlockSecond", 1, "BLOCK"),
      ],
    });
    const result = evaluateWebACL(baseRequest({ country: "US" }), acl);
    expect(result.finalAction).toBe("BLOCK");
    expect(result.terminatingRule?.rule.name).toBe("BlockSecond");
    expect(result.allMatchedRules.map((m) => m.rule.name)).toContain("CountFirst");
    expect(result.allMatchedRules.find((m) => m.rule.name === "CountFirst")?.action).toBe("COUNT");
  });

  it.each([
    ["ALLOW" as const],
    ["BLOCK" as const],
    ["CAPTCHA" as const],
    ["CHALLENGE" as const],
  ])("%s terminates evaluation immediately", (action) => {
    const acl = makeWebACL({
      name: `terminates-${action}`,
      defaultAction: "BLOCK",
      rules: [
        matches("Terminator", 0, action),
        matches("NeverReached", 1, "BLOCK"),
      ],
    });
    const result = evaluateWebACL(baseRequest({ country: "US" }), acl);
    expect(result.finalAction).toBe(action);
    expect(result.terminatingRule?.rule.name).toBe("Terminator");
    expect(result.ruleTrace.find((t) => t.ruleName === "NeverReached")).toBeUndefined();
  });
});

describe("evaluateWebACL — label propagation", () => {
  it("applies labels from COUNT rules so later rules can match them", () => {
    const acl = makeWebACL({
      name: "label-propagation",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "ApplyLabel",
          priority: 0,
          action: "COUNT",
          ruleLabels: ["test:traffic:suspicious"],
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
        makeRule({
          name: "MatchLabel",
          priority: 1,
          action: "BLOCK",
          statement: {
            type: "LabelMatchStatement",
            scope: "LABEL",
            key: "test:traffic:suspicious",
          } as Rule["statement"],
        }),
      ],
    });
    const result = evaluateWebACL(baseRequest({ country: "US" }), acl);
    expect(result.finalAction).toBe("BLOCK");
    expect(result.labelsApplied).toContain("test:traffic:suspicious");
    expect(result.terminatingRule?.rule.name).toBe("MatchLabel");
  });

  it("labels applied by terminating rule are visible in result", () => {
    const acl = makeWebACL({
      name: "label-on-terminate",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "BlockWithLabel",
          priority: 0,
          action: "BLOCK",
          ruleLabels: ["test:blocked:geo"],
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
      ],
    });
    const result = evaluateWebACL(baseRequest({ country: "US" }), acl);
    expect(result.labelsApplied).toContain("test:blocked:geo");
  });
});

describe("validateWebACL", () => {
  it("flags duplicate priorities", () => {
    const acl = makeWebACL({
      name: "dup",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "RuleA",
          priority: 0,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
        makeRule({
          name: "RuleB",
          priority: 0,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
      ],
    });
    const v = validateWebACL(acl);
    expect(v.valid).toBe(false);
    expect(v.errors.some((e) => e.includes("Duplicate priority"))).toBe(true);
  });

  it("flags duplicate rule names", () => {
    const acl = makeWebACL({
      name: "dup-names",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "Same",
          priority: 0,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
        makeRule({
          name: "Same",
          priority: 1,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
      ],
    });
    const v = validateWebACL(acl);
    expect(v.valid).toBe(false);
    expect(v.errors.some((e) => e.includes("Duplicate rule name"))).toBe(true);
  });

  it("returns total WCU for rules", () => {
    const acl = makeWebACL({
      name: "wcu-total",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "GeoRule",
          priority: 0,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
      ],
    });
    const v = validateWebACL(acl);
    expect(v.wcu).toBeGreaterThan(0);
  });
});

describe("evaluateBatch + summarizeResults", () => {
  it("processes multiple requests and tallies by action", () => {
    const acl = makeWebACL({
      name: "batch",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "BlockUS",
          priority: 0,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
      ],
    });
    const reqs: HttpRequest[] = [
      baseRequest({ country: "US" }),
      baseRequest({ country: "US" }),
      baseRequest({ country: "CA" }),
    ];
    const results = evaluateBatch(reqs, acl);
    const summary = summarizeResults(results);
    expect(summary.total).toBe(3);
    expect(summary.blocked).toBe(2);
    expect(summary.allowed).toBe(1);
    expect(summary.byRule.get("BlockUS")).toBe(2);
  });
});
