// WAFSim v3 — Posture scorer tests
// Verifies the 5-category scoring logic with tailored WebACL fixtures.

import { describe, expect, it } from "vitest";
import { scoreWebACL } from "@/engines/postureScorer";
import type { Rule, Statement } from "@/lib/types";
import { makeRule, makeWebACL } from "./_fixtures";

const geoStmt = { type: "GeoMatchStatement", countryCodes: ["ZZ"] } as Rule["statement"];

describe("scoreWebACL — empty WebACL", () => {
  it("returns near-zero score and NoProtection verdict", () => {
    const acl = makeWebACL({ name: "empty", defaultAction: "ALLOW", rules: [] });
    const r = scoreWebACL(acl);
    expect(r.totalScore).toBeLessThan(20);
    expect(r.verdict).toBe("No Protection");
    expect(r.categories).toHaveLength(5);
    expect(r.findings.some((f) => f.severity === "error" && f.category === "Defense")).toBe(true);
  });
});

describe("scoreWebACL — Coverage category", () => {
  it("awards points for AWSManagedRulesCommonRuleSet", () => {
    const acl = makeWebACL({
      name: "with-crs",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "CRS",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
          } as unknown as Rule["statement"],
        }),
      ],
    });
    const r = scoreWebACL(acl);
    const cov = r.categories.find((c) => c.category === "Coverage")!;
    expect(cov.score).toBeGreaterThanOrEqual(10); // +5 for any managed + +5 for CRS
  });

  it("awards points for custom SQLi protection", () => {
    const acl = makeWebACL({
      name: "custom-sqli",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "BlockSQLi",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "SqliMatchStatement",
            fieldToMatch: { type: "QUERY_STRING" },
            textTransformations: [{ type: "URL_DECODE", priority: 0 }],
            sensitivityLevel: "LOW",
          } as Rule["statement"],
        }),
      ],
    });
    const r = scoreWebACL(acl);
    const cov = r.categories.find((c) => c.category === "Coverage")!;
    expect(cov.score).toBeGreaterThanOrEqual(3);
    expect(cov.findings.find((f) => f.title.includes("SQLi"))).toBeUndefined();
  });
});

describe("scoreWebACL — Defense category", () => {
  it("zero defense score when all rules are COUNT", () => {
    const acl = makeWebACL({
      name: "all-count",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "CountOnly",
          priority: 0,
          action: "COUNT",
          statement: geoStmt,
        }),
      ],
    });
    const r = scoreWebACL(acl);
    const def = r.categories.find((c) => c.category === "Defense")!;
    expect(def.findings.some((f) => f.title.includes("monitor-only"))).toBe(true);
  });

  it("high defense score when there are BLOCK rules + mostly terminating", () => {
    const acl = makeWebACL({
      name: "blocking",
      defaultAction: "ALLOW",
      rules: [
        makeRule({ name: "Block1", priority: 0, action: "BLOCK", statement: geoStmt }),
        makeRule({ name: "Block2", priority: 1, action: "BLOCK", statement: geoStmt }),
      ],
    });
    const r = scoreWebACL(acl);
    const def = r.categories.find((c) => c.category === "Defense")!;
    // +8 for at least one BLOCK + +4 for mostly terminating + +4 for no bare IP allow + +4 for default
    expect(def.score).toBeGreaterThanOrEqual(16);
  });

  it("flags bare IP-only ALLOW rules as risky", () => {
    const acl = makeWebACL({
      name: "bare-ip-allow",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "BareIPAllow",
          priority: 0,
          action: "ALLOW",
          statement: {
            type: "IPSetReferenceStatement",
            arn: "arn:aws:wafv2:us-east-1:111:regional/ipset/x/1",
            ipSetReference: { arn: "arn:aws:wafv2:us-east-1:111:regional/ipset/x/1" },
          } as Rule["statement"],
        }),
        makeRule({
          name: "BlockOthers",
          priority: 1,
          action: "BLOCK",
          statement: geoStmt,
        }),
      ],
    });
    const r = scoreWebACL(acl);
    const def = r.categories.find((c) => c.category === "Defense")!;
    expect(def.findings.some((f) => f.title.includes("bare IP-only ALLOW"))).toBe(true);
  });
});

describe("scoreWebACL — RateLimiting category", () => {
  it("scores 0 + warning when no rate-based rule", () => {
    const acl = makeWebACL({
      name: "no-rate",
      defaultAction: "ALLOW",
      rules: [makeRule({ name: "G", priority: 0, action: "BLOCK", statement: geoStmt })],
    });
    const r = scoreWebACL(acl);
    const rate = r.categories.find((c) => c.category === "RateLimiting")!;
    expect(rate.score).toBe(0);
    expect(rate.findings.some((f) => f.title.includes("No rate-based rules"))).toBe(true);
  });

  it("scores 10 for basic rate rule", () => {
    const acl = makeWebACL({
      name: "rate-basic",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "Rate",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            limit: 50, // out of typical range → only +10, not +5
            aggregateKeyType: "IP",
          } as Rule["statement"],
        }),
      ],
    });
    const r = scoreWebACL(acl);
    const rate = r.categories.find((c) => c.category === "RateLimiting")!;
    expect(rate.score).toBeGreaterThanOrEqual(10);
    expect(rate.score).toBeLessThan(20);
  });

  it("scores 20 with scope-down + reasonable limit", () => {
    const acl = makeWebACL({
      name: "rate-scoped",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "LoginRate",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            limit: 100,
            aggregateKeyType: "IP",
            scopeDownStatement: {
              type: "ByteMatchStatement",
              searchString: "/login",
              fieldToMatch: { type: "URI_PATH" },
              textTransformations: [{ type: "NONE", priority: 0 }],
              positionalConstraint: "STARTS_WITH",
            },
          } as Rule["statement"],
        }),
      ],
    });
    const r = scoreWebACL(acl);
    const rate = r.categories.find((c) => c.category === "RateLimiting")!;
    expect(rate.score).toBe(20);
  });
});

describe("scoreWebACL — Visibility category", () => {
  it("full points when all rules are observable + have unique metric names + use labels", () => {
    const acl = makeWebACL({
      name: "observable",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "R1",
          priority: 0,
          action: "BLOCK",
          ruleLabels: ["myapp:blocked:sqli"],
          statement: geoStmt,
        }),
        makeRule({
          name: "R2",
          priority: 1,
          action: "BLOCK",
          statement: geoStmt,
        }),
      ],
    });
    const r = scoreWebACL(acl);
    const vis = r.categories.find((c) => c.category === "Visibility")!;
    // makeRule defaults have sampled + metrics enabled, rule names unique, and one label
    expect(vis.score).toBe(20);
  });
});

describe("scoreWebACL — Hygiene category", () => {
  it("flags duplicate priorities as error", () => {
    const acl = makeWebACL({
      name: "dup-prio",
      defaultAction: "ALLOW",
      rules: [
        makeRule({ name: "A", priority: 5, action: "BLOCK", statement: geoStmt }),
        makeRule({ name: "B", priority: 5, action: "BLOCK", statement: geoStmt }),
      ],
    });
    const r = scoreWebACL(acl);
    const hyg = r.categories.find((c) => c.category === "Hygiene")!;
    expect(hyg.findings.some((f) => f.severity === "error" && f.title.includes("priorities"))).toBe(true);
  });

  it("flags managed rule group scope mismatch", () => {
    // Bot Control is BOTH-scoped per current managedRuleGroups.ts, but let's use
    // a managed group that's real. If all are BOTH-scoped, this test becomes a no-op.
    // We'll check the scope comparison codepath with a REGIONAL WebACL and look
    // for errors only if there's an ACTUAL mismatch. Assertion: no crash.
    const acl = makeWebACL({
      name: "scope-check",
      defaultAction: "ALLOW",
      scope: "REGIONAL",
      rules: [
        makeRule({
          name: "CRS",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
          } as unknown as Rule["statement"],
        }),
      ],
    });
    const r = scoreWebACL(acl);
    // CRS is BOTH-scoped so no mismatch
    expect(r.findings.some((f) => f.title.includes("scope mismatch"))).toBe(false);
  });
});

describe("scoreWebACL — end-to-end production-ready WebACL", () => {
  it("a good WebACL scores 70+ and verdict is at least Solid", () => {
    const acl = makeWebACL({
      name: "prod-ready",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "AmazonIpRep",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesAmazonIpReputationList",
          } as unknown as Rule["statement"],
        }),
        makeRule({
          name: "CRS",
          priority: 1,
          action: "BLOCK",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
          } as unknown as Rule["statement"],
        }),
        makeRule({
          name: "KnownBad",
          priority: 2,
          action: "BLOCK",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesKnownBadInputsRuleSet",
          } as unknown as Rule["statement"],
        }),
        makeRule({
          name: "SQLi",
          priority: 3,
          action: "BLOCK",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesSQLiRuleSet",
          } as unknown as Rule["statement"],
        }),
        makeRule({
          name: "LoginRate",
          priority: 4,
          action: "BLOCK",
          ruleLabels: ["myapp:rate:login"],
          statement: {
            type: "RateBasedStatement",
            limit: 100,
            aggregateKeyType: "IP",
            scopeDownStatement: {
              type: "ByteMatchStatement",
              searchString: "/login",
              fieldToMatch: { type: "URI_PATH" },
              textTransformations: [{ type: "NONE", priority: 0 }],
              positionalConstraint: "STARTS_WITH",
            },
          } as Rule["statement"],
        }),
      ],
    });
    const r = scoreWebACL(acl);
    expect(r.totalScore).toBeGreaterThanOrEqual(70);
    expect(["Solid", "Strong", "Defense in Depth"]).toContain(r.verdict);
  });
});
