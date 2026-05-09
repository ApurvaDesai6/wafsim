// Fleet-level posture scorer tests. The unit-level postureScorer tests cover
// scoring ONE WebACL; these cover aggregation across the fleet, fleet-only
// findings (unprotected resources, IP rep drift, etc.), and the
// consolidatedFindings dedup.

import { describe, it, expect } from "vitest";
import { scoreWebACLFleet, type FleetScopingInput } from "@/engines/postureScorer";
import { makeWebACL, makeRule } from "./_fixtures";
import type { Statement, ManagedRuleGroupStatement } from "@/lib/types";

function managedGroup(name: string): ManagedRuleGroupStatement {
  return {
    type: "ManagedRuleGroupStatement",
    vendorName: "AWS",
    name,
    excludedRules: [],
  } as unknown as ManagedRuleGroupStatement;
}

describe("scoreWebACLFleet — aggregate math", () => {
  it("overall score is the average of per-WebACL scores", () => {
    const wafs = [
      makeWebACL({
        id: "waf-1",
        name: "WAF1",
        scope: "REGIONAL",
        defaultAction: "ALLOW",
        rules: [
          makeRule({
            name: "CRS",
            priority: 10,
            action: "NONE",
            statement: managedGroup("AWSManagedRulesCommonRuleSet") as Statement,
          }),
        ],
      }),
      makeWebACL({
        id: "waf-2",
        name: "WAF2",
        scope: "REGIONAL",
        defaultAction: "ALLOW",
        rules: [], // empty — will score low
      }),
    ];

    const input: FleetScopingInput = {
      webACLs: wafs,
      attachments: new Map([
        ["waf-1", [{ resourceId: "alb-1", resourceKind: "ALB" }]],
        ["waf-2", [{ resourceId: "alb-2", resourceKind: "ALB" }]],
      ]),
      attachableResources: [
        { resourceId: "alb-1", resourceKind: "ALB" },
        { resourceId: "alb-2", resourceKind: "ALB" },
      ],
    };

    const report = scoreWebACLFleet(input);
    expect(report.webAclCount).toBe(2);
    // Average, so between the two individual scores
    const expected = Math.round(
      (report.perWebAcl[0].report.totalScore + report.perWebAcl[1].report.totalScore) / 2
    );
    expect(report.overallScore).toBe(expected);
  });

  it("zero-WebACL fleet returns 0 score, no errors thrown", () => {
    const input: FleetScopingInput = {
      webACLs: [],
      attachments: new Map(),
      attachableResources: [],
    };
    const report = scoreWebACLFleet(input);
    expect(report.overallScore).toBe(0);
    expect(report.webAclCount).toBe(0);
  });
});

describe("scoreWebACLFleet — fleet-only findings", () => {
  it("flags unprotected WAF-attachable resources in the topology", () => {
    const waf = makeWebACL({
      id: "waf-1",
      name: "WAF1",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
    });
    const input: FleetScopingInput = {
      webACLs: [waf],
      attachments: new Map([["waf-1", [{ resourceId: "alb-1", resourceKind: "ALB" }]]]),
      // alb-2 has NO WebACL attached → unprotected
      attachableResources: [
        { resourceId: "alb-1", resourceKind: "ALB" },
        { resourceId: "alb-2", resourceKind: "ALB" },
      ],
    };

    const report = scoreWebACLFleet(input);
    expect(report.unprotectedResourceCount).toBe(1);
    expect(
      report.fleetFindings.some(
        (f) =>
          f.title === "Unprotected WAF-attachable resource(s) in topology" &&
          f.severity === "error"
      )
    ).toBe(true);
  });

  it("does NOT flag unprotected resources when all are covered", () => {
    const waf = makeWebACL({
      id: "waf-1",
      name: "WAF1",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
    });
    const input: FleetScopingInput = {
      webACLs: [waf],
      attachments: new Map([["waf-1", [{ resourceId: "alb-1", resourceKind: "ALB" }]]]),
      attachableResources: [{ resourceId: "alb-1", resourceKind: "ALB" }],
    };

    const report = scoreWebACLFleet(input);
    expect(report.unprotectedResourceCount).toBe(0);
    expect(
      report.fleetFindings.some(
        (f) => f.title === "Unprotected WAF-attachable resource(s) in topology"
      )
    ).toBe(false);
  });

  it("flags IP reputation drift when some WebACLs have it and others don't", () => {
    const withIpRep = makeWebACL({
      id: "waf-1",
      name: "WAF1",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "IpRep",
          priority: 10,
          action: "NONE",
          statement: managedGroup("AWSManagedRulesAmazonIpReputationList") as Statement,
        }),
      ],
    });
    const withoutIpRep = makeWebACL({
      id: "waf-2",
      name: "WAF2",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
    });

    const input: FleetScopingInput = {
      webACLs: [withIpRep, withoutIpRep],
      attachments: new Map([
        ["waf-1", [{ resourceId: "alb-1", resourceKind: "ALB" }]],
        ["waf-2", [{ resourceId: "alb-2", resourceKind: "ALB" }]],
      ]),
      attachableResources: [
        { resourceId: "alb-1", resourceKind: "ALB" },
        { resourceId: "alb-2", resourceKind: "ALB" },
      ],
    };

    const report = scoreWebACLFleet(input);
    expect(
      report.fleetFindings.some(
        (f) => f.title === "Inconsistent IP reputation protection across fleet"
      )
    ).toBe(true);
  });

  it("flags mixed default actions across WebACLs", () => {
    const allowDefault = makeWebACL({
      id: "waf-1",
      name: "WAF_Allow",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
    });
    const blockDefault = makeWebACL({
      id: "waf-2",
      name: "WAF_Block",
      scope: "REGIONAL",
      defaultAction: "BLOCK",
      rules: [],
    });

    const input: FleetScopingInput = {
      webACLs: [allowDefault, blockDefault],
      attachments: new Map([
        ["waf-1", [{ resourceId: "alb-1", resourceKind: "ALB" }]],
        ["waf-2", [{ resourceId: "alb-2", resourceKind: "ALB" }]],
      ]),
      attachableResources: [
        { resourceId: "alb-1", resourceKind: "ALB" },
        { resourceId: "alb-2", resourceKind: "ALB" },
      ],
    };

    const report = scoreWebACLFleet(input);
    expect(
      report.fleetFindings.some(
        (f) => f.title === "Mixed default actions across WebACLs"
      )
    ).toBe(true);
  });
});

describe("scoreWebACLFleet — consolidated findings", () => {
  it("dedupes findings with the same title across WebACLs, keeping highest severity", () => {
    // Two identical empty WebACLs should generate the same findings; dedup
    // means each unique finding title appears once.
    const waf1 = makeWebACL({
      id: "waf-1",
      name: "WAF1",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
    });
    const waf2 = makeWebACL({
      id: "waf-2",
      name: "WAF2",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [],
    });

    const input: FleetScopingInput = {
      webACLs: [waf1, waf2],
      attachments: new Map(),
      attachableResources: [],
    };
    const report = scoreWebACLFleet(input);

    const titles = report.consolidatedFindings.map((f) => f.title);
    const uniqueTitles = new Set(titles);
    expect(titles.length).toBe(uniqueTitles.size);
  });
});

describe("scoreWebACLFleet — per-WebACL drill-down", () => {
  it("returns the right number of per-WebACL entries with attachments", () => {
    const wafs = [
      makeWebACL({ id: "a", name: "A", scope: "REGIONAL", defaultAction: "ALLOW", rules: [] }),
      makeWebACL({ id: "b", name: "B", scope: "CLOUDFRONT", defaultAction: "ALLOW", rules: [] }),
      makeWebACL({ id: "c", name: "C", scope: "REGIONAL", defaultAction: "ALLOW", rules: [] }),
    ];
    const input: FleetScopingInput = {
      webACLs: wafs,
      attachments: new Map([
        ["a", [{ resourceId: "alb-1", resourceKind: "ALB" }]],
        ["b", [{ resourceId: "cf-1", resourceKind: "CloudFront" }]],
        // c has no attachments
      ]),
      attachableResources: [
        { resourceId: "alb-1", resourceKind: "ALB" },
        { resourceId: "cf-1", resourceKind: "CloudFront" },
      ],
    };

    const report = scoreWebACLFleet(input);
    expect(report.perWebAcl).toHaveLength(3);
    expect(report.perWebAcl[0].attachedResourceIds).toEqual(["alb-1"]);
    expect(report.perWebAcl[1].attachedResourceIds).toEqual(["cf-1"]);
    expect(report.perWebAcl[2].attachedResourceIds).toEqual([]);
  });
});
