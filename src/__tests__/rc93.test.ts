// rc.9.3 — tests for shareable URLs and multi-format exporters.

import { describe, it, expect } from "vitest";
import { encodeShareableState, decodeShareableState } from "@/lib/shareState";
import { toJson, toCloudFormation, toTerraform, toCli, exportException } from "@/lib/exceptionExporters";
import { makeRule, makeWebACL } from "./_fixtures";
import type { Statement } from "@/lib/types";

describe("shareState round-trip", () => {
  it("encodes + decodes an empty workspace", async () => {
    const state = {
      nodes: [],
      edges: [],
      wafs: [],
      ipSets: [],
      regexPatternSets: [],
    };
    const encoded = await encodeShareableState(state);
    expect(encoded).toBeTruthy();
    const decoded = await decodeShareableState(encoded);
    expect(decoded).not.toBeNull();
    expect(decoded!.v).toBe(1);
    expect(decoded!.nodes).toEqual([]);
  });

  it("encodes + decodes a workspace with WAFs and preserves data", async () => {
    const waf = makeWebACL({
      id: "waf-1",
      name: "Test",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "BlockRU",
          priority: 10,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["RU"] } as Statement,
        }),
      ],
    });
    const state = {
      nodes: [],
      edges: [],
      wafs: [waf],
      ipSets: [],
      regexPatternSets: [],
    };
    const encoded = await encodeShareableState(state);
    const decoded = await decodeShareableState(encoded);
    expect(decoded!.wafs).toHaveLength(1);
    expect(decoded!.wafs[0].name).toBe("Test");
    expect(decoded!.wafs[0].rules[0].name).toBe("BlockRU");
  });

  it("returns null on invalid input", async () => {
    const decoded = await decodeShareableState("not-a-valid-encoded-string");
    expect(decoded).toBeNull();
  });
});

describe("exceptionExporters", () => {
  const sampleRule = makeRule({
    name: "AllowLegitApi",
    priority: 5,
    action: "ALLOW",
    statement: {
      type: "ByteMatchStatement",
      searchString: "/api/legit",
      fieldToMatch: { type: "URI_PATH" },
      textTransformations: [{ type: "NONE", priority: 0 }],
      positionalConstraint: "EXACTLY",
    } as Statement,
  });

  it("emits valid JSON", () => {
    const out = toJson(sampleRule);
    const parsed = JSON.parse(out);
    expect(parsed.name).toBe("AllowLegitApi");
    expect(parsed.priority).toBe(5);
  });

  it("emits CloudFormation YAML with the rule structure", () => {
    const out = toCloudFormation(sampleRule);
    expect(out).toContain("Name: AllowLegitApi");
    expect(out).toContain("Priority: 5");
    expect(out).toContain("Allow: {}");
    expect(out).toContain("ByteMatchStatement:");
    expect(out).toContain("UriPath: {}");
  });

  it("emits Terraform HCL with block structure", () => {
    const out = toTerraform(sampleRule);
    expect(out).toContain('name     = "AllowLegitApi"');
    expect(out).toContain("priority = 5");
    expect(out).toContain("allow {}");
    expect(out).toContain("byte_match_statement {");
    expect(out).toContain("uri_path {}");
    expect(out).toContain('positional_constraint = "EXACTLY"');
  });

  it("emits AWS CLI one-liner template", () => {
    const out = toCli(sampleRule, "ProdWebACL", "REGIONAL");
    expect(out).toContain("aws wafv2 get-web-acl");
    expect(out).toContain("aws wafv2 update-web-acl");
    expect(out).toContain("ProdWebACL");
    expect(out).toContain("REGIONAL");
  });

  it("exportException dispatches to the right format", () => {
    expect(exportException(sampleRule, "json")).toContain("AllowLegitApi");
    expect(exportException(sampleRule, "cloudformation")).toContain("Name: AllowLegitApi");
    expect(exportException(sampleRule, "terraform")).toContain('name     = "AllowLegitApi"');
    expect(exportException(sampleRule, "cli")).toContain("aws wafv2");
  });

  it("CloudFormation handles AND statements", () => {
    const andRule = makeRule({
      name: "AndRule",
      priority: 1,
      action: "ALLOW",
      statement: {
        type: "AndStatement",
        statements: [
          {
            type: "LabelMatchStatement",
            scope: "LABEL",
            key: "awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH",
          } as Statement,
          {
            type: "ByteMatchStatement",
            searchString: "/api",
            fieldToMatch: { type: "URI_PATH" },
            textTransformations: [{ type: "NONE", priority: 0 }],
            positionalConstraint: "EXACTLY",
          } as Statement,
        ],
      } as Statement,
    });
    const out = toCloudFormation(andRule);
    expect(out).toContain("AndStatement:");
    expect(out).toContain("LabelMatchStatement:");
    expect(out).toContain("ByteMatchStatement:");
  });

  it("Terraform handles managed rule group with excluded rules", () => {
    const managedRule = makeRule({
      name: "CRS",
      priority: 10,
      action: "BLOCK" /* placeholder for managed-group rules */,
      statement: {
        type: "ManagedRuleGroupStatement",
        vendorName: "AWS",
        name: "AWSManagedRulesCommonRuleSet",
        excludedRules: ["GenericRFI_URIPATH", "SizeRestrictions_BODY"],
      } as Statement,
    });
    const out = toTerraform(managedRule);
    expect(out).toContain('vendor_name = "AWS"');
    expect(out).toContain('name        = "AWSManagedRulesCommonRuleSet"');
    expect(out).toContain('name = "GenericRFI_URIPATH"');
    expect(out).toContain("count {}");
  });
});
