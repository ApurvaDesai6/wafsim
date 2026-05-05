// WAFSim v3 — Export engine schema conformance tests.
// Validates that generated AWS WAFv2 JSON matches the documented AWS API
// schema, and Terraform HCL uses documented block structures for
// aws_wafv2_web_acl / aws_wafv2_regex_pattern_set.
//
// Authoritative refs:
//   https://docs.aws.amazon.com/waf/latest/APIReference/API_CreateWebACL.html
//   https://docs.aws.amazon.com/waf/latest/APIReference/API_RateBasedStatement.html
//   https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_regex_pattern_set

import { describe, expect, it } from "vitest";
import {
  exportAsWebACLJson,
  exportAsTerraformHCL,
  generateCLICommands,
  exportIPSetJson,
  exportRegexPatternSetJson,
} from "@/engines/exportEngine";
import type { Rule, WebACL } from "@/lib/types";
import { makeIPSet, makeRegexPatternSet, makeRule, makeWebACL } from "./_fixtures";

describe("exportEngine — WebACL JSON schema conformance", () => {
  it("top-level keys match AWS CreateWebACL input schema", () => {
    const acl = makeWebACL({
      name: "conformance",
      defaultAction: "ALLOW",
      rules: [],
    });
    const json = exportAsWebACLJson(acl);
    expect(json).toHaveProperty("Name");
    expect(json).toHaveProperty("Scope");
    expect(json).toHaveProperty("DefaultAction");
    expect(json).toHaveProperty("Rules");
    expect(json).toHaveProperty("VisibilityConfig");
    // DefaultAction shape per AWS: { Allow: {} } or { Block: {} }
    expect(json.DefaultAction).toEqual({ Allow: {} });
  });

  it("DefaultAction BLOCK serializes as { Block: {} }", () => {
    const acl = makeWebACL({ name: "b", defaultAction: "BLOCK", rules: [] });
    const json = exportAsWebACLJson(acl);
    expect(json.DefaultAction).toEqual({ Block: {} });
  });

  it("VisibilityConfig uses AWS field names with expected casing", () => {
    const acl = makeWebACL({ name: "vis", defaultAction: "ALLOW", rules: [] });
    const json = exportAsWebACLJson(acl);
    expect(json.VisibilityConfig).toHaveProperty("SampledRequestsEnabled");
    expect(json.VisibilityConfig).toHaveProperty("CloudWatchMetricsEnabled");
    expect(json.VisibilityConfig).toHaveProperty("MetricName");
  });
});

describe("exportEngine — Rule JSON schema", () => {
  it("custom rule carries Action with PascalCase key", () => {
    const acl = makeWebACL({
      name: "act",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "Geo",
          priority: 0,
          action: "BLOCK",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Rule["statement"],
        }),
      ],
    });
    const json = exportAsWebACLJson(acl);
    expect(json.Rules[0].Action).toEqual({ Block: {} });
    expect(json.Rules[0].OverrideAction).toBeUndefined();
  });

  it("managed rule group rule carries OverrideAction, not Action", () => {
    const acl = makeWebACL({
      name: "mg",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "CRS",
          priority: 0,
          action: "BLOCK",
          overrideAction: "NONE",
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
          } as unknown as Rule["statement"],
        }),
      ],
    });
    const json = exportAsWebACLJson(acl);
    expect(json.Rules[0].OverrideAction).toEqual({ None: {} });
    expect(json.Rules[0].Action).toBeUndefined();
  });
});

describe("exportEngine — RateBasedStatement AWS API conformance", () => {
  // Per AWS docs (API_RateBasedStatement.html):
  //   required: AggregateKeyType, Limit
  //   optional: CustomKeys (not "AggregateKeys"), EvaluationWindowSec,
  //             ForwardedIPConfig, ScopeDownStatement
  it("uses Limit (not RateLimit)", () => {
    const acl = makeWebACL({
      name: "rate",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "Rate",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            rateLimit: 2000,
            evaluationWindowSec: 300,
            aggregateKeyType: "IP",
          } as Rule["statement"],
        }),
      ],
    });
    const json = exportAsWebACLJson(acl);
    const rate = json.Rules[0].Statement.RateBasedStatement as Record<string, unknown>;
    expect(rate).toHaveProperty("Limit");
    expect(rate).not.toHaveProperty("RateLimit");
    expect(rate.Limit).toBe(2000);
  });

  it("uses CustomKeys (not AggregateKeys) for CUSTOM_KEYS aggregation", () => {
    const acl = makeWebACL({
      name: "custom-keys",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "Rate",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            rateLimit: 100,
            aggregateKeyType: "CUSTOM_KEYS",
            aggregateKeys: [{ ip: {} }, { uriPath: {} }],
          } as Rule["statement"],
        }),
      ],
    });
    const json = exportAsWebACLJson(acl);
    const rate = json.Rules[0].Statement.RateBasedStatement as Record<string, unknown>;
    expect(rate).toHaveProperty("CustomKeys");
    expect(rate).not.toHaveProperty("AggregateKeys");
    expect(Array.isArray(rate.CustomKeys)).toBe(true);
  });

  it("valid EvaluationWindowSec values only (60, 120, 300, 600)", () => {
    const acl = makeWebACL({
      name: "window",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "Rate",
          priority: 0,
          action: "BLOCK",
          statement: {
            type: "RateBasedStatement",
            rateLimit: 100,
            evaluationWindowSec: 120,
            aggregateKeyType: "IP",
          } as Rule["statement"],
        }),
      ],
    });
    const json = exportAsWebACLJson(acl);
    const rate = json.Rules[0].Statement.RateBasedStatement as Record<string, unknown>;
    expect([60, 120, 300, 600]).toContain(rate.EvaluationWindowSec);
  });
});

describe("exportEngine — IP Set + Regex Pattern Set JSON", () => {
  it("IP set JSON has correct field names", () => {
    const ipSet = makeIPSet({ name: "corp", addresses: ["10.0.0.0/8"] });
    const json = exportIPSetJson(ipSet);
    expect(json).toHaveProperty("Name");
    expect(json).toHaveProperty("Scope");
    expect(json).toHaveProperty("IPAddressVersion");
    expect(json).toHaveProperty("Addresses");
  });

  it("regex pattern set JSON has correct field names", () => {
    const rps = makeRegexPatternSet({
      name: "paths",
      regularExpressionList: ["^/admin", "^/wp-"],
    });
    const json = exportRegexPatternSetJson(rps);
    expect(json).toHaveProperty("Name");
    expect(json).toHaveProperty("Scope");
    expect(json).toHaveProperty("RegularExpressionList");
    expect(json.RegularExpressionList).toEqual(["^/admin", "^/wp-"]);
  });
});

describe("exportEngine — Terraform HCL conformance", () => {
  const webACL = makeWebACL({
    name: "tf-test",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "GeoBlock",
        priority: 0,
        action: "BLOCK",
        statement: { type: "GeoMatchStatement", countryCodes: ["CN"] } as Rule["statement"],
      }),
    ],
  });
  const ipSet = makeIPSet({ name: "corp", addresses: ["10.0.0.0/8", "192.168.0.0/16"] });
  const rps = makeRegexPatternSet({
    name: "admin-paths",
    regularExpressionList: ["^/admin", "^/wp-admin"],
  });

  it("references aws_wafv2_web_acl / ip_set / regex_pattern_set resources", () => {
    const tf = exportAsTerraformHCL(webACL, [ipSet], [rps]);
    expect(tf).toContain("aws_wafv2_web_acl");
    expect(tf).toContain("aws_wafv2_ip_set");
    expect(tf).toContain("aws_wafv2_regex_pattern_set");
  });

  it("regex pattern set has one regular_expression block per pattern (not one block with many regex_string)", () => {
    const tf = exportAsTerraformHCL(webACL, [], [rps]);
    // There are 2 patterns in the set, so there must be 2 regular_expression blocks
    const blockCount = (tf.match(/regular_expression\s*\{/g) || []).length;
    const regexStringCount = (tf.match(/regex_string\s*=/g) || []).length;
    expect(blockCount).toBe(2);
    expect(regexStringCount).toBe(2);
  });

  it("uses snake_case Terraform attribute names", () => {
    const tf = exportAsTerraformHCL(webACL, [ipSet], [rps]);
    expect(tf).toContain("ip_address_version");
    expect(tf).toContain("default_action");
    expect(tf).toContain("visibility_config");
    expect(tf).toContain("cloudwatch_metrics_enabled");
    expect(tf).toContain("sampled_requests_enabled");
    expect(tf).toContain("metric_name");
  });
});

describe("exportEngine — CLI command sequence", () => {
  it("emits create-ip-set, create-regex-pattern-set, create-web-acl in dependency order", () => {
    const webACL = makeWebACL({
      name: "cli-seq",
      defaultAction: "ALLOW",
      rules: [],
    });
    const ipSet = makeIPSet({ name: "corp", addresses: ["10.0.0.0/8"] });
    const rps = makeRegexPatternSet({
      name: "paths",
      regularExpressionList: ["^/admin"],
    });
    const cli = generateCLICommands(webACL, [ipSet], [rps]);
    expect(cli).toHaveLength(3);
    expect(cli[0]).toContain("create-ip-set");
    expect(cli[1]).toContain("create-regex-pattern-set");
    expect(cli[2]).toContain("create-web-acl");
    // The WebACL command must come last because it references the others by ARN.
  });
});
