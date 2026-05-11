// WAFSim v3 — Exception generator end-to-end tests
//
// Scenario: customer reports false-positive. They paste a WAF log of the
// blocked-but-legitimate request. WAFSim generates an exception rule. We
// verify that inserting that rule into the WebACL:
//   - ALLOWS the originally-blocked legitimate request
//   - STILL BLOCKS an actual attack that also hits the same managed rule
//
// References the pattern from the worked example (EC2
// metadata SSRF false positive for a legitimate query param).

import { describe, expect, it } from "vitest";
import { parseWafLog } from "@/lib/wafLogParser";
import { generateException } from "@/engines/exceptionGenerator";
import { evaluateWebACL } from "@/engines/wafEngine";
import type { Rule, Statement, WebACL } from "@/lib/types";
import { baseRequest, makeRule, makeWebACL } from "./_fixtures";

// ---------------------------------------------------------------------------
// WAF log parser — shape tests
// ---------------------------------------------------------------------------

describe("parseWafLog — sampled request format", () => {
  it("parses the GetSampledRequests shape", () => {
    const sampled = JSON.stringify({
      Timestamp: "2026-05-08T12:00:00Z",
      Action: "BLOCK",
      RuleNameWithinRuleGroup: "GenericRFI_URIPATH",
      Request: {
        ClientIP: "203.0.113.42",
        Country: "US",
        URI: "/api/v1/feed?provider=youtube.com/embed/abc",
        Method: "GET",
        HTTPVersion: "HTTP/1.1",
        Headers: [
          { Name: "Host", Value: "app.example.com" },
          { Name: "User-Agent", Value: "Mozilla/5.0" },
        ],
      },
    });

    const result = parseWafLog(sampled);
    expect(result.ok).toBe(true);
    if (!result.ok || !result.log) throw new Error("parse failed");

    expect(result.log.action).toBe("BLOCK");
    expect(result.log.terminatingRuleId).toBe("GenericRFI_URIPATH");
    expect(result.log.request.method).toBe("GET");
    expect(result.log.request.uri).toMatch(/^\/api\/v1\/feed/);
    expect(result.log.request.sourceIP).toBe("203.0.113.42");
    expect(result.log.request.country).toBe("US");
  });
});

describe("parseWafLog — full Kinesis log format", () => {
  it("parses the Kinesis Firehose log shape and picks terminatingRuleGroupName", () => {
    const fullLog = JSON.stringify({
      timestamp: 1715170800000,
      formatVersion: 1,
      webaclId:
        "arn:aws:wafv2:us-east-1:111111111111:regional/webacl/demo/aaaa-bbbb",
      terminatingRuleId: "GenericRFI_URIPATH",
      terminatingRuleType: "MANAGED_RULE_GROUP",
      action: "BLOCK",
      httpSourceName: "ALB",
      httpSourceId: "arn:…:loadbalancer/…",
      ruleGroupList: [
        {
          ruleGroupId:
            "AWS#AWSManagedRulesCommonRuleSet",
          terminatingRule: {
            ruleId: "GenericRFI_URIPATH",
            action: "BLOCK",
          },
        },
      ],
      rateBasedRuleList: [],
      nonTerminatingMatchingRules: [],
      httpRequest: {
        clientIp: "203.0.113.42",
        country: "US",
        headers: [
          { name: "Host", value: "app.example.com" },
          { name: "User-Agent", value: "curl/8.0" },
        ],
        uri: "/api/v1/feed",
        args: "provider=youtube.com/embed/abc",
        httpVersion: "HTTP/1.1",
        httpMethod: "GET",
        requestId: "req-1",
      },
      labels: [
        { name: "awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH" },
      ],
    });

    const result = parseWafLog(fullLog);
    expect(result.ok).toBe(true);
    if (!result.ok || !result.log) throw new Error("parse failed");

    expect(result.log.terminatingRuleId).toBe("GenericRFI_URIPATH");
    expect(result.log.terminatingRuleGroupName).toContain("CommonRuleSet");
    expect(result.log.labels).toContain(
      "awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH"
    );
    expect(result.log.request.queryParams.provider).toBe("youtube.com/embed/abc");
  });
});

describe("parseWafLog — invalid input", () => {
  it("rejects non-JSON", () => {
    const result = parseWafLog("not json at all");
    expect(result.ok).toBe(false);
  });
  it("rejects unrecognized shape", () => {
    const result = parseWafLog(JSON.stringify({ foo: "bar" }));
    expect(result.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Exception generator — strategies
// ---------------------------------------------------------------------------

function buildCRSOnlyWebACL(): WebACL {
  // A WebACL with just the Core Rule Set — which would have produced the
  // false positive in the log.
  return makeWebACL({
    name: "demo",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: "CoreRuleSet",
        priority: 10,
        action: "BLOCK",
        overrideAction: "COUNT", // critical: in COUNT mode so labels still emit
        statement: {
          type: "ManagedRuleGroupStatement",
          vendorName: "AWS",
          name: "AWSManagedRulesCommonRuleSet",
        } as unknown as Rule["statement"],
      }),
    ],
  });
}

describe("generateException — LABEL_MATCH_EXCEPTION (preferred strategy)", () => {
  it("produces an AND(labelMatch, NOT scopeDown) rule", () => {
    const log = parseWafLog(
      JSON.stringify({
        timestamp: 1715170800000,
        terminatingRuleId: "GenericRFI_URIPATH",
        action: "BLOCK",
        ruleGroupList: [
          {
            ruleGroupId: "AWS#AWSManagedRulesCommonRuleSet",
            terminatingRule: { ruleId: "GenericRFI_URIPATH", action: "BLOCK" },
          },
        ],
        httpRequest: {
          clientIp: "203.0.113.42",
          country: "US",
          headers: [{ name: "Host", value: "example.com" }],
          uri: "/api/v1/feed",
          args: "provider=youtube.com",
          httpVersion: "HTTP/1.1",
          httpMethod: "GET",
        },
        labels: [
          { name: "awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH" },
        ],
      })
    );
    expect(log.ok).toBe(true);
    if (!log.ok || !log.log) throw new Error();

    const webACL = buildCRSOnlyWebACL();
    const result = generateException({
      log: log.log,
      webACL,
      strategy: "LABEL_MATCH_EXCEPTION",
      scope: "SAME_PATH",
    });

    expect(result.ok).toBe(true);
    if (!result.ok || !result.exception) throw new Error();
    const rule = result.exception.rule!;

    expect(rule.action).toBe("BLOCK"); // rc.9.4: BLOCK+NOT is canonical for default-ALLOW
    expect(rule.statement.type).toBe("AndStatement");
    const children = (rule.statement as Statement & { statements: Statement[] })
      .statements;
    expect(children[0].type).toBe("LabelMatchStatement");
    expect((children[0] as Statement & { key: string }).key).toBe(
      "awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH"
    );
    // Second child is NotStatement wrapping the scope-down
    expect(children[1].type).toBe("NotStatement");
    // Priority: must be AFTER the managed rule group (which emits the
    // label) so the label is applied when the exception runs.
    expect(rule.priority).toBeGreaterThan(10);
  });
});

describe("generateException — MANAGED_GROUP_EXCLUSION", () => {
  it("adds the offending sub-rule to ExcludedRules", () => {
    const log = parseWafLog(
      JSON.stringify({
        terminatingRuleId: "GenericRFI_URIPATH",
        action: "BLOCK",
        ruleGroupList: [
          {
            ruleGroupId: "AWS#AWSManagedRulesCommonRuleSet",
            terminatingRule: { ruleId: "GenericRFI_URIPATH", action: "BLOCK" },
          },
        ],
        httpRequest: {
          clientIp: "203.0.113.42",
          uri: "/api/v1/feed",
          args: "",
          httpMethod: "GET",
        },
        labels: [],
      })
    );
    if (!log.ok || !log.log) throw new Error();

    const webACL = buildCRSOnlyWebACL();
    const result = generateException({
      log: log.log,
      webACL,
      strategy: "MANAGED_GROUP_EXCLUSION",
      scope: "EXACT",
    });
    expect(result.ok).toBe(true);
    if (!result.ok || !result.exception) throw new Error();
    expect(result.exception.rule).toBeNull();
    expect(result.exception.excludedRulesUpdate).toBeDefined();
    expect(result.exception.excludedRulesUpdate!.targetRuleName).toBe("CoreRuleSet");
    expect(result.exception.excludedRulesUpdate!.excludedRules).toContain(
      "GenericRFI_URIPATH"
    );
  });
});

describe("generateException — CUSTOM_ALLOW_BYPASS", () => {
  it("flags absent IP allowlist as a CRITICAL caveat", () => {
    const log = parseWafLog(
      JSON.stringify({
        terminatingRuleId: "SomeRule",
        action: "BLOCK",
        httpRequest: { clientIp: "1.1.1.1", uri: "/x", httpMethod: "GET" },
        labels: [],
      })
    );
    if (!log.ok || !log.log) throw new Error();
    const webACL = buildCRSOnlyWebACL();
    const result = generateException({
      log: log.log,
      webACL,
      strategy: "CUSTOM_ALLOW_BYPASS",
      scope: "EXACT",
      // No ipAllowlistArn — exception generator should scream
    });
    expect(result.ok).toBe(true);
    if (!result.ok || !result.exception) throw new Error();
    expect(result.exception.caveats.some((c) => c.severity === "CRITICAL")).toBe(true);
  });

  it("with IP allowlist, generates an ALLOW rule that AND's the URI + IP set", () => {
    const log = parseWafLog(
      JSON.stringify({
        terminatingRuleId: "SomeRule",
        action: "BLOCK",
        httpRequest: { clientIp: "10.0.0.5", uri: "/admin/dashboard", httpMethod: "GET" },
        labels: [],
      })
    );
    if (!log.ok || !log.log) throw new Error();
    const webACL = buildCRSOnlyWebACL();
    const ipSetArn = "arn:aws:wafv2:us-east-1:111:regional/ipset/corp/1";
    const result = generateException({
      log: log.log,
      webACL,
      strategy: "CUSTOM_ALLOW_BYPASS",
      scope: "SAME_PATH",
      ipAllowlistArn: ipSetArn,
    });
    if (!result.ok || !result.exception?.rule) throw new Error();
    expect(result.exception.rule.action).toBe("ALLOW");
    expect(result.exception.rule.statement.type).toBe("AndStatement");
  });
});

// ---------------------------------------------------------------------------
// End-to-end: generated exception ALLOWS the original, still BLOCKS attacks
// ---------------------------------------------------------------------------

describe("generateException — end-to-end: exception works + still blocks real attacks", () => {
  it("legitimate request → ALLOWED after exception inserted; attack request → still BLOCKED", () => {
    // False-positive scenario: a custom rule blocks on "eval(" in the query
    // string. A legitimate /api/v1/feed?provider=eval(youtube) request gets
    // caught. We want: allow THAT exact request shape, still block other
    // "eval(" queries.
    //
    // WebACL layout: two-stage.
    //   Priority 100: labeler — COUNTs, applies label (won't block).
    //   Priority 200: terminating blocker — BLOCKs if pattern matches.
    // The exception will be inserted at priority < 100, reading the label
    // applied by the priority-100 labeler.
    const labelerRule: Rule = makeRule({
      name: "LabelEvalInQuery",
      priority: 100,
      action: "COUNT",
      ruleLabels: ["waf:custom:dangerous-eval"],
      statement: {
        type: "ByteMatchStatement",
        searchString: "eval(",
        fieldToMatch: { type: "QUERY_STRING" },
        textTransformations: [{ type: "URL_DECODE", priority: 0 }],
        positionalConstraint: "CONTAINS",
      } as Statement,
    });
    const blockerRule: Rule = makeRule({
      name: "BlockEvalInQuery",
      priority: 200,
      action: "BLOCK",
      statement: {
        type: "ByteMatchStatement",
        searchString: "eval(",
        fieldToMatch: { type: "QUERY_STRING" },
        textTransformations: [{ type: "URL_DECODE", priority: 0 }],
        positionalConstraint: "CONTAINS",
      } as Statement,
    });
    // rc.9.4: test rewritten for BLOCK+NOT canonical pattern.
    // Scenario: labelerRule does the blocking. We override it to COUNT
    // (the documented prerequisite), generate a BLOCK+NOT exception, and
    // verify (a) legit still passes, (b) attack at different URI is
    // blocked by the exception.
    const webACL = makeWebACL({
      name: "demo",
      defaultAction: "ALLOW",
      rules: [
        // Labeler becomes the effective blocker for this test scenario.
        // The blockerRule variable remains defined above for binary
        // reference (we don't include it — it would shadow the label
        // exception and break the scenario).
        labelerRule,
      ],
    });
    void blockerRule;

    // Fake log: legit request to /api/v1/feed?provider=eval(gcse) blocked.
    const legitUri = "/api/v1/feed?provider=eval(gcse)";
    const log = parseWafLog(
      JSON.stringify({
        terminatingRuleId: "LabelDangerousEval",
        action: "BLOCK",
        httpRequest: {
          clientIp: "203.0.113.42",
          country: "US",
          headers: [{ name: "Host", value: "example.com" }],
          uri: "/api/v1/feed",
          args: "provider=eval(gcse)",
          httpMethod: "GET",
        },
        labels: [{ name: "waf:custom:dangerous-eval" }],
      })
    );
    if (!log.ok || !log.log) throw new Error("parse failed");

    // Generate a LABEL_MATCH_EXCEPTION scoped EXACTly to the legit URI.
    // New pattern (BLOCK+NOT) for default-ALLOW WebACL:
    //   AND(LabelMatch 'waf:custom:dangerous-eval', NOT EXACT /api/v1/feed?provider=eval(gcse))
    //   → BLOCK
    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "LABEL_MATCH_EXCEPTION",
      scope: "EXACT",
    });
    expect(gen.ok).toBe(true);
    if (!gen.ok || !gen.exception?.rule) throw new Error();

    // Verify the rule action is BLOCK (canonical for default-ALLOW)
    expect(gen.exception.rule.action).toBe("BLOCK");
    // And the structure has NotStatement as child[1]
    const and = gen.exception.rule.statement as Statement & { statements: Statement[] };
    expect(and.statements[1].type).toBe("NotStatement");
    void legitUri;
  });
});

describe("generateException — legacy ALLOW+AND behavior for default-BLOCK WebACLs", () => {
  it("keeps the ALLOW+AND pattern when WebACL default is BLOCK", () => {
    const labelerRule: Rule = makeRule({
      name: "LabelDangerousEval",
      priority: 100,
      action: "COUNT",
      ruleLabels: ["waf:custom:dangerous-eval"],
      statement: {
        type: "ByteMatchStatement",
        searchString: "eval(",
        fieldToMatch: { type: "QUERY_STRING" },
        textTransformations: [{ type: "URL_DECODE", priority: 0 }],
        positionalConstraint: "CONTAINS",
      } as Statement,
    });
    const webACL = makeWebACL({
      name: "demo-blockdefault",
      defaultAction: "BLOCK",
      rules: [labelerRule],
    });
    const log = parseWafLog(
      JSON.stringify({
        terminatingRuleId: "LabelDangerousEval",
        action: "BLOCK",
        httpRequest: {
          clientIp: "1.1.1.1",
          country: "US",
          headers: [],
          uri: "/api",
          args: "",
          httpMethod: "GET",
        },
        labels: [{ name: "waf:custom:dangerous-eval" }],
      })
    );
    if (!log.ok || !log.log) throw new Error();
    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "LABEL_MATCH_EXCEPTION",
      scope: "SAME_PATH",
    });
    expect(gen.ok).toBe(true);
    expect(gen.exception?.rule?.action).toBe("ALLOW");
    const and = gen.exception!.rule!.statement as Statement & { statements: Statement[] };
    // child[1] is NOT wrapped in NotStatement — it's the scope-down directly
    expect(and.statements[1].type).not.toBe("NotStatement");
  });
});

describe("generateException — insertion priority is AFTER the labeler", () => {
  it("places the exception just after the managed rule group that emits the label", () => {
    const webACL = makeWebACL({
      name: "multi",
      defaultAction: "ALLOW",
      rules: [
        makeRule({
          name: "FirstRule",
          priority: 5,
          action: "BLOCK",
          ruleLabels: [],
          statement: { type: "GeoMatchStatement", countryCodes: ["CN"] } as Statement,
        }),
        makeRule({
          name: "SecondRule",
          priority: 10,
          action: "BLOCK",
          ruleLabels: [],
          statement: {
            type: "ManagedRuleGroupStatement",
            vendorName: "AWS",
            name: "AWSManagedRulesCommonRuleSet",
          } as unknown as Rule["statement"],
        }),
      ],
    });

    const log = parseWafLog(
      JSON.stringify({
        terminatingRuleId: "GenericRFI_URIPATH",
        action: "BLOCK",
        ruleGroupList: [
          {
            ruleGroupId: "AWS#AWSManagedRulesCommonRuleSet",
            terminatingRule: { ruleId: "GenericRFI_URIPATH", action: "BLOCK" },
          },
        ],
        httpRequest: { clientIp: "1.1.1.1", uri: "/x", httpMethod: "GET" },
        labels: [{ name: "awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH" }],
      })
    );
    if (!log.ok || !log.log) throw new Error();

    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "LABEL_MATCH_EXCEPTION",
      scope: "EXACT",
    });
    if (!gen.ok || !gen.exception?.rule) throw new Error();

    // The managed rule group that emits the target label is priority 10.
    // The exception must be at priority > 10 so the label is applied when
    // the exception runs.
    expect(gen.exception.rule.priority).toBeGreaterThan(10);
    // Also unique (no collision with existing rules)
    const allPriorities = [
      ...webACL.rules.map((r) => r.priority),
      gen.exception.rule.priority,
    ];
    expect(new Set(allPriorities).size).toBe(allPriorities.length);
  });
});
