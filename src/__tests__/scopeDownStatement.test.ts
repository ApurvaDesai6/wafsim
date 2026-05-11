// rc.9.5 — tests for SCOPE_DOWN_STATEMENT strategy

import { describe, it, expect } from "vitest";
import { parseWafLog } from "@/lib/wafLogParser";
import { generateException } from "@/engines/exceptionGenerator";
import { makeWebACL, makeRule } from "./_fixtures";
import type { Statement, WebACL } from "@/lib/types";

function logFor(ruleId: string, groupId = "AWS#AWSManagedRulesCommonRuleSet") {
  return JSON.stringify({
    terminatingRuleId: ruleId,
    action: "BLOCK",
    ruleGroupList: [
      {
        ruleGroupId: groupId,
        terminatingRule: { ruleId, action: "BLOCK" },
      },
    ],
    httpRequest: {
      clientIp: "1.1.1.1",
      country: "US",
      uri: "/api/upload",
      args: "",
      httpMethod: "POST",
      headers: [],
    },
    labels: [{ name: `awswaf:managed:aws:core-rule-set:${ruleId}` }],
  });
}

function webACLWithManagedGroup(groupName: string, scopeDown?: Statement): WebACL {
  return makeWebACL({
    id: "waf-1",
    name: "prod",
    scope: "REGIONAL",
    defaultAction: "ALLOW",
    rules: [
      makeRule({
        name: groupName, // rule is named after the managed group
        priority: 10,
        overrideAction: "NONE",
        action: "BLOCK" /* placeholder for managed-group rules */,
        statement: {
          type: "ManagedRuleGroupStatement",
          vendorName: "AWS",
          name: groupName,
          excludedRules: [],
          ...(scopeDown ? { scopeDownStatement: scopeDown } : {}),
        } as unknown as Statement,
      }),
    ],
  });
}

describe("SCOPE_DOWN_STATEMENT — basic flow", () => {
  it("generates a scope-down update when the managed group is attached", () => {
    const webACL = webACLWithManagedGroup("AWSManagedRulesCommonRuleSet");
    const log = parseWafLog(logFor("CrossSiteScripting_BODY"));
    if (!log.ok || !log.log) throw new Error();

    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "SCOPE_DOWN_STATEMENT",
      scope: "SAME_PATH",
    });
    expect(gen.ok).toBe(true);
    expect(gen.exception?.rule).toBeNull(); // no new rule — edits existing
    expect(gen.exception?.scopeDownUpdate).toBeDefined();
    expect(gen.exception?.scopeDownUpdate?.targetRuleName).toBe("AWSManagedRulesCommonRuleSet");
  });

  it("wraps the legit-match in a NotStatement (so managed group skips legit traffic)", () => {
    const webACL = webACLWithManagedGroup("AWSManagedRulesCommonRuleSet");
    const log = parseWafLog(logFor("CrossSiteScripting_BODY"));
    if (!log.ok || !log.log) throw new Error();

    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "SCOPE_DOWN_STATEMENT",
      scope: "SAME_PATH",
    });
    const sd = gen.exception?.scopeDownUpdate?.scopeDownStatement as Statement;
    // The scope-down is a NotStatement so the managed group runs only when
    // the request does NOT match our legit pattern (= suspicious traffic).
    expect(sd.type).toBe("NotStatement");
  });

  it("returns error when the log's rule group isn't attached to the WebACL", () => {
    const webACL = webACLWithManagedGroup("AWSManagedRulesCommonRuleSet");
    const log = parseWafLog(logFor("SomeRule", "AWS#AWSManagedRulesSQLiRuleSet"));
    if (!log.ok || !log.log) throw new Error();

    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "SCOPE_DOWN_STATEMENT",
      scope: "SAME_PATH",
    });
    expect(gen.ok).toBe(false);
    expect(gen.error).toMatch(/not attached/i);
  });
});

describe("SCOPE_DOWN_STATEMENT — preserves existing scope-down", () => {
  it("AND-combines the new condition with an existing scope-down", () => {
    const existingScopeDown: Statement = {
      type: "GeoMatchStatement",
      countryCodes: ["US", "CA"],
    } as Statement;

    const webACL = webACLWithManagedGroup("AWSManagedRulesCommonRuleSet", existingScopeDown);
    const log = parseWafLog(logFor("CrossSiteScripting_BODY"));
    if (!log.ok || !log.log) throw new Error();

    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "SCOPE_DOWN_STATEMENT",
      scope: "SAME_PATH",
    });

    const sd = gen.exception?.scopeDownUpdate?.scopeDownStatement as Statement & {
      statements: Statement[];
    };
    expect(sd.type).toBe("AndStatement");
    expect(sd.statements[0].type).toBe("GeoMatchStatement"); // existing preserved
    expect(sd.statements[1].type).toBe("NotStatement");      // new NOT wrapper added

    // MEDIUM-severity caveat about the combined logic
    expect(
      gen.exception?.caveats.some(
        (c) => c.severity === "MEDIUM" && c.text.includes("already has a scope-down")
      )
    ).toBe(true);
  });
});

describe("SCOPE_DOWN_STATEMENT — suggestedPriority reflects in-place edit", () => {
  it("uses the existing managed rule's priority (this is an edit, not an insert)", () => {
    const webACL = webACLWithManagedGroup("AWSManagedRulesCommonRuleSet");
    const log = parseWafLog(logFor("CrossSiteScripting_BODY"));
    if (!log.ok || !log.log) throw new Error();

    const gen = generateException({
      log: log.log,
      webACL,
      strategy: "SCOPE_DOWN_STATEMENT",
      scope: "SAME_PATH",
    });
    // Priority 10 — same as the managed rule. The scope-down is an edit,
    // not a new rule insert, so priority doesn't shift.
    expect(gen.exception?.suggestedPriority).toBe(10);
  });
});
