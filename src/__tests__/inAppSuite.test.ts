// WAFSim v3 — Wraps the in-app testSuite.ts (managed rule group sub-rule
// coverage + rule ordering scenarios) so its results run under vitest CI.
// When a sub-rule test fails here, it indicates a drift between the simulated
// behavior and the documented AMR behavior that the sub-rule represents.

import { describe, expect, it } from "vitest";
import { runAllTests } from "@/engines/testSuite";

const { subRuleResults, orderResults, summary } = runAllTests();

describe("In-app testSuite — managed rule group sub-rules", () => {
  it("summary reports counts", () => {
    expect(summary.total).toBeGreaterThan(0);
    expect(summary.total).toBe(summary.passed + summary.failed);
  });

  // Report failures individually so each one surfaces as a named test, not
  // drowned in an aggregate. Use dynamic it.each so CI output is informative.
  if (subRuleResults.length > 0) {
    it.each(subRuleResults)(
      "[$ruleGroupName] $subRuleName — $description",
      (result) => {
        expect(
          result.passed,
          `Expected match=${result.testCase.expectedMatch}, got match=${result.actualMatch}. ${
            result.error ?? ""
          }`
        ).toBe(true);
      }
    );
  }
});

describe("In-app testSuite — rule ordering scenarios", () => {
  if (orderResults.length > 0) {
    it.each(orderResults)("$name", (result) => {
      expect(
        result.passed,
        `Expected finalAction=${result.testCase.expectedFinalAction}, got ${result.actualFinalAction}. ${
          result.error ?? ""
        }`
      ).toBe(true);
    });
  }
});
