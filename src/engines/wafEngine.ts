// WAFSim - WAF Evaluation Engine
// Core WebACL evaluation loop implementing AWS WAFv2 specification

import {
  WebACL,
  Rule,
  HttpRequest,
  EvaluationResult,
  RuleMatch,
  RuleTrace,
  WAFAction,
  IPSet,
  RegexPatternSet,
  Statement,
} from "@/lib/types";
import { evaluateStatement, EvaluationContext, ManagedRuleGroupModel } from "./statementEvaluator";
import { MANAGED_RULE_GROUPS } from "@/lib/managedRuleGroups";

/**
 * Evaluate a WebACL against an HTTP request
 */
export function evaluateWebACL(
  request: HttpRequest,
  webACL: WebACL,
  options: {
    ipSets?: IPSet[];
    regexPatternSets?: RegexPatternSet[];
    requestTimestamp?: number;
    rateTracking?: { requestCounts: Map<string, number[]>; windowMs: number };
  } = {}
): EvaluationResult {
  // Sort rules by priority (lowest number = evaluated first)
  const sortedRules = [...webACL.rules].sort((a, b) => a.priority - b.priority);

  const labelsApplied: string[] = [];
  const allMatchedRules: RuleMatch[] = [];
  const ruleTrace: RuleTrace[] = [];
  let approximatedManagedRules = false;

  // Build context
  const ipSetsMap = new Map<string, IPSet>();
  (options.ipSets || []).forEach((ipSet) => ipSetsMap.set(ipSet.arn, ipSet));

  const regexPatternSetsMap = new Map<string, RegexPatternSet>();
  (options.regexPatternSets || []).forEach((set) => regexPatternSetsMap.set(set.arn, set));

  const managedRuleGroupModels = new Map<string, ManagedRuleGroupModel>();
  Object.entries(MANAGED_RULE_GROUPS).forEach(([name, model]) => {
    managedRuleGroupModels.set(name, model as ManagedRuleGroupModel);
  });

  const context: EvaluationContext = {
    request,
    labelsApplied,
    ipSets: ipSetsMap,
    regexPatternSets: regexPatternSetsMap,
    requestTimestamp: options.requestTimestamp || Date.now(),
    rateTracking: options.rateTracking,
    managedRuleGroupModels,
  };

  // Evaluate each rule in priority order
  for (const rule of sortedRules) {
    const trace = evaluateRule(rule, context);

    if (trace.matched) {
      // Track if any managed rules were approximated
      if (
        rule.statement.type === "ManagedRuleGroupStatement" ||
        (rule.statement.type === "RateBasedStatement" && rule.statement.scopeDownStatement?.type === "ManagedRuleGroupStatement")
      ) {
        approximatedManagedRules = true;
      }

      // Add any labels this rule applies regardless of action type
      if (rule.ruleLabels) {
        for (const label of rule.ruleLabels) {
          if (!labelsApplied.includes(label)) {
            labelsApplied.push(label);
          }
        }
        trace.labelsAdded = rule.ruleLabels;
      }

      const effectiveAction = getEffectiveAction(rule);

      if (effectiveAction === "COUNT") {
        // COUNT does NOT terminate — continues evaluation
        allMatchedRules.push({ rule, action: "COUNT" });
        trace.action = "COUNT";
        trace.terminates = false;
      } else {
        // ALLOW, BLOCK, CAPTCHA, CHALLENGE all terminate evaluation
        trace.action = effectiveAction;
        trace.terminates = true;
        ruleTrace.push(trace);

        return {
          finalAction: effectiveAction,
          terminatingRule: { rule, action: effectiveAction },
          allMatchedRules,
          labelsApplied,
          ruleTrace,
          requestWithTransformations: request,
          approximatedManagedRules,
        };
      }
    }

    ruleTrace.push(trace);
  }

  // No rule terminated — apply WebACL default action
  return {
    finalAction: webACL.defaultAction,
    terminatingRule: null,
    allMatchedRules,
    labelsApplied,
    ruleTrace,
    requestWithTransformations: request,
    approximatedManagedRules,
  };
}

/**
 * Evaluate a single rule
 */
function evaluateRule(rule: Rule, context: EvaluationContext): RuleTrace {
  const trace: RuleTrace = {
    ruleName: rule.name,
    priority: rule.priority,
    matched: false,
    action: "no-action",
    labelsAdded: [],
    terminates: false,
    reason: "",
  };

  // Evaluate the statement
  const result = evaluateStatement(rule.statement, context);

  trace.matched = result.matched;
  trace.reason = result.reason;

  if (result.matched && result.transformedContent) {
    trace.transformedContent = result.transformedContent;
  }

  if (result.matched && result.matchedContent) {
    trace.matchedContent = result.matchedContent;
  }

  return trace;
}

/**
 * Get the effective action for a rule
 * Handles override actions for managed rule groups
 */
function getEffectiveAction(rule: Rule): WAFAction {
  // For managed rule groups, check override action
  if (rule.statement.type === "ManagedRuleGroupStatement") {
    // If override action is "COUNT", treat as count
    if (rule.overrideAction === "COUNT") {
      return "COUNT";
    }
    // If override action is "NONE", use the rule's normal action
    if (rule.overrideAction === "NONE" || !rule.overrideAction) {
      return rule.action;
    }
    return rule.overrideAction;
  }

  return rule.action;
}

/**
 * Batch evaluate multiple requests
 * Useful for flood simulation
 */
export function evaluateBatch(
  requests: HttpRequest[],
  webACL: WebACL,
  options: {
    ipSets?: IPSet[];
    regexPatternSets?: RegexPatternSet[];
    startTime?: number;
    requestInterval?: number; // ms between requests
  } = {}
): EvaluationResult[] {
  const results: EvaluationResult[] = [];
  const startTime = options.startTime || Date.now();
  const interval = options.requestInterval || 100; // 100ms default

  // Initialize rate tracking
  const rateTracking = {
    requestCounts: new Map<string, number[]>(),
    windowMs: 60000, // 1 minute window
  };

  for (let i = 0; i < requests.length; i++) {
    const request = requests[i];
    const requestTimestamp = startTime + i * interval;

    // Update rate tracking
    updateRateTracking(rateTracking, request, requestTimestamp, webACL);

    const result = evaluateWebACL(request, webACL, {
      ...options,
      requestTimestamp,
      rateTracking,
    });

    results.push(result);
  }

  return results;
}

/**
 * Update rate tracking state for a request
 */
function updateRateTracking(
  rateTracking: { requestCounts: Map<string, number[]>; windowMs: number },
  request: HttpRequest,
  timestamp: number,
  webACL: WebACL
): void {
  // Find all rate-based rules in the WebACL
  const rateRules = webACL.rules.filter(
    (r) => r.statement.type === "RateBasedStatement"
  );

  for (const rule of rateRules) {
    const rateStatement = rule.statement as Statement extends infer S ? S extends { type: "RateBasedStatement" } ? S : never : never;
    const key = getRateTrackingKey(rateStatement, request);

    if (key) {
      const timestamps = rateTracking.requestCounts.get(key) || [];
      timestamps.push(timestamp);

      // Keep only timestamps within the window
      const windowStart = timestamp - rateTracking.windowMs;
      const recentTimestamps = timestamps.filter((t) => t > windowStart);
      rateTracking.requestCounts.set(key, recentTimestamps);
    }
  }
}

/**
 * Get rate tracking key for a rate-based statement
 */
function getRateTrackingKey(
  statement: { aggregateKeyType: string; aggregateKeys?: Array<Record<string, unknown>>; forwardedIPConfig?: { headerName: string } },
  request: HttpRequest
): string | null {
  switch (statement.aggregateKeyType) {
    case "IP":
      return `ip:${request.sourceIP}`;

    case "FORWARDED_IP":
      const headerName = statement.forwardedIPConfig?.headerName || "X-Forwarded-For";
      const forwardedIP = request.headers?.find(
        (h) => h.name.toLowerCase() === headerName.toLowerCase()
      )?.value;
      return forwardedIP ? `fwdip:${forwardedIP.split(",")[0].trim()}` : null;

    case "CONSTANT":
      return "constant:all";

    case "CUSTOM_KEYS":
      if (!statement.aggregateKeys || statement.aggregateKeys.length === 0) {
        return null;
      }
      const keyParts: string[] = [];
      for (const key of statement.aggregateKeys) {
        if (key.ip) {
          keyParts.push(request.sourceIP);
        } else if (key.forwardedIP) {
          const fwdHeader = statement.forwardedIPConfig?.headerName || "X-Forwarded-For";
          const fwdIP = request.headers?.find(
            (h) => h.name.toLowerCase() === fwdHeader.toLowerCase()
          )?.value;
          keyParts.push(fwdIP?.split(",")[0].trim() || "");
        } else if (key.header) {
          const headerVal = request.headers?.find(
            (h) => h.name.toLowerCase() === (key.header as { name: string }).name.toLowerCase()
          )?.value || "";
          keyParts.push(headerVal);
        } else if (key.uriPath) {
          keyParts.push(request.uri.split("?")[0]);
        }
      }
      return `custom:${keyParts.join(":")}`;

    default:
      return null;
  }
}

/**
 * Create a summary of evaluation results
 */
export function summarizeResults(results: EvaluationResult[]): {
  total: number;
  allowed: number;
  blocked: number;
  counted: number;
  captcha: number;
  challenge: number;
  byRule: Map<string, number>;
} {
  const summary = {
    total: results.length,
    allowed: 0,
    blocked: 0,
    counted: 0,
    captcha: 0,
    challenge: 0,
    byRule: new Map<string, number>(),
  };

  for (const result of results) {
    switch (result.finalAction) {
      case "ALLOW":
        summary.allowed++;
        break;
      case "BLOCK":
        summary.blocked++;
        break;
      case "COUNT":
        summary.counted++;
        break;
      case "CAPTCHA":
        summary.captcha++;
        break;
      case "CHALLENGE":
        summary.challenge++;
        break;
    }

    if (result.terminatingRule) {
      const ruleName = result.terminatingRule.rule.name;
      summary.byRule.set(ruleName, (summary.byRule.get(ruleName) || 0) + 1);
    }
  }

  return summary;
}

/**
 * Validate a WebACL configuration
 */
export function validateWebACL(webACL: WebACL): {
  valid: boolean;
  errors: string[];
  warnings: string[];
  wcu: number;
} {
  const errors: string[] = [];
  const warnings: string[] = [];
  let wcu = 0;

  // Check required fields
  if (!webACL.name) {
    errors.push("WebACL name is required");
  }

  if (!webACL.defaultAction) {
    errors.push("Default action is required");
  }

  // Check rule priorities are unique
  const priorities = new Set<number>();
  const ruleNames = new Set<string>();

  for (const rule of webACL.rules) {
    if (priorities.has(rule.priority)) {
      errors.push(`Duplicate priority ${rule.priority} for rule "${rule.name}"`);
    }
    priorities.add(rule.priority);

    if (ruleNames.has(rule.name)) {
      errors.push(`Duplicate rule name "${rule.name}"`);
    }
    ruleNames.add(rule.name);

    // Calculate WCU for the rule
    const ruleWcu = calculateRuleWCU(rule);
    wcu += ruleWcu;
  }

  // Check WCU limit
  if (wcu > 1500) {
    errors.push(`WCU ${wcu} exceeds maximum of 1500`);
  } else if (wcu > 1200) {
    warnings.push(`WCU ${wcu} is close to maximum (1500), consider optimizing rules`);
  }

  // Check for scope conflicts
  const hasCloudFrontScope = webACL.rules.some((r) => {
    if (r.statement.type === "ManagedRuleGroupStatement") {
      const stmt = r.statement as Statement extends infer S ? S extends { type: "ManagedRuleGroupStatement" } ? S : never : never;
      // Some managed rule groups are CloudFront only
      return false; // Would check managed rule group scope here
    }
    return false;
  });

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    wcu,
  };
}

/**
 * Calculate WCU for a rule
 */
function calculateRuleWCU(rule: Rule): number {
  const statement = rule.statement;

  // Base WCU depends on statement type
  let baseWcu = 1;

  switch (statement.type) {
    case "ByteMatchStatement":
      baseWcu = 3;
      // Add cost for text transformations
      const byteMatchStmt = statement as Statement extends infer S ? S extends { type: "ByteMatchStatement" } ? S : never : never;
      baseWcu += (byteMatchStmt.textTransformations?.length || 0) * 10;
      break;

    case "GeoMatchStatement":
      baseWcu = 1;
      break;

    case "IPSetReferenceStatement":
      baseWcu = 1;
      break;

    case "LabelMatchStatement":
      baseWcu = 1;
      break;

    case "ManagedRuleGroupStatement":
      // Use documented WCU for managed rule groups
      const managedStmt = statement as Statement extends infer S ? S extends { type: "ManagedRuleGroupStatement" } ? S : never : never;
      const managedGroup = MANAGED_RULE_GROUPS[managedStmt.name];
      baseWcu = managedGroup?.wcu || 200;
      break;

    case "RateBasedStatement":
      baseWcu = 2;
      break;

    case "RegexMatchStatement":
      baseWcu = 5;
      break;

    case "RegexPatternSetReferenceStatement":
      baseWcu = 5;
      break;

    case "SizeConstraintStatement":
      baseWcu = 1;
      break;

    case "SqliMatchStatement":
      baseWcu = 20;
      break;

    case "XssMatchStatement":
      baseWcu = 20;
      break;

    case "AndStatement":
    case "OrStatement":
      baseWcu = 1;
      break;

    case "NotStatement":
      baseWcu = 1;
      break;

    default:
      baseWcu = 1;
  }

  return baseWcu;
}
