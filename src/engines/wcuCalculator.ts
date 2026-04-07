// WAFSim - WCU (Web ACL Capacity Unit) Calculator
// Calculates WCU costs for custom rules based on AWS documentation

import {
  Rule,
  Statement,
  TextTransformation,
  WCUCostBreakdown,
} from "@/lib/types";
import { MANAGED_RULE_GROUPS } from "@/lib/managedRuleGroups";

/**
 * WCU costs for different statement types
 * Based on AWS WAF documentation
 */
const STATEMENT_BASE_WCU: Record<string, number> = {
  ByteMatchStatement: 3,
  GeoMatchStatement: 1,
  IPSetReferenceStatement: 1,
  LabelMatchStatement: 1,
  ManagedRuleGroupStatement: 0, // Variable, calculated separately
  RateBasedStatement: 2,
  RegexMatchStatement: 5,
  RegexPatternSetReferenceStatement: 5,
  SizeConstraintStatement: 1,
  SqliMatchStatement: 20,
  XssMatchStatement: 20,
  AndStatement: 1,
  OrStatement: 1,
  NotStatement: 1,
  RuleGroupReferenceStatement: 0, // Variable
};

/**
 * WCU costs for text transformations
 */
const TRANSFORMATION_WCU: Record<string, number> = {
  NONE: 0,
  LOWERCASE: 10,
  URL_DECODE: 10,
  URL_DECODE_UNI: 10,
  HTML_ENTITY_DECODE: 10,
  COMPRESS_WHITE_SPACE: 10,
  CMD_LINE: 10,
  BASE64_DECODE: 10,
  BASE64_DECODE_EXT: 10,
  HEX_DECODE: 10,
  MD5: 10,
  REPLACE_NULLS: 10,
  REMOVE_NULLS: 10,
  NORMALIZE_PATH: 10,
  NORMALIZE_PATH_WIN: 10,
};

/**
 * Maximum WCU for a Web ACL (5,000 per AWS docs; 1,500 included in base pricing)
 */
export const MAX_WCU = 5000;

/**
 * Base pricing tier threshold
 */
export const BASE_TIER_WCU = 1500;

/**
 * Warning threshold for WCU
 */
export const WARNING_WCU = 1200;

/**
 * Calculate WCU for a single rule
 */
export function calculateRuleWCU(rule: Rule): WCUCostBreakdown {
  const details: string[] = [];
  let base = 0;
  let transformations = 0;

  // Get base WCU for the statement
  const statementType = rule.statement.type;
  base = STATEMENT_BASE_WCU[statementType] || 1;
  details.push(`Base ${statementType}: ${base} WCU`);

  // Calculate transformation costs
  const transformationCost = calculateStatementTransformations(rule.statement);
  transformations = transformationCost.total;
  details.push(...transformationCost.details);

  // Handle special cases
  if (statementType === "ManagedRuleGroupStatement") {
    const managedStatement = rule.statement as Statement extends infer S ? S extends { type: "ManagedRuleGroupStatement" } ? S : never : never;
    const managedGroup = MANAGED_RULE_GROUPS[managedStatement.name];
    if (managedGroup) {
      base = managedGroup.wcu;
      details.push(`Managed rule group ${managedStatement.name}: ${base} WCU`);
    } else {
      base = 200; // Default estimate
      details.push(`Managed rule group (estimated): ${base} WCU`);
    }
  }

  if (statementType === "RateBasedStatement") {
    const rateStatement = rule.statement as Statement extends infer S ? S extends { type: "RateBasedStatement" } ? S : never : never;
    // Rate-based rules have higher cost for custom keys
    if (rateStatement.aggregateKeyType === "CUSTOM_KEYS") {
      const keyCount = rateStatement.aggregateKeys?.length || 0;
      base += keyCount * 2;
      details.push(`Custom aggregation keys: +${keyCount * 2} WCU`);
    }

    // Scope-down statement adds WCU
    if (rateStatement.scopeDownStatement) {
      const scopeDownCost = calculateStatementWCU(rateStatement.scopeDownStatement);
      base += scopeDownCost.total;
      details.push(`Scope-down statement: +${scopeDownCost.total} WCU`);
    }
  }

  // Handle nested statements
  if (statementType === "AndStatement" || statementType === "OrStatement") {
    const compoundStatement = rule.statement as Statement extends infer S ? S extends { type: "AndStatement" | "OrStatement" } ? S : never : never;
    const nestedCost = (compoundStatement.statements as Statement[]).reduce(
      (sum: number, stmt: Statement) => sum + calculateStatementWCU(stmt).total,
      0
    );
    base += nestedCost;
    details.push(`Nested statements: +${nestedCost} WCU`);
  }

  if (statementType === "NotStatement") {
    const notStatement = rule.statement as Statement extends infer S ? S extends { type: "NotStatement" } ? S : never : never;
    const nestedCost = calculateStatementWCU(notStatement.statement as Statement);
    base += nestedCost.total;
    details.push(`Nested statement: +${nestedCost.total} WCU`);
  }

  const total = base + transformations;

  return {
    base,
    transformations,
    total,
    details,
  };
}

/**
 * Calculate WCU for a statement (without action overhead)
 */
function calculateStatementWCU(statement: Statement): WCUCostBreakdown {
  const details: string[] = [];
  let base = STATEMENT_BASE_WCU[statement.type] || 1;
  let transformations = 0;

  const transformationCost = calculateStatementTransformations(statement);
  transformations = transformationCost.total;
  details.push(...transformationCost.details);

  return {
    base,
    transformations,
    total: base + transformations,
    details,
  };
}

/**
 * Calculate WCU for transformations in a statement
 */
function calculateStatementTransformations(statement: Statement): WCUCostBreakdown {
  const details: string[] = [];
  let total = 0;

  // Check for transformations in various statement types
  const statementWithTransformations = statement as Statement & {
    textTransformations?: TextTransformation[];
  };

  if (statementWithTransformations.textTransformations) {
    for (const transform of statementWithTransformations.textTransformations) {
      const cost = TRANSFORMATION_WCU[transform.type] || 0;
      total += cost;
      if (cost > 0) {
        details.push(`Transformation ${transform.type}: ${cost} WCU`);
      }
    }
  }

  return {
    base: 0,
    transformations: total,
    total,
    details,
  };
}

/**
 * Calculate total WCU for a Web ACL
 */
export function calculateWebACLUWCU(rules: Rule[]): {
  total: number;
  byRule: Map<string, WCUCostBreakdown>;
  breakdown: WCUCostBreakdown;
} {
  const byRule = new Map<string, WCUCostBreakdown>();
  let total = 0;
  const allDetails: string[] = [];

  for (const rule of rules) {
    const cost = calculateRuleWCU(rule);
    byRule.set(rule.name, cost);
    total += cost.total;
    allDetails.push(`Rule "${rule.name}": ${cost.total} WCU`);
  }

  return {
    total,
    byRule,
    breakdown: {
      base: total,
      transformations: 0,
      total,
      details: allDetails,
    },
  };
}

/**
 * Check if WCU exceeds limits
 */
export function checkWCULimits(wcu: number): {
  status: "ok" | "warning" | "exceeded";
  remaining: number;
  percentage: number;
  message: string;
} {
  const percentage = (wcu / MAX_WCU) * 100;
  const remaining = MAX_WCU - wcu;

  if (wcu > MAX_WCU) {
    return {
      status: "exceeded",
      remaining: 0,
      percentage,
      message: `WCU exceeded: ${wcu} > ${MAX_WCU} maximum`,
    };
  }

  if (wcu > WARNING_WCU) {
    return {
      status: "warning",
      remaining,
      percentage,
      message: `WCU warning: ${wcu} is close to ${MAX_WCU} maximum`,
    };
  }

  return {
    status: "ok",
    remaining,
    percentage,
    message: `WCU usage: ${wcu}/${MAX_WCU}`,
  };
}

/**
 * Get WCU cost for a managed rule group
 */
export function getManagedRuleGroupWCU(name: string): number {
  const group = MANAGED_RULE_GROUPS[name];
  return group?.wcu || 200;
}

/**
 * Estimate WCU for a rule before creating it
 */
export function estimateRuleWCU(
  statementType: Statement["type"],
  transformationCount: number = 0,
  hasNestedStatements: boolean = false
): number {
  let wcu = STATEMENT_BASE_WCU[statementType] || 1;

  // Add transformation costs (assume 10 WCU each)
  wcu += transformationCount * 10;

  // Add buffer for nested statements
  if (hasNestedStatements) {
    wcu += 10;
  }

  return wcu;
}

/**
 * Get WCU budget remaining after rules
 */
export function getWCUBudgetRemaining(rules: Rule[]): {
  used: number;
  remaining: number;
  percentage: number;
} {
  const { total } = calculateWebACLUWCU(rules);
  return {
    used: total,
    remaining: MAX_WCU - total,
    percentage: (total / MAX_WCU) * 100,
  };
}

/**
 * Optimize rule order for WCU efficiency
 * Lower WCU rules should be evaluated first when possible
 */
export function optimizeRuleOrderForWCU(rules: Rule[]): Rule[] {
  // Calculate WCU for each rule
  const rulesWithWCU = rules.map((rule) => ({
    rule,
    wcu: calculateRuleWCU(rule).total,
  }));

  // Sort by priority (maintain original order by priority)
  // But within same priority, prefer lower WCU
  return rulesWithWCU
    .sort((a, b) => {
      if (a.rule.priority !== b.rule.priority) {
        return a.rule.priority - b.rule.priority;
      }
      return a.wcu - b.wcu;
    })
    .map((item) => item.rule);
}
