// WAFSim - Statement Evaluator Engine
// Evaluates all 14 AWS WAF statement types

import {
  Statement,
  HttpRequest,
  IPSet,
  RegexPatternSet,
  PositionalConstraint,
  SizeComparisonOperator,
  RateBasedStatement,
  ManagedRuleGroupStatement,
} from "@/lib/types";
import { applyTransformations } from "./textTransformations";
import { extractField } from "./fieldExtractor";
import { detectSQLInjection, getSQLInjectionMatch } from "./sqliDetector";
import { detectXSS, getXSSMatch } from "./xssDetector";

// Context passed to statement evaluators
export interface EvaluationContext {
  request: HttpRequest;
  labelsApplied: string[];
  ipSets: Map<string, IPSet>;
  regexPatternSets: Map<string, RegexPatternSet>;
  requestTimestamp: number;
  rateTracking?: RateTrackingState;
  managedRuleGroupModels?: Map<string, ManagedRuleGroupModel>;
}

// Rate tracking state for rate-based rules
export interface RateTrackingState {
  requestCounts: Map<string, number[]>; // key -> timestamps
  windowMs: number;
}

// Managed rule group model for simulation
export interface ManagedRuleGroupModel {
  name: string;
  vendorName: string;
  wcu: number;
  rules: ManagedRuleModel[];
  labelNamespace: string;
}

export interface ManagedRuleModel {
  name: string;
  description: string;
  defaultAction: "Block" | "Count";
  addedLabels: string[];
  simulationCriteria?: SimulationCriteria;
}

export interface SimulationCriteria {
  type: string;
  field?: string;
  pattern?: string | RegExp;
  patterns?: (string | RegExp)[];
  operator?: string;
  value?: string | number | string[];
}

/**
 * Main statement evaluator entry point
 */
export function evaluateStatement(
  statement: Statement,
  context: EvaluationContext
): { matched: boolean; reason: string; matchedContent?: string; transformedContent?: string } {
  switch (statement.type) {
    case "ByteMatchStatement":
      return evaluateByteMatch(statement, context);
    case "GeoMatchStatement":
      return evaluateGeoMatch(statement, context);
    case "IPSetReferenceStatement":
      return evaluateIPSetReference(statement, context);
    case "LabelMatchStatement":
      return evaluateLabelMatch(statement, context);
    case "ManagedRuleGroupStatement":
      return evaluateManagedRuleGroup(statement, context);
    case "RateBasedStatement":
      return evaluateRateBased(statement, context);
    case "RegexMatchStatement":
      return evaluateRegexMatch(statement, context);
    case "RegexPatternSetReferenceStatement":
      return evaluateRegexPatternSetReference(statement, context);
    case "SizeConstraintStatement":
      return evaluateSizeConstraint(statement, context);
    case "SqliMatchStatement":
      return evaluateSqliMatch(statement, context);
    case "XssMatchStatement":
      return evaluateXssMatch(statement, context);
    case "AndStatement":
      return evaluateAnd(statement, context);
    case "OrStatement":
      return evaluateOr(statement, context);
    case "NotStatement":
      return evaluateNot(statement, context);
    case "RuleGroupReferenceStatement":
      return evaluateRuleGroupReference(statement, context);
    default:
      return { matched: false, reason: `Unknown statement type: ${(statement as Statement).type}` };
  }
}

/**
 * Byte Match Statement evaluation
 */
function evaluateByteMatch(
  statement: {
    searchString: string;
    fieldToMatch: Statement extends infer S ? S extends { type: "ByteMatchStatement" } ? S["fieldToMatch"] : never : never;
    textTransformations: Statement extends infer S ? S extends { type: "ByteMatchStatement" } ? S["textTransformations"] : never : never;
    positionalConstraint: PositionalConstraint;
  },
  context: EvaluationContext
): { matched: boolean; reason: string; matchedContent?: string; transformedContent?: string } {
  // Extract field content
  const { content: fieldContent } = extractField(context.request, statement.fieldToMatch as Statement extends infer S ? S extends { type: "ByteMatchStatement" } ? S["fieldToMatch"] : never : never);

  // Apply text transformations
  const transformedContent = applyTransformations(fieldContent, statement.textTransformations as Statement extends infer S ? S extends { type: "ByteMatchStatement" } ? S["textTransformations"] : never : never);

  // Match based on positional constraint
  const searchString = statement.searchString;
  let matched = false;
  let matchReason = "";

  switch (statement.positionalConstraint) {
    case "EXACTLY":
      matched = transformedContent === searchString;
      matchReason = matched
        ? `Exact match: "${searchString}"`
        : `No exact match for "${searchString}"`;
      break;

    case "STARTS_WITH":
      matched = transformedContent.startsWith(searchString);
      matchReason = matched
        ? `Starts with: "${searchString}"`
        : `Does not start with "${searchString}"`;
      break;

    case "ENDS_WITH":
      matched = transformedContent.endsWith(searchString);
      matchReason = matched
        ? `Ends with: "${searchString}"`
        : `Does not end with "${searchString}"`;
      break;

    case "CONTAINS":
      matched = transformedContent.includes(searchString);
      matchReason = matched
        ? `Contains: "${searchString}"`
        : `Does not contain "${searchString}"`;
      break;

    case "CONTAINS_WORD":
      // Word boundary aware matching - AWS WAF ByteMatch is case-sensitive
      const wordRegex = new RegExp(`\\b${escapeRegex(searchString)}\\b`);
      matched = wordRegex.test(transformedContent);
      matchReason = matched
        ? `Contains word: "${searchString}"`
        : `Does not contain word "${searchString}"`;
      break;

    default:
      matched = false;
      matchReason = `Unknown positional constraint: ${statement.positionalConstraint}`;
  }

  return {
    matched,
    reason: matchReason,
    matchedContent: fieldContent,
    transformedContent,
  };
}

/**
 * Geo Match Statement evaluation
 */
function evaluateGeoMatch(
  statement: {
    countryCodes: string[];
    forwardedIPConfig?: { headerName: string; fallbackBehavior: "MATCH" | "NO_MATCH" };
  },
  context: EvaluationContext
): { matched: boolean; reason: string } {
  let sourceCountry = context.request.country;

  // Handle forwarded IP if configured
  if (statement.forwardedIPConfig) {
    const forwardedIP = context.request.headers?.find(
      (h) => h.name.toLowerCase() === statement.forwardedIPConfig!.headerName.toLowerCase()
    )?.value;

    if (forwardedIP) {
      // In a real implementation, we'd look up the country for the forwarded IP
      // For simulation, we use the request's country or the first segment of the IP
      sourceCountry = context.request.country;
    } else {
      // Fallback behavior
      if (statement.forwardedIPConfig.fallbackBehavior === "MATCH") {
        return { matched: true, reason: "Forwarded IP header not found, fallback matched" };
      }
      return { matched: false, reason: "Forwarded IP header not found, fallback no match" };
    }
  }

  const normalizedCountry = sourceCountry?.toUpperCase() || "";
  const matched = statement.countryCodes.map((c) => c.toUpperCase()).includes(normalizedCountry);

  return {
    matched,
    reason: matched
      ? `Country ${normalizedCountry} matches country list`
      : `Country ${normalizedCountry} not in list: ${statement.countryCodes.join(", ")}`,
  };
}

/**
 * IP Set Reference Statement evaluation
 */
function evaluateIPSetReference(
  statement: {
    arn: string;
    ipSetReference?: { arn: string };
    forwardedIPConfig?: { headerName: string; fallbackBehavior: "MATCH" | "NO_MATCH" };
  },
  context: EvaluationContext
): { matched: boolean; reason: string } {
  const arn = statement.arn || statement.ipSetReference?.arn;
  const ipSet = context.ipSets.get(arn);

  if (!ipSet) {
    return { matched: false, reason: `IP Set not found: ${arn}` };
  }

  let sourceIP = context.request.sourceIP;

  // Handle forwarded IP if configured
  if (statement.forwardedIPConfig) {
    const forwardedIP = context.request.headers?.find(
      (h) => h.name.toLowerCase() === statement.forwardedIPConfig!.headerName.toLowerCase()
    )?.value;

    if (forwardedIP) {
      sourceIP = forwardedIP.split(",")[0].trim(); // Take first IP if multiple
    } else if (statement.forwardedIPConfig.fallbackBehavior === "MATCH") {
      return { matched: true, reason: "Forwarded IP header not found, fallback matched" };
    }
  }

  // Check if IP matches any CIDR in the set
  const matched = ipSet.addresses.some((cidr) => ipInCIDR(sourceIP, cidr));

  return {
    matched,
    reason: matched
      ? `Source IP ${sourceIP} matches IP set "${ipSet.name}"`
      : `Source IP ${sourceIP} not in IP set "${ipSet.name}"`,
  };
}

/**
 * Label Match Statement evaluation
 */
function evaluateLabelMatch(
  statement: {
    key: string;
    scope: "LABEL" | "NAMESPACE";
  },
  context: EvaluationContext
): { matched: boolean; reason: string } {
  const labelsApplied = context.labelsApplied;

  if (statement.scope === "LABEL") {
    // Exact label match
    const matched = labelsApplied.includes(statement.key);
    return {
      matched,
      reason: matched
        ? `Label "${statement.key}" was applied by earlier rule`
        : `Label "${statement.key}" not found in applied labels`,
    };
  } else {
    // Namespace prefix match
    const matched = labelsApplied.some((label) => label.startsWith(statement.key));
    return {
      matched,
      reason: matched
        ? `Label namespace "${statement.key}" matched`
        : `No labels in namespace "${statement.key}"`,
    };
  }
}

/**
 * Managed Rule Group Statement evaluation
 * This is an approximation based on documented behavior
 */
function evaluateManagedRuleGroup(
  statement: ManagedRuleGroupStatement,
  context: EvaluationContext
): { matched: boolean; reason: string; approximated: boolean } {
  const model = context.managedRuleGroupModels?.get(statement.name);

  if (!model) {
    return {
      matched: false,
      reason: `Managed rule group model not found: ${statement.name}`,
      approximated: true,
    };
  }

  // Check each rule in the managed group
  const matchedRules: string[] = [];
  const excludedRules = new Set(statement.excludedRules || []);

  for (const rule of model.rules) {
    if (excludedRules.has(rule.name)) {
      continue;
    }

    const ruleMatched = evaluateManagedRule(rule, context, statement.managedRuleGroupConfigs);

    if (ruleMatched) {
      matchedRules.push(rule.name);

      // Check for action override
      const actionOverride = statement.ruleActionOverrides?.find(
        (o) => o.name === rule.name
      );

      // Add labels for matched rule
      for (const label of rule.addedLabels) {
        const fullLabel = model.labelNamespace + label;
        if (!context.labelsApplied.includes(fullLabel)) {
          context.labelsApplied.push(fullLabel);
        }
      }

      // For managed rule groups, first match terminates unless COUNT
      const effectiveAction = actionOverride?.actionToUse ||
        (rule.defaultAction === "Count" ? "COUNT" : rule.defaultAction.toUpperCase());

      if (effectiveAction !== "COUNT") {
        return {
          matched: true,
          reason: `Managed rule "${rule.name}" matched (approximated behavior)`,
          approximated: true,
        };
      }
    }
  }

  if (matchedRules.length > 0) {
    return {
      matched: true,
      reason: `Managed rules matched (COUNT action): ${matchedRules.join(", ")} (approximated)`,
      approximated: true,
    };
  }

  return {
    matched: false,
    reason: `No managed rules matched in ${statement.name} (approximated)`,
    approximated: true,
  };
}

/**
 * Unescape a pattern string that may contain regex escapes
 * Converts \\$ to $, \\. to ., etc. for literal matching
 */
function unescapePattern(pattern: string): string {
  try {
    // Handle common regex escapes
    return pattern
      .replace(/\\\$/g, '$')
      .replace(/\\\./g, '.')
      .replace(/\\\*/g, '*')
      .replace(/\\\+/g, '+')
      .replace(/\\\?/g, '?')
      .replace(/\\\^/g, '^')
      .replace(/\\\(/g, '(')
      .replace(/\\\)/g, ')')
      .replace(/\\\[/g, '[')
      .replace(/\\\]/g, ']')
      .replace(/\\\{/g, '{')
      .replace(/\\\}/g, '}')
      .replace(/\\:/g, ':')
      .replace(/\\-/g, '-')
      .replace(/\\_/g, '_')
      .replace(/\\\\/g, '\\');
  } catch {
    return pattern;
  }
}

/**
 * Check if a pattern matches content
 * Handles both literal strings and regex-escaped patterns
 */
function patternMatches(content: string, pattern: string): boolean {
  const lowerContent = content.toLowerCase();
  
  // First try direct match
  if (lowerContent.includes(pattern.toLowerCase())) {
    return true;
  }
  
  // Then try unescaped match (for patterns like \\$\\{jndi:)
  const unescaped = unescapePattern(pattern);
  if (unescaped !== pattern && lowerContent.includes(unescaped.toLowerCase())) {
    return true;
  }
  
  return false;
}

/**
 * Evaluate a single managed rule
 */
function evaluateManagedRule(
  rule: ManagedRuleModel,
  context: EvaluationContext,
  configs?: ManagedRuleGroupStatement["managedRuleGroupConfigs"]
): boolean {
  if (!rule.simulationCriteria) {
    // No criteria defined - can't evaluate, default to no match
    return false;
  }

  const criteria = rule.simulationCriteria;

  switch (criteria.type) {
    case "header_absent": {
      const headerExists = context.request.headers?.some(
        (h) => h.name.toLowerCase() === (criteria.field || "").toLowerCase()
      );
      return !headerExists;
    }

    case "header_match": {
      // Handle "any" field to check all headers
      if ((criteria.field || "").toLowerCase() === "any") {
        const allHeadersValue = context.request.headers?.map(h => h.value).join(" ") || "";
        if (criteria.pattern instanceof RegExp) {
          return criteria.pattern.test(allHeadersValue);
        }
        const anyHeaderPatterns = String(criteria.pattern).split("|");
        return anyHeaderPatterns.some(p => patternMatches(allHeadersValue, p));
      }
      const header = context.request.headers?.find(
        (h) => h.name.toLowerCase() === (criteria.field || "").toLowerCase()
      );
      if (!header) return false;
      if (criteria.pattern instanceof RegExp) {
        return criteria.pattern.test(header.value);
      }
      // Treat pipe-separated patterns as alternatives
      const headerPatterns = String(criteria.pattern).split("|");
      return headerPatterns.some(p => patternMatches(header.value, p));
    }

    case "uri_pattern": {
      const uri = context.request.uri;
      if (criteria.pattern instanceof RegExp) {
        return criteria.pattern.test(uri);
      }
      // Treat pipe-separated patterns as alternatives
      const uriPatterns = String(criteria.pattern).split("|");
      return uriPatterns.some(p => patternMatches(uri, p));
    }

    case "query_pattern": {
      const fullQueryString = context.request.uri.split("?")[1] || "";
      // If no field specified, check the entire query string
      if (!criteria.field) {
        if (criteria.pattern instanceof RegExp) {
          return criteria.pattern.test(fullQueryString);
        }
        // Treat pipe-separated patterns as alternatives
        const patterns = String(criteria.pattern).split("|");
        return patterns.some(p => patternMatches(fullQueryString, p));
      }
      // Otherwise check specific parameter
      const query = new URLSearchParams(fullQueryString);
      const paramValue = query.get(criteria.field) || "";
      if (criteria.pattern instanceof RegExp) {
        return criteria.pattern.test(paramValue);
      }
      // Treat pipe-separated patterns as alternatives
      const fieldPatterns = String(criteria.pattern).split("|");
      return fieldPatterns.some(p => patternMatches(paramValue, p));
    }

    case "body_pattern": {
      const body = context.request.body || "";
      if (criteria.pattern instanceof RegExp) {
        return criteria.pattern.test(body);
      }
      // Treat pipe-separated patterns as alternatives
      const bodyPatterns = String(criteria.pattern).split("|");
      return bodyPatterns.some(p => patternMatches(body, p));
    }

    case "method_check":
      return context.request.method.toUpperCase() === (criteria.value || "").toString().toUpperCase();

    case "size_check": {
      const size = parseInt(String(criteria.value)) || 0;
      let contentToCheck = "";
      
      if (criteria.field === "body") {
        contentToCheck = context.request.body || "";
      } else if (criteria.field === "uri") {
        contentToCheck = context.request.uri;
      } else if (criteria.field === "query") {
        contentToCheck = context.request.uri.split("?")[1] || "";
      }
      
      if (criteria.operator === "exceeds") {
        return contentToCheck.length > size;
      }
      return contentToCheck.length === size;
    }

    case "ip_in_list": {
      const ipPatterns = (criteria.patterns as string[]) || [];
      // Also check if pattern (singular) is an array
      if (!ipPatterns.length && criteria.pattern) {
        const patternArr = String(criteria.pattern).split(",");
        return patternArr.some(p => context.request.sourceIP === p.trim());
      }
      return ipPatterns.includes(context.request.sourceIP);
    }

    case "custom": {
      // Custom criteria - evaluate based on operator and value
      if (criteria.operator === "contains" && criteria.value) {
        const valueStr = String(criteria.value);
        if (criteria.field === "body") {
          return (context.request.body || "").includes(valueStr);
        } else if (criteria.field === "uri") {
          return context.request.uri.includes(valueStr);
        } else if (!criteria.field || criteria.field === "any") {
          // Check all fields - headers, body, URI
          const headerMatch = context.request.headers?.some(h => h.value.includes(valueStr)) || false;
          return (context.request.body || "").includes(valueStr) ||
                 context.request.uri.includes(valueStr) ||
                 headerMatch;
        }
      }
      if (criteria.operator === "equals" && criteria.value) {
        return criteria.field === "country"
          ? context.request.country === criteria.value
          : false;
      }
      return false;
    }

    default:
      return false;
  }
}

/**
 * Rate Based Statement evaluation
 */
function evaluateRateBased(
  statement: RateBasedStatement,
  context: EvaluationContext
): { matched: boolean; reason: string } {
  // Get the rate tracking key
  const rateKey = getRateKey(statement, context);

  if (!rateKey) {
    return { matched: false, reason: "Could not determine rate tracking key" };
  }

  // Check rate tracking state
  if (!context.rateTracking) {
    // No rate tracking - this is a single request evaluation
    // Return would potentially trigger
    return {
      matched: false,
      reason: `Rate-based rule: would evaluate if rate > ${statement.rateLimit}/min for key "${rateKey}"`,
    };
  }

  // Get request count for this key in the window
  const timestamps = context.rateTracking.requestCounts.get(rateKey) || [];
  const windowStart = context.requestTimestamp - statement.evaluationWindowSec * 1000;
  const recentRequests = timestamps.filter((t) => t > windowStart);

  const currentRate = recentRequests.length;
  const matched = currentRate > statement.rateLimit;

  // Check scope-down statement if present
  if (statement.scopeDownStatement) {
    const scopeResult = evaluateStatement(statement.scopeDownStatement, context);
    if (!scopeResult.matched) {
      return {
        matched: false,
        reason: `Rate-based rule: scope-down statement did not match`,
      };
    }
  }

  return {
    matched,
    reason: matched
      ? `Rate limit exceeded: ${currentRate} requests > ${statement.rateLimit} limit`
      : `Rate within limit: ${currentRate}/${statement.rateLimit} requests`,
  };
}

/**
 * Get the rate tracking key for a request
 */
function getRateKey(statement: RateBasedStatement, context: EvaluationContext): string | null {
  switch (statement.aggregateKeyType) {
    case "IP":
      return `ip:${context.request.sourceIP}`;

    case "FORWARDED_IP":
      const forwardedHeader = statement.forwardedIPConfig?.headerName || "X-Forwarded-For";
      const forwardedIP = context.request.headers?.find(
        (h) => h.name.toLowerCase() === forwardedHeader.toLowerCase()
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
          keyParts.push(context.request.sourceIP);
        } else if (key.forwardedIP) {
          const fwdHeader = statement.forwardedIPConfig?.headerName || "X-Forwarded-For";
          const fwdIP = context.request.headers?.find(
            (h) => h.name.toLowerCase() === fwdHeader.toLowerCase()
          )?.value;
          keyParts.push(fwdIP?.split(",")[0].trim() || "");
        } else if (key.header && key.header.name) {
          const headerVal = context.request.headers?.find(
            (h) => h.name.toLowerCase() === key.header!.name.toLowerCase()
          )?.value || "";
          keyParts.push(headerVal);
        } else if (key.cookie && key.cookie.name) {
          const cookies = context.request.headers?.find((h) => h.name.toLowerCase() === "cookie")?.value || "";
          const cookieMatch = cookies.match(new RegExp(`${key.cookie.name}=([^;]+)`));
          keyParts.push(cookieMatch?.[1] || "");
        } else if (key.queryArgument && key.queryArgument.name) {
          const params = new URLSearchParams(context.request.uri.split("?")[1] || "");
          keyParts.push(params.get(key.queryArgument.name) || "");
        } else if (key.queryString) {
          keyParts.push(context.request.uri.split("?")[1] || "");
        } else if (key.httpMethod) {
          keyParts.push(context.request.method);
        } else if (key.uriPath) {
          keyParts.push(context.request.uri.split("?")[0]);
        } else if (key.labelNamespace && key.labelNamespace.namespace) {
          const matchingLabels = context.labelsApplied.filter((l) =>
            l.startsWith(key.labelNamespace!.namespace)
          );
          keyParts.push(matchingLabels.join(","));
        }
      }
      return `custom:${keyParts.join(":")}`;

    default:
      return null;
  }
}

/**
 * Regex Match Statement evaluation
 */
function evaluateRegexMatch(
  statement: {
    regexString: string;
    fieldToMatch: Statement extends infer S ? S extends { type: "RegexMatchStatement" } ? S["fieldToMatch"] : never : never;
    textTransformations: Statement extends infer S ? S extends { type: "RegexMatchStatement" } ? S["textTransformations"] : never : never;
  },
  context: EvaluationContext
): { matched: boolean; reason: string; matchedContent?: string; transformedContent?: string } {
  const { content: fieldContent } = extractField(context.request, statement.fieldToMatch as Statement extends infer S ? S extends { type: "RegexMatchStatement" } ? S["fieldToMatch"] : never : never);
  const transformedContent = applyTransformations(fieldContent, statement.textTransformations as Statement extends infer S ? S extends { type: "RegexMatchStatement" } ? S["textTransformations"] : never : never);

  try {
    const regex = new RegExp(statement.regexString, "i");
    const matched = regex.test(transformedContent);

    return {
      matched,
      reason: matched
        ? `Regex "${statement.regexString}" matched`
        : `Regex "${statement.regexString}" did not match`,
      matchedContent: fieldContent,
      transformedContent,
    };
  } catch (e) {
    return {
      matched: false,
      reason: `Invalid regex: ${statement.regexString} - ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/**
 * Regex Pattern Set Reference Statement evaluation
 */
function evaluateRegexPatternSetReference(
  statement: {
    arn: string;
    fieldToMatch: Statement extends infer S ? S extends { type: "RegexPatternSetReferenceStatement" } ? S["fieldToMatch"] : never : never;
    textTransformations: Statement extends infer S ? S extends { type: "RegexPatternSetReferenceStatement" } ? S["textTransformations"] : never : never;
  },
  context: EvaluationContext
): { matched: boolean; reason: string; matchedContent?: string; transformedContent?: string } {
  const patternSet = context.regexPatternSets.get(statement.arn);

  if (!patternSet) {
    return { matched: false, reason: `Regex Pattern Set not found: ${statement.arn}` };
  }

  const { content: fieldContent } = extractField(context.request, statement.fieldToMatch as Statement extends infer S ? S extends { type: "RegexPatternSetReferenceStatement" } ? S["fieldToMatch"] : never : never);
  const transformedContent = applyTransformations(fieldContent, statement.textTransformations as Statement extends infer S ? S extends { type: "RegexPatternSetReferenceStatement" } ? S["textTransformations"] : never : never);

  // Check each pattern in the set
  for (const pattern of patternSet.regularExpressionList) {
    try {
      const regex = new RegExp(pattern, "i");
      if (regex.test(transformedContent)) {
        return {
          matched: true,
          reason: `Pattern "${pattern}" from set "${patternSet.name}" matched`,
          matchedContent: fieldContent,
          transformedContent,
        };
      }
    } catch {
      // Invalid regex, skip
      continue;
    }
  }

  return {
    matched: false,
    reason: `No patterns in set "${patternSet.name}" matched`,
    matchedContent: fieldContent,
    transformedContent,
  };
}

/**
 * Size Constraint Statement evaluation
 */
function evaluateSizeConstraint(
  statement: {
    fieldToMatch: Statement extends infer S ? S extends { type: "SizeConstraintStatement" } ? S["fieldToMatch"] : never : never;
    comparisonOperator: SizeComparisonOperator;
    size: number;
    textTransformations: Statement extends infer S ? S extends { type: "SizeConstraintStatement" } ? S["textTransformations"] : never : never;
  },
  context: EvaluationContext
): { matched: boolean; reason: string; matchedContent?: string; transformedContent?: string } {
  const { content: fieldContent } = extractField(context.request, statement.fieldToMatch as Statement extends infer S ? S extends { type: "SizeConstraintStatement" } ? S["fieldToMatch"] : never : never);
  const transformedContent = applyTransformations(fieldContent, statement.textTransformations as Statement extends infer S ? S extends { type: "SizeConstraintStatement" } ? S["textTransformations"] : never : never);

  const size = transformedContent.length;
  let matched = false;
  let comparisonDesc = "";

  switch (statement.comparisonOperator) {
    case "EQ":
      matched = size === statement.size;
      comparisonDesc = `equal to`;
      break;
    case "NE":
      matched = size !== statement.size;
      comparisonDesc = `not equal to`;
      break;
    case "LE":
      matched = size <= statement.size;
      comparisonDesc = `less than or equal to`;
      break;
    case "LT":
      matched = size < statement.size;
      comparisonDesc = `less than`;
      break;
    case "GE":
      matched = size >= statement.size;
      comparisonDesc = `greater than or equal to`;
      break;
    case "GT":
      matched = size > statement.size;
      comparisonDesc = `greater than`;
      break;
  }

  return {
    matched,
    reason: matched
      ? `Size ${size} is ${comparisonDesc} ${statement.size}`
      : `Size ${size} is not ${comparisonDesc} ${statement.size}`,
    matchedContent: fieldContent,
    transformedContent,
  };
}

/**
 * SQLi Match Statement evaluation
 */
function evaluateSqliMatch(
  statement: {
    fieldToMatch: Statement extends infer S ? S extends { type: "SqliMatchStatement" } ? S["fieldToMatch"] : never : never;
    textTransformations: Statement extends infer S ? S extends { type: "SqliMatchStatement" } ? S["textTransformations"] : never : never;
    sensitivityLevel?: "LOW" | "HIGH";
  },
  context: EvaluationContext
): { matched: boolean; reason: string; matchedContent?: string; transformedContent?: string } {
  const { content: fieldContent } = extractField(context.request, statement.fieldToMatch as Statement extends infer S ? S extends { type: "SqliMatchStatement" } ? S["fieldToMatch"] : never : never);
  const transformedContent = applyTransformations(fieldContent, statement.textTransformations as Statement extends infer S ? S extends { type: "SqliMatchStatement" } ? S["textTransformations"] : never : never);

  const sensitivity = statement.sensitivityLevel || "LOW";
  const matchResult = getSQLInjectionMatch(transformedContent, sensitivity);

  if (matchResult.detected) {
    const details = [
      matchResult.matchedPatterns.length > 0 ? `patterns: ${matchResult.matchedPatterns.slice(0, 3).join(", ")}` : "",
      matchResult.matchedKeywords.length > 0 ? `keywords: ${matchResult.matchedKeywords.slice(0, 5).join(", ")}` : "",
    ].filter(Boolean).join("; ");

    return {
      matched: true,
      reason: `SQL injection detected (${sensitivity} sensitivity): ${details}`,
      matchedContent: fieldContent,
      transformedContent,
    };
  }

  return {
    matched: false,
    reason: `No SQL injection detected (${sensitivity} sensitivity)`,
    matchedContent: fieldContent,
    transformedContent,
  };
}

/**
 * XSS Match Statement evaluation
 */
function evaluateXssMatch(
  statement: {
    fieldToMatch: Statement extends infer S ? S extends { type: "XssMatchStatement" } ? S["fieldToMatch"] : never : never;
    textTransformations: Statement extends infer S ? S extends { type: "XssMatchStatement" } ? S["textTransformations"] : never : never;
    sensitivityLevel?: "LOW" | "HIGH";
  },
  context: EvaluationContext
): { matched: boolean; reason: string; matchedContent?: string; transformedContent?: string } {
  const { content: fieldContent } = extractField(context.request, statement.fieldToMatch as Statement extends infer S ? S extends { type: "XssMatchStatement" } ? S["fieldToMatch"] : never : never);
  const transformedContent = applyTransformations(fieldContent, statement.textTransformations as Statement extends infer S ? S extends { type: "XssMatchStatement" } ? S["textTransformations"] : never : never);

  const sensitivity = statement.sensitivityLevel || "HIGH";
  const matchResult = getXSSMatch(transformedContent, sensitivity);

  if (matchResult.detected) {
    const details = [
      matchResult.matchedTags.length > 0 ? `tags: ${matchResult.matchedTags.join(", ")}` : "",
      matchResult.matchedEvents.length > 0 ? `events: ${matchResult.matchedEvents.slice(0, 5).join(", ")}` : "",
      matchResult.matchedSchemes.length > 0 ? `schemes: ${matchResult.matchedSchemes.join(", ")}` : "",
    ].filter(Boolean).join("; ");

    return {
      matched: true,
      reason: `XSS detected (${sensitivity} sensitivity): ${details}`,
      matchedContent: fieldContent,
      transformedContent,
    };
  }

  return {
    matched: false,
    reason: `No XSS detected (${sensitivity} sensitivity)`,
    matchedContent: fieldContent,
    transformedContent,
  };
}

/**
 * AND Statement evaluation
 */
function evaluateAnd(
  statement: { statements: Statement[] },
  context: EvaluationContext
): { matched: boolean; reason: string } {
  if (!statement.statements || statement.statements.length === 0) {
    return { matched: false, reason: "AND statement has no child statements" };
  }

  const results: { matched: boolean; reason: string }[] = [];

  for (const childStatement of statement.statements) {
    const result = evaluateStatement(childStatement, context);
    results.push(result);

    if (!result.matched) {
      return {
        matched: false,
        reason: `AND failed: ${result.reason}`,
      };
    }
  }

  return {
    matched: true,
    reason: `All ${results.length} conditions matched (AND)`,
  };
}

/**
 * OR Statement evaluation
 */
function evaluateOr(
  statement: { statements: Statement[] },
  context: EvaluationContext
): { matched: boolean; reason: string } {
  if (!statement.statements || statement.statements.length === 0) {
    return { matched: false, reason: "OR statement has no child statements" };
  }

  const results: { matched: boolean; reason: string }[] = [];

  for (const childStatement of statement.statements) {
    const result = evaluateStatement(childStatement, context);
    results.push(result);

    if (result.matched) {
      return {
        matched: true,
        reason: `OR matched: ${result.reason}`,
      };
    }
  }

  return {
    matched: false,
    reason: `None of ${results.length} conditions matched (OR)`,
  };
}

/**
 * NOT Statement evaluation
 */
function evaluateNot(
  statement: { statement: Statement },
  context: EvaluationContext
): { matched: boolean; reason: string } {
  if (!statement.statement) {
    return { matched: false, reason: "NOT statement has no child statement" };
  }

  const result = evaluateStatement(statement.statement, context);

  return {
    matched: !result.matched,
    reason: !result.matched
      ? `NOT matched (child did not match: ${result.reason})`
      : `NOT not matched (child matched: ${result.reason})`,
  };
}

/**
 * Rule Group Reference Statement evaluation
 * Simplified - treats referenced rule group as nested rules
 */
function evaluateRuleGroupReference(
  statement: {
    arn: string;
    excludedRules?: string[];
    ruleActionOverrides?: Array<{ name: string; actionToUse: string }>;
  },
  context: EvaluationContext
): { matched: boolean; reason: string } {
  // For simulation, we would need to look up the rule group definition
  // This is a placeholder for custom rule groups

  return {
    matched: false,
    reason: `Rule group reference not implemented: ${statement.arn}`,
  };
}

/**
 * Utility: Check if an IP is within a CIDR block
 */
function ipInCIDR(ip: string, cidr: string): boolean {
  try {
    // Handle IPv4
    if (ip.includes(".") && cidr.includes(".")) {
      const [cidrIp, prefixLength] = cidr.split("/");
      const prefix = parseInt(prefixLength) || 32;

      const ipNum = ipToNumber(ip);
      const cidrNum = ipToNumber(cidrIp);
      const mask = prefix === 0 ? 0 : ~((1 << (32 - prefix)) - 1);

      return (ipNum & mask) === (cidrNum & mask);
    }

    // Handle IPv6 (simplified - just exact match for now)
    if (ip.includes(":") && cidr.includes(":")) {
      const [cidrIp] = cidr.split("/");
      return normalizeIPv6(ip) === normalizeIPv6(cidrIp);
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Convert IPv4 address to number
 */
function ipToNumber(ip: string): number {
  const parts = ip.split(".").map((p) => parseInt(p) || 0);
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/**
 * Normalize IPv6 address
 */
function normalizeIPv6(ip: string): string {
  // Simplified normalization
  return ip.toLowerCase().replace(/::/g, ":0:0:0:0:0:0:0:");
}

/**
 * Escape regex special characters
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
