// WAFSim - Import Engine
// Parses AWS WAFv2 GetWebACL JSON into WAFSim internal types

import {
  WebACL,
  Rule,
  Statement,
  WAFAction,
  OverrideAction,
  FieldToMatch,
  TextTransformation,
  VisibilityConfig,
  RuleActionOverride,
} from "@/lib/types";
import { v4 as uuidv4 } from "uuid";

export interface ImportResult {
  success: boolean;
  webACL?: WebACL;
  errors: string[];
  warnings: string[];
}

export function importWebACLJson(jsonStr: string): ImportResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(jsonStr);
  } catch {
    return { success: false, errors: ["Invalid JSON"], warnings: [] };
  }

  // Handle GetWebACL response wrapper
  const webACLData = (raw.WebACL || raw) as Record<string, unknown>;

  if (!webACLData.Name) {
    return { success: false, errors: ["Missing required field: Name"], warnings: [] };
  }

  const rules: Rule[] = [];
  const rawRules = (webACLData.Rules || []) as Record<string, unknown>[];

  for (const rawRule of rawRules) {
    try {
      rules.push(parseRule(rawRule, warnings));
    } catch (e) {
      errors.push(`Failed to parse rule "${rawRule.Name || "unknown"}": ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  const defaultActionRaw = webACLData.DefaultAction as Record<string, unknown> | undefined;
  const defaultAction: WAFAction = defaultActionRaw?.Block ? "BLOCK" : "ALLOW";

  const visRaw = webACLData.VisibilityConfig as Record<string, unknown> | undefined;
  const visibilityConfig: VisibilityConfig = {
    sampledRequestsEnabled: (visRaw?.SampledRequestsEnabled as boolean) ?? true,
    cloudWatchMetricsEnabled: (visRaw?.CloudWatchMetricsEnabled as boolean) ?? true,
    metricName: (visRaw?.MetricName as string) || (webACLData.Name as string),
  };

  const scope = (webACLData.Scope as string)?.toUpperCase() === "CLOUDFRONT" ? "CLOUDFRONT" : "REGIONAL";

  const webACL: WebACL = {
    id: uuidv4(),
    name: webACLData.Name as string,
    description: (webACLData.Description as string) || "",
    scope: scope as "CLOUDFRONT" | "REGIONAL",
    defaultAction,
    rules: rules.sort((a, b) => a.priority - b.priority),
    visibilityConfig,
    capacity: 0,
  };

  return { success: errors.length === 0, webACL, errors, warnings };
}

function parseRule(raw: Record<string, unknown>, warnings: string[]): Rule {
  const name = raw.Name as string;
  if (!name) throw new Error("Rule missing Name");

  const priority = (raw.Priority as number) ?? 0;
  const statement = parseStatement(raw.Statement as Record<string, unknown>, warnings);

  // Determine action
  let action: WAFAction = "BLOCK";
  let overrideAction: OverrideAction | undefined;

  if (raw.OverrideAction) {
    const oa = raw.OverrideAction as Record<string, unknown>;
    overrideAction = oa.Count ? "COUNT" : "NONE";
    action = "BLOCK"; // placeholder, managed rules use overrideAction
  } else if (raw.Action) {
    const a = raw.Action as Record<string, unknown>;
    if (a.Allow) action = "ALLOW";
    else if (a.Block) action = "BLOCK";
    else if (a.Count) action = "COUNT";
    else if (a.Captcha) action = "CAPTCHA";
    else if (a.Challenge) action = "CHALLENGE";
  }

  const visRaw = raw.VisibilityConfig as Record<string, unknown> | undefined;
  const ruleLabelsRaw = raw.RuleLabels as Array<{ Name: string }> | undefined;

  return {
    name,
    priority,
    statement,
    action,
    overrideAction,
    visibilityConfig: {
      sampledRequestsEnabled: (visRaw?.SampledRequestsEnabled as boolean) ?? true,
      cloudWatchMetricsEnabled: (visRaw?.CloudWatchMetricsEnabled as boolean) ?? true,
      metricName: (visRaw?.MetricName as string) || name,
    },
    ruleLabels: ruleLabelsRaw?.map(l => l.Name),
  };
}

function parseStatement(raw: Record<string, unknown>, warnings: string[]): Statement {
  if (!raw) throw new Error("Missing statement");

  if (raw.ByteMatchStatement) {
    const s = raw.ByteMatchStatement as Record<string, unknown>;
    return {
      type: "ByteMatchStatement",
      searchString: (s.SearchString as string) || "",
      fieldToMatch: parseFieldToMatch(s.FieldToMatch as Record<string, unknown>),
      textTransformations: parseTransformations(s.TextTransformations as Array<Record<string, unknown>>),
      positionalConstraint: (s.PositionalConstraint as string) || "CONTAINS",
    } as Statement;
  }

  if (raw.GeoMatchStatement) {
    const s = raw.GeoMatchStatement as Record<string, unknown>;
    return {
      type: "GeoMatchStatement",
      countryCodes: (s.CountryCodes as string[]) || [],
      ...(s.ForwardedIPConfig && { forwardedIPConfig: parseFwdIP(s.ForwardedIPConfig as Record<string, unknown>) }),
    } as Statement;
  }

  if (raw.IPSetReferenceStatement) {
    const s = raw.IPSetReferenceStatement as Record<string, unknown>;
    return {
      type: "IPSetReferenceStatement",
      arn: (s.ARN as string) || "",
      ipSetReference: { arn: (s.ARN as string) || "" },
      ...(s.IPSetForwardedIPConfig && { forwardedIPConfig: parseFwdIP(s.IPSetForwardedIPConfig as Record<string, unknown>) }),
    } as Statement;
  }

  if (raw.LabelMatchStatement) {
    const s = raw.LabelMatchStatement as Record<string, unknown>;
    return { type: "LabelMatchStatement", key: s.Key as string, scope: s.Scope as "LABEL" | "NAMESPACE" } as Statement;
  }

  if (raw.ManagedRuleGroupStatement) {
    const s = raw.ManagedRuleGroupStatement as Record<string, unknown>;
    const excludedRules = (s.ExcludedRules as Array<{ Name: string }> | undefined)?.map(r => r.Name);
    const ruleActionOverrides = (s.RuleActionOverrides as Array<Record<string, unknown>> | undefined)?.map(o => ({
      name: o.Name as string,
      actionToUse: parseActionKey(o.ActionToUse as Record<string, unknown>),
    })) as RuleActionOverride[] | undefined;
    return {
      type: "ManagedRuleGroupStatement",
      vendorName: (s.VendorName as string) || "AWS",
      name: s.Name as string,
      ...(s.Version && { version: s.Version as string }),
      ...(excludedRules?.length && { excludedRules }),
      ...(ruleActionOverrides?.length && { ruleActionOverrides }),
      ...(s.ScopeDownStatement && { scopeDownStatement: parseStatement(s.ScopeDownStatement as Record<string, unknown>, warnings) }),
    } as Statement;
  }

  if (raw.RateBasedStatement) {
    const s = raw.RateBasedStatement as Record<string, unknown>;
    return {
      type: "RateBasedStatement",
      rateLimit: (s.Limit || s.RateLimit) as number,
      evaluationWindowSec: (s.EvaluationWindowSec as number) || 300,
      aggregateKeyType: (s.AggregateKeyType as string) || "IP",
      ...(s.ScopeDownStatement && { scopeDownStatement: parseStatement(s.ScopeDownStatement as Record<string, unknown>, warnings) }),
      ...(s.ForwardedIPConfig && { forwardedIPConfig: parseFwdIP(s.ForwardedIPConfig as Record<string, unknown>) }),
    } as Statement;
  }

  if (raw.RegexMatchStatement) {
    const s = raw.RegexMatchStatement as Record<string, unknown>;
    return {
      type: "RegexMatchStatement",
      regexString: (s.RegexString as string) || "",
      fieldToMatch: parseFieldToMatch(s.FieldToMatch as Record<string, unknown>),
      textTransformations: parseTransformations(s.TextTransformations as Array<Record<string, unknown>>),
    } as Statement;
  }

  if (raw.RegexPatternSetReferenceStatement) {
    const s = raw.RegexPatternSetReferenceStatement as Record<string, unknown>;
    return {
      type: "RegexPatternSetReferenceStatement",
      arn: (s.ARN as string) || "",
      fieldToMatch: parseFieldToMatch(s.FieldToMatch as Record<string, unknown>),
      textTransformations: parseTransformations(s.TextTransformations as Array<Record<string, unknown>>),
    } as Statement;
  }

  if (raw.SizeConstraintStatement) {
    const s = raw.SizeConstraintStatement as Record<string, unknown>;
    return {
      type: "SizeConstraintStatement",
      fieldToMatch: parseFieldToMatch(s.FieldToMatch as Record<string, unknown>),
      comparisonOperator: (s.ComparisonOperator as string) || "GT",
      size: (s.Size as number) || 0,
      textTransformations: parseTransformations(s.TextTransformations as Array<Record<string, unknown>>),
    } as Statement;
  }

  if (raw.SqliMatchStatement) {
    const s = raw.SqliMatchStatement as Record<string, unknown>;
    return {
      type: "SqliMatchStatement",
      fieldToMatch: parseFieldToMatch(s.FieldToMatch as Record<string, unknown>),
      textTransformations: parseTransformations(s.TextTransformations as Array<Record<string, unknown>>),
      ...(s.SensitivityLevel && { sensitivityLevel: s.SensitivityLevel as "LOW" | "HIGH" }),
    } as Statement;
  }

  if (raw.XssMatchStatement) {
    const s = raw.XssMatchStatement as Record<string, unknown>;
    return {
      type: "XssMatchStatement",
      fieldToMatch: parseFieldToMatch(s.FieldToMatch as Record<string, unknown>),
      textTransformations: parseTransformations(s.TextTransformations as Array<Record<string, unknown>>),
      ...(s.SensitivityLevel && { sensitivityLevel: s.SensitivityLevel as "LOW" | "HIGH" }),
    } as Statement;
  }

  if (raw.AndStatement) {
    const s = raw.AndStatement as Record<string, unknown>;
    return {
      type: "AndStatement",
      statements: ((s.Statements as Array<Record<string, unknown>>) || []).map(st => parseStatement(st, warnings)),
    } as Statement;
  }

  if (raw.OrStatement) {
    const s = raw.OrStatement as Record<string, unknown>;
    return {
      type: "OrStatement",
      statements: ((s.Statements as Array<Record<string, unknown>>) || []).map(st => parseStatement(st, warnings)),
    } as Statement;
  }

  if (raw.NotStatement) {
    const s = raw.NotStatement as Record<string, unknown>;
    return {
      type: "NotStatement",
      statement: parseStatement(s.Statement as Record<string, unknown>, warnings),
    } as Statement;
  }

  if (raw.RuleGroupReferenceStatement) {
    const s = raw.RuleGroupReferenceStatement as Record<string, unknown>;
    return {
      type: "RuleGroupReferenceStatement",
      arn: (s.ARN as string) || "",
      ...(s.ExcludedRules && { excludedRules: (s.ExcludedRules as Array<{ Name: string }>).map(r => r.Name) }),
    } as Statement;
  }

  const unknownType = Object.keys(raw)[0] || "Unknown";
  warnings.push(`Unsupported statement type: ${unknownType}`);
  // Fallback: return as byte match placeholder
  return {
    type: "ByteMatchStatement",
    searchString: `UNSUPPORTED:${unknownType}`,
    fieldToMatch: { type: "URI_PATH" },
    textTransformations: [{ type: "NONE", priority: 1 }],
    positionalConstraint: "CONTAINS",
  } as Statement;
}

function parseFieldToMatch(raw: Record<string, unknown> | undefined): FieldToMatch {
  if (!raw) return { type: "URI_PATH" };

  if (raw.UriPath !== undefined) return { type: "URI_PATH" };
  if (raw.QueryString !== undefined) return { type: "QUERY_STRING" };
  if (raw.Method !== undefined) return { type: "METHOD" };
  if (raw.AllQueryArguments !== undefined) return { type: "ALL_QUERY_ARGUMENTS" };

  if (raw.SingleHeader) {
    const h = raw.SingleHeader as Record<string, unknown>;
    return { type: "SINGLE_HEADER", name: (h.Name as string) || "" };
  }
  if (raw.SingleQueryArgument) {
    const q = raw.SingleQueryArgument as Record<string, unknown>;
    return { type: "SINGLE_QUERY_ARGUMENT", name: (q.Name as string) || "" };
  }
  if (raw.Body) {
    const b = raw.Body as Record<string, unknown>;
    return { type: "BODY", oversizeHandling: (b.OversizeHandling as "CONTINUE" | "MATCH" | "NO_MATCH") || "CONTINUE" };
  }
  if (raw.Headers) {
    const h = raw.Headers as Record<string, unknown>;
    return { type: "ALL_HEADERS", matchScope: (h.MatchScope as "KEY" | "VALUE" | "ALL") || "ALL", oversizeHandling: (h.OversizeHandling as "CONTINUE" | "MATCH" | "NO_MATCH") || "CONTINUE" };
  }
  if (raw.Cookies) {
    const c = raw.Cookies as Record<string, unknown>;
    return { type: "COOKIES", matchScope: (c.MatchScope as "KEY" | "VALUE" | "ALL") || "ALL", oversizeHandling: (c.OversizeHandling as "CONTINUE" | "MATCH" | "NO_MATCH") || "CONTINUE" };
  }
  if (raw.JsonBody) {
    const j = raw.JsonBody as Record<string, unknown>;
    return {
      type: "JSON_BODY",
      jsonMatchScope: (j.MatchScope as "VALUE" | "KEY" | "ALL") || "VALUE",
      invalidFallback: (j.InvalidFallbackBehavior as "MATCH" | "NO_MATCH" | "EVALUATE_AS_STRING") || "EVALUATE_AS_STRING",
      oversizeHandling: (j.OversizeHandling as "CONTINUE" | "MATCH" | "NO_MATCH") || "CONTINUE",
    };
  }
  if (raw.JA3Fingerprint) {
    const j = raw.JA3Fingerprint as Record<string, unknown>;
    return { type: "JA3_FINGERPRINT", fallbackBehavior: (j.FallbackBehavior as "MATCH" | "NO_MATCH") || "MATCH" };
  }
  if (raw.HeaderOrder) return { type: "HEADER_ORDER" };

  return { type: "URI_PATH" };
}

function parseTransformations(raw: Array<Record<string, unknown>> | undefined): TextTransformation[] {
  if (!raw?.length) return [{ type: "NONE", priority: 1 }];
  return raw.map(t => ({
    type: (t.Type as string) || "NONE",
    priority: (t.Priority as number) || 1,
  })) as TextTransformation[];
}

function parseFwdIP(raw: Record<string, unknown>): { headerName: string; fallbackBehavior: "MATCH" | "NO_MATCH" } {
  return {
    headerName: (raw.HeaderName as string) || "X-Forwarded-For",
    fallbackBehavior: (raw.FallbackBehavior as "MATCH" | "NO_MATCH") || "MATCH",
  };
}

function parseActionKey(raw: Record<string, unknown>): WAFAction {
  if (raw.Allow) return "ALLOW";
  if (raw.Block) return "BLOCK";
  if (raw.Count) return "COUNT";
  if (raw.Captcha) return "CAPTCHA";
  if (raw.Challenge) return "CHALLENGE";
  return "BLOCK";
}
