// WAFSim - Export Engine
// Generates AWS WAF JSON and Terraform HCL exports

import {
  WebACL,
  Rule,
  Statement,
  IPSet,
  RegexPatternSet,
  WAFV2WebACLJson,
  WAFV2RuleJson,
  TextTransformation,
  FieldToMatch,
  PositionalConstraint,
  SizeComparisonOperator,
} from "@/lib/types";

/**
 * Export WebACL as AWS WAFv2 JSON format
 */
export function exportAsWebACLJson(webACL: WebACL): WAFV2WebACLJson {
  return {
    Name: webACL.name,
    Scope: webACL.scope,
    DefaultAction: webACL.defaultAction === "ALLOW"
      ? { Allow: {} }
      : { Block: {} },
    Description: webACL.description,
    Rules: webACL.rules.map((rule) => convertRuleToJson(rule)),
    VisibilityConfig: {
      SampledRequestsEnabled: webACL.visibilityConfig.sampledRequestsEnabled,
      CloudWatchMetricsEnabled: webACL.visibilityConfig.cloudWatchMetricsEnabled,
      MetricName: webACL.visibilityConfig.metricName,
    },
    CustomResponseBodies: webACL.customResponseBodies
      ? convertCustomResponseBodies(webACL.customResponseBodies)
      : undefined,
    TokenDomains: webACL.tokenDomains,
  };
}

/**
 * Convert a rule to AWS JSON format
 */
function convertRuleToJson(rule: Rule): WAFV2RuleJson {
  const json: WAFV2RuleJson = {
    Name: rule.name,
    Priority: rule.priority,
    Statement: convertStatementToJson(rule.statement),
    VisibilityConfig: {
      SampledRequestsEnabled: rule.visibilityConfig.sampledRequestsEnabled,
      CloudWatchMetricsEnabled: rule.visibilityConfig.cloudWatchMetricsEnabled,
      MetricName: rule.visibilityConfig.metricName,
    },
  };

  // Handle action based on rule type
  if (rule.statement.type === "ManagedRuleGroupStatement" || rule.statement.type === "RuleGroupReferenceStatement") {
    // Managed rule groups and rule group references use OverrideAction (Count or None only)
    json.OverrideAction = rule.overrideAction === "COUNT"
      ? { Count: {} }
      : { None: {} };
  } else {
    json.Action = { [capitalize(rule.action)]: {} };
  }

  // Add rule labels
  if (rule.ruleLabels && rule.ruleLabels.length > 0) {
    json.RuleLabels = rule.ruleLabels.map((label) => ({ Name: label }));
  }

  return json;
}

/**
 * Convert a statement to AWS JSON format
 */
function convertStatementToJson(statement: Statement): Record<string, unknown> {
  switch (statement.type) {
    case "ByteMatchStatement":
      return {
        ByteMatchStatement: {
          SearchString: statement.searchString,
          FieldToMatch: convertFieldToMatchToJson(statement.fieldToMatch as FieldToMatch),
          TextTransformations: (statement.textTransformations as TextTransformation[]).map(convertTextTransformationToJson),
          PositionalConstraint: statement.positionalConstraint,
        },
      };

    case "GeoMatchStatement":
      return {
        GeoMatchStatement: {
          CountryCodes: statement.countryCodes,
          ...(statement.forwardedIPConfig && {
            ForwardedIPConfig: {
              HeaderName: statement.forwardedIPConfig.headerName,
              FallbackBehavior: statement.forwardedIPConfig.fallbackBehavior,
            },
          }),
        },
      };

    case "IPSetReferenceStatement":
      return {
        IPSetReferenceStatement: {
          ARN: statement.arn,
          ...(statement.forwardedIPConfig && {
            IPSetForwardedIPConfig: {
              HeaderName: statement.forwardedIPConfig.headerName,
              FallbackBehavior: statement.forwardedIPConfig.fallbackBehavior,
              Position: "ANY",
            },
          }),
        },
      };

    case "LabelMatchStatement":
      return {
        LabelMatchStatement: {
          Key: statement.key,
          Scope: statement.scope,
        },
      };

    case "ManagedRuleGroupStatement":
      return {
        ManagedRuleGroupStatement: {
          VendorName: statement.vendorName,
          Name: statement.name,
          ...(statement.version && { Version: statement.version }),
          ...(statement.excludedRules && {
            ExcludedRules: statement.excludedRules.map((name) => ({ Name: name })),
          }),
          ...(statement.managedRuleGroupConfigs && {
            ManagedRuleGroupConfigs: statement.managedRuleGroupConfigs,
          }),
          ...(statement.ruleActionOverrides && {
            RuleActionOverrides: statement.ruleActionOverrides.map((override) => ({
              Name: override.name,
              ActionToUse: { [capitalize(override.actionToUse)]: {} },
            })),
          }),
        },
      };

    case "RateBasedStatement":
      return {
        RateBasedStatement: {
          RateLimit: statement.rateLimit,
          EvaluationWindowSec: statement.evaluationWindowSec,
          AggregateKeyType: statement.aggregateKeyType,
          ...(statement.aggregateKeys && {
            AggregateKeys: statement.aggregateKeys.map((key) => ({
              ...(key.header && { Header: { Name: key.header.name } }),
              ...(key.cookie && { Cookie: { Name: key.cookie.name } }),
              ...(key.queryArgument && { QueryArgument: { Name: key.queryArgument.name } }),
              ...(key.queryString && { QueryString: {} }),
              ...(key.httpMethod && { HTTPMethod: {} }),
              ...(key.forwardedIP && { ForwardedIP: {} }),
              ...(key.ip && { IP: {} }),
              ...(key.labelNamespace && { LabelNamespace: { Namespace: key.labelNamespace.namespace } }),
              ...(key.uriPath && { URIPath: {} }),
            })),
          }),
          ...(statement.scopeDownStatement && {
            ScopeDownStatement: convertStatementToJson(statement.scopeDownStatement),
          }),
          ...(statement.forwardedIPConfig && {
            ForwardedIPConfig: {
              HeaderName: statement.forwardedIPConfig.headerName,
              FallbackBehavior: statement.forwardedIPConfig.fallbackBehavior,
            },
          }),
        },
      };

    case "RegexMatchStatement":
      return {
        RegexMatchStatement: {
          RegexString: statement.regexString,
          FieldToMatch: convertFieldToMatchToJson(statement.fieldToMatch as FieldToMatch),
          TextTransformations: (statement.textTransformations as TextTransformation[]).map(convertTextTransformationToJson),
        },
      };

    case "RegexPatternSetReferenceStatement":
      return {
        RegexPatternSetReferenceStatement: {
          ARN: statement.arn,
          FieldToMatch: convertFieldToMatchToJson(statement.fieldToMatch as FieldToMatch),
          TextTransformations: (statement.textTransformations as TextTransformation[]).map(convertTextTransformationToJson),
        },
      };

    case "SizeConstraintStatement":
      return {
        SizeConstraintStatement: {
          FieldToMatch: convertFieldToMatchToJson(statement.fieldToMatch as FieldToMatch),
          ComparisonOperator: statement.comparisonOperator,
          Size: statement.size,
          TextTransformations: (statement.textTransformations as TextTransformation[]).map(convertTextTransformationToJson),
        },
      };

    case "SqliMatchStatement":
      return {
        SqliMatchStatement: {
          FieldToMatch: convertFieldToMatchToJson(statement.fieldToMatch as FieldToMatch),
          TextTransformations: (statement.textTransformations as TextTransformation[]).map(convertTextTransformationToJson),
          ...(statement.sensitivityLevel && { SensitivityLevel: statement.sensitivityLevel }),
        },
      };

    case "XssMatchStatement":
      return {
        XssMatchStatement: {
          FieldToMatch: convertFieldToMatchToJson(statement.fieldToMatch as FieldToMatch),
          TextTransformations: (statement.textTransformations as TextTransformation[]).map(convertTextTransformationToJson),
          ...(statement.sensitivityLevel && { SensitivityLevel: statement.sensitivityLevel }),
        },
      };

    case "AndStatement":
      return {
        AndStatement: {
          Statements: statement.statements.map(convertStatementToJson),
        },
      };

    case "OrStatement":
      return {
        OrStatement: {
          Statements: statement.statements.map(convertStatementToJson),
        },
      };

    case "NotStatement":
      return {
        NotStatement: {
          Statement: convertStatementToJson(statement.statement),
        },
      };

    case "RuleGroupReferenceStatement":
      return {
        RuleGroupReferenceStatement: {
          ARN: statement.arn,
          ...(statement.excludedRules && {
            ExcludedRules: statement.excludedRules.map((name) => ({ Name: name })),
          }),
        },
      };

    default:
      return {};
  }
}

/**
 * Convert FieldToMatch to AWS JSON format
 */
function convertFieldToMatchToJson(field: FieldToMatch): Record<string, unknown> {
  switch (field.type) {
    case "URI_PATH":
      return { UriPath: {} };
    case "QUERY_STRING":
      return { QueryString: {} };
    case "BODY":
      return {
        Body: {
          OversizeHandling: field.oversizeHandling || "CONTINUE",
        },
      };
    case "METHOD":
      return { Method: {} };
    case "SINGLE_HEADER":
      return { SingleHeader: { Name: field.name } };
    case "ALL_HEADERS":
      return {
        Headers: {
          MatchPattern: { All: {} },
          MatchScope: field.matchScope || "ALL",
          OversizeHandling: field.oversizeHandling || "CONTINUE",
        },
      };
    case "SINGLE_QUERY_ARGUMENT":
      return { SingleQueryArgument: { Name: field.name } };
    case "ALL_QUERY_ARGUMENTS":
      return { AllQueryArguments: {} };
    case "COOKIES":
      return {
        Cookies: {
          MatchPattern: { All: {} },
          MatchScope: field.matchScope || "ALL",
          OversizeHandling: field.oversizeHandling || "CONTINUE",
        },
      };
    case "JSON_BODY":
      return {
        JsonBody: {
          MatchPattern: { All: {} },
          MatchScope: field.jsonMatchScope || "VALUE",
          InvalidFallbackBehavior: field.invalidFallback || "EVALUATE_AS_STRING",
          OversizeHandling: field.oversizeHandling || "CONTINUE",
        },
      };
    case "JA3_FINGERPRINT":
      return {
        JA3Fingerprint: {
          FallbackBehavior: field.fallbackBehavior || "MATCH",
        },
      };
    case "HTTP_VERSION":
      return { HttpVersion: {} };
    case "HEADER_ORDER":
      return {
        HeaderOrder: {
          OversizeHandling: field.oversizeHandling || "CONTINUE",
        },
      };
    default:
      return {};
  }
}

/**
 * Convert TextTransformation to AWS JSON format
 */
function convertTextTransformationToJson(transform: TextTransformation): Record<string, unknown> {
  return {
    Priority: transform.priority,
    Type: transform.type,
  };
}

/**
 * Convert custom response bodies to AWS JSON format
 */
function convertCustomResponseBodies(
  bodies: Record<string, { contentType: string; content: string }>
): Record<string, { ContentType: string; Content: string }> {
  const result: Record<string, { ContentType: string; Content: string }> = {};
  for (const [key, body] of Object.entries(bodies)) {
    result[key] = {
      ContentType: body.contentType,
      Content: body.content,
    };
  }
  return result;
}

/**
 * Capitalize first letter
 */
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}

/**
 * Export IP Set as AWS JSON
 */
export function exportIPSetJson(ipSet: IPSet): Record<string, unknown> {
  return {
    Name: ipSet.name,
    Scope: ipSet.scope,
    Description: ipSet.description,
    IPAddressVersion: ipSet.ipAddressVersion,
    Addresses: ipSet.addresses,
  };
}

/**
 * Export Regex Pattern Set as AWS JSON
 */
export function exportRegexPatternSetJson(patternSet: RegexPatternSet): Record<string, unknown> {
  return {
    Name: patternSet.name,
    Scope: patternSet.scope,
    Description: patternSet.description,
    RegularExpressionList: patternSet.regularExpressionList,
  };
}

/**
 * Generate AWS CLI commands for deployment
 */
export function generateCLICommands(
  webACL: WebACL,
  ipSets: IPSet[],
  regexPatternSets: RegexPatternSet[]
): string[] {
  const commands: string[] = [];

  // Create IP Sets first
  for (const ipSet of ipSets) {
    commands.push(
      `aws wafv2 create-ip-set \\
  --name "${ipSet.name}" \\
  --scope ${ipSet.scope} \\
  --ip-address-version ${ipSet.ipAddressVersion} \\
  --addresses '${JSON.stringify(ipSet.addresses)}' \\
  --description "${ipSet.description || ''}"`
    );
  }

  // Create Regex Pattern Sets
  for (const patternSet of regexPatternSets) {
    commands.push(
      `aws wafv2 create-regex-pattern-set \\
  --name "${patternSet.name}" \\
  --scope ${patternSet.scope} \\
  --regular-expression-list '${JSON.stringify(patternSet.regularExpressionList.map((p) => ({ RegexString: p })))}' \\
  --description "${patternSet.description || ''}"`
    );
  }

  // Create WebACL
  const webACLJson = exportAsWebACLJson(webACL);
  commands.push(
    `aws wafv2 create-web-acl \\
  --cli-input-json '${JSON.stringify(webACLJson, null, 2)}'`
  );

  return commands;
}

/**
 * Export as Terraform HCL
 */
export function exportAsTerraformHCL(
  webACL: WebACL,
  ipSets: IPSet[],
  regexPatternSets: RegexPatternSet[]
): string {
  const lines: string[] = [];

  // Add header comment
  lines.push("# WAFSim Terraform Export");
  lines.push(`# Generated for WebACL: ${webACL.name}`);
  lines.push(`# Scope: ${webACL.scope}`);
  lines.push("");

  // AWS Provider
  lines.push('provider "aws" {');
  lines.push("  region = var.aws_region");
  lines.push("}");
  lines.push("");

  // IP Sets
  for (const ipSet of ipSets) {
    lines.push(`resource "aws_wafv2_ip_set" "${sanitizeTerraformName(ipSet.name)}" {`);
    lines.push(`  name               = "${ipSet.name}"`);
    lines.push(`  description        = "${ipSet.description || "Created by WAFSim"}"`);
    lines.push(`  scope              = "${ipSet.scope}"`);
    lines.push(`  ip_address_version = "${ipSet.ipAddressVersion}"`);
    lines.push("");
    lines.push("  addresses = [");
    for (const addr of ipSet.addresses) {
      lines.push(`    "${addr}",`);
    }
    lines.push("  ]");
    lines.push("}");
    lines.push("");
  }

  // Regex Pattern Sets
  for (const patternSet of regexPatternSets) {
    lines.push(`resource "aws_wafv2_regex_pattern_set" "${sanitizeTerraformName(patternSet.name)}" {`);
    lines.push(`  name        = "${patternSet.name}"`);
    lines.push(`  description = "${patternSet.description || "Created by WAFSim"}"`);
    lines.push(`  scope       = "${patternSet.scope}"`);
    lines.push("");
    lines.push("  regular_expression {");
    for (const pattern of patternSet.regularExpressionList) {
      lines.push(`    regex_string = "${escapeTerraformString(pattern)}"`);
    }
    lines.push("  }");
    lines.push("}");
    lines.push("");
  }

  // Web ACL
  lines.push(`resource "aws_wafv2_web_acl" "${sanitizeTerraformName(webACL.name)}" {`);
  lines.push(`  name        = "${webACL.name}"`);
  lines.push(`  description = "${webACL.description || "Created by WAFSim"}"`);
  lines.push(`  scope       = "${webACL.scope}"`);
  lines.push("");

  // Default action
  if (webACL.defaultAction === "ALLOW") {
    lines.push("  default_action {");
    lines.push("    allow {}");
    lines.push("  }");
  } else {
    lines.push("  default_action {");
    lines.push("    block {}");
    lines.push("  }");
  }
  lines.push("");

  // Rules
  for (const rule of webACL.rules) {
    lines.push("  rule {");
    lines.push(`    name     = "${rule.name}"`);
    lines.push(`    priority = ${rule.priority}`);
    lines.push("");

    // Action
    if (rule.statement.type === "ManagedRuleGroupStatement") {
      lines.push("    override_action {");
      if (rule.overrideAction && rule.overrideAction !== "NONE") {
        lines.push(`      ${rule.overrideAction.toLowerCase()} {}`);
      } else {
        lines.push("      none {}");
      }
      lines.push("    }");
    } else {
      lines.push(`    action {`);
      lines.push(`      ${rule.action.toLowerCase()} {}`);
      lines.push("    }");
    }
    lines.push("");

    // Statement
    lines.push("    statement {");
    lines.push(convertStatementToTerraform(rule.statement, "      ", ipSets));
    lines.push("    }");
    lines.push("");

    // Visibility config
    lines.push("    visibility_config {");
    lines.push(`      cloudwatch_metrics_enabled = ${rule.visibilityConfig.cloudWatchMetricsEnabled}`);
    lines.push(`      metric_name               = "${rule.visibilityConfig.metricName}"`);
    lines.push(`      sampled_requests_enabled  = ${rule.visibilityConfig.sampledRequestsEnabled}`);
    lines.push("    }");
    lines.push("  }");
    lines.push("");
  }

  // Visibility config
  lines.push("  visibility_config {");
  lines.push(`    cloudwatch_metrics_enabled = ${webACL.visibilityConfig.cloudWatchMetricsEnabled}`);
  lines.push(`    metric_name               = "${webACL.visibilityConfig.metricName}"`);
  lines.push(`    sampled_requests_enabled  = ${webACL.visibilityConfig.sampledRequestsEnabled}`);
  lines.push("  }");
  lines.push("");

  // Custom response bodies
  if (webACL.customResponseBodies) {
    for (const [key, body] of Object.entries(webACL.customResponseBodies)) {
      lines.push(`  custom_response_body {`);
      lines.push(`    key          = "${key}"`);
      lines.push(`    content      = "${escapeTerraformString(body.content)}"`);
      lines.push(`    content_type = "${body.contentType.toLowerCase()}"`);
      lines.push("  }");
    }
  }

  lines.push("}");

  // Add variables
  lines.push("");
  lines.push('variable "aws_region" {');
  lines.push('  description = "AWS region for resources"');
  lines.push('  type        = string');
  lines.push('  default     = "us-east-1"');
  lines.push("}");

  return lines.join("\n");
}

/**
 * Convert statement to Terraform format
 */
function convertStatementToTerraform(
  statement: Statement,
  indent: string,
  ipSets: IPSet[]
): string {
  const lines: string[] = [];

  switch (statement.type) {
    case "ByteMatchStatement":
      lines.push(`${indent}byte_match_statement {`);
      lines.push(`${indent}  search_string                 = "${escapeTerraformString(statement.searchString)}"`);
      lines.push(`${indent}  positional_constraint         = "${statement.positionalConstraint}"`);
      lines.push("");
      lines.push(convertFieldToMatchToTerraform(statement.fieldToMatch as FieldToMatch, `${indent}  `));
      lines.push("");
      for (const transform of statement.textTransformations as TextTransformation[]) {
        lines.push(`${indent}  text_transformation {`);
        lines.push(`${indent}    priority = ${transform.priority}`);
        lines.push(`${indent}    type     = "${transform.type}"`);
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "GeoMatchStatement":
      lines.push(`${indent}geo_match_statement {`);
      lines.push(`${indent}  country_codes = ${JSON.stringify(statement.countryCodes)}`);
      if (statement.forwardedIPConfig) {
        lines.push(`${indent}  forwarded_ip_config {`);
        lines.push(`${indent}    header_name       = "${statement.forwardedIPConfig.headerName}"`);
        lines.push(`${indent}    fallback_behavior = "${statement.forwardedIPConfig.fallbackBehavior}"`);
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "IPSetReferenceStatement":
      const ipSet = ipSets.find((s) => s.arn === statement.arn);
      lines.push(`${indent}ip_set_reference_statement {`);
      lines.push(`${indent}  arn = ${ipSet ? `aws_wafv2_ip_set.${sanitizeTerraformName(ipSet.name)}.arn` : `"${statement.arn}"`}`);
      lines.push(`${indent}}`);
      break;

    case "ManagedRuleGroupStatement":
      lines.push(`${indent}managed_rule_group_statement {`);
      lines.push(`${indent}  name        = "${statement.name}"`);
      lines.push(`${indent}  vendor_name = "${statement.vendorName}"`);
      if (statement.version) {
        lines.push(`${indent}  version     = "${statement.version}"`);
      }
      if (statement.excludedRules && statement.excludedRules.length > 0) {
        for (const rule of statement.excludedRules) {
          lines.push(`${indent}  excluded_rule {`);
          lines.push(`${indent}    name = "${rule}"`);
          lines.push(`${indent}  }`);
        }
      }
      if (statement.ruleActionOverrides && statement.ruleActionOverrides.length > 0) {
        for (const override of statement.ruleActionOverrides) {
          lines.push(`${indent}  rule_action_override {`);
          lines.push(`${indent}    name = "${override.name}"`);
          lines.push(`${indent}    action_to_use {`);
          lines.push(`${indent}      ${override.actionToUse.toLowerCase()} {}`);
          lines.push(`${indent}    }`);
          lines.push(`${indent}  }`);
        }
      }
      if (statement.scopeDownStatement) {
        lines.push(`${indent}  scope_down_statement {`);
        lines.push(convertStatementToTerraform(statement.scopeDownStatement, `${indent}    `, ipSets));
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "RateBasedStatement":
      lines.push(`${indent}rate_based_statement {`);
      lines.push(`${indent}  aggregate_key_type    = "${statement.aggregateKeyType}"`);
      lines.push(`${indent}  limit                 = ${statement.rateLimit}`);
      lines.push(`${indent}  evaluation_window_sec = ${statement.evaluationWindowSec}`);
      if (statement.scopeDownStatement) {
        lines.push(`${indent}  scope_down_statement {`);
        lines.push(convertStatementToTerraform(statement.scopeDownStatement, `${indent}    `, ipSets));
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "RegexMatchStatement":
      lines.push(`${indent}regex_match_statement {`);
      lines.push(`${indent}  regex_string = "${escapeTerraformString(statement.regexString)}"`);
      lines.push(convertFieldToMatchToTerraform(statement.fieldToMatch as FieldToMatch, `${indent}  `));
      for (const transform of statement.textTransformations as TextTransformation[]) {
        lines.push(`${indent}  text_transformation {`);
        lines.push(`${indent}    priority = ${transform.priority}`);
        lines.push(`${indent}    type     = "${transform.type}"`);
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "SqliMatchStatement":
      lines.push(`${indent}sqli_match_statement {`);
      lines.push(convertFieldToMatchToTerraform(statement.fieldToMatch as FieldToMatch, `${indent}  `));
      for (const transform of statement.textTransformations as TextTransformation[]) {
        lines.push(`${indent}  text_transformation {`);
        lines.push(`${indent}    priority = ${transform.priority}`);
        lines.push(`${indent}    type     = "${transform.type}"`);
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "XssMatchStatement":
      lines.push(`${indent}xss_match_statement {`);
      lines.push(convertFieldToMatchToTerraform(statement.fieldToMatch as FieldToMatch, `${indent}  `));
      for (const transform of statement.textTransformations as TextTransformation[]) {
        lines.push(`${indent}  text_transformation {`);
        lines.push(`${indent}    priority = ${transform.priority}`);
        lines.push(`${indent}    type     = "${transform.type}"`);
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "SizeConstraintStatement":
      lines.push(`${indent}size_constraint_statement {`);
      lines.push(`${indent}  comparison_operator = "${statement.comparisonOperator}"`);
      lines.push(`${indent}  size                = ${statement.size}`);
      lines.push(convertFieldToMatchToTerraform(statement.fieldToMatch as FieldToMatch, `${indent}  `));
      for (const transform of statement.textTransformations as TextTransformation[]) {
        lines.push(`${indent}  text_transformation {`);
        lines.push(`${indent}    priority = ${transform.priority}`);
        lines.push(`${indent}    type     = "${transform.type}"`);
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "RegexPatternSetReferenceStatement":
      lines.push(`${indent}regex_pattern_set_reference_statement {`);
      lines.push(`${indent}  arn = "${statement.arn}"`);
      lines.push(convertFieldToMatchToTerraform(statement.fieldToMatch as FieldToMatch, `${indent}  `));
      for (const transform of statement.textTransformations as TextTransformation[]) {
        lines.push(`${indent}  text_transformation {`);
        lines.push(`${indent}    priority = ${transform.priority}`);
        lines.push(`${indent}    type     = "${transform.type}"`);
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "LabelMatchStatement":
      lines.push(`${indent}label_match_statement {`);
      lines.push(`${indent}  key   = "${statement.key}"`);
      lines.push(`${indent}  scope = "${statement.scope}"`);
      lines.push(`${indent}}`);
      break;

    case "RuleGroupReferenceStatement":
      lines.push(`${indent}rule_group_reference_statement {`);
      lines.push(`${indent}  arn = "${statement.arn}"`);
      if (statement.excludedRules && statement.excludedRules.length > 0) {
        for (const rule of statement.excludedRules) {
          lines.push(`${indent}  excluded_rule {`);
          lines.push(`${indent}    name = "${rule}"`);
          lines.push(`${indent}  }`);
        }
      }
      lines.push(`${indent}}`);
      break;

    case "AndStatement":
      lines.push(`${indent}and_statement {`);
      for (const stmt of statement.statements) {
        lines.push(`${indent}  statement {`);
        lines.push(convertStatementToTerraform(stmt, `${indent}    `, ipSets));
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "OrStatement":
      lines.push(`${indent}or_statement {`);
      for (const stmt of statement.statements) {
        lines.push(`${indent}  statement {`);
        lines.push(convertStatementToTerraform(stmt, `${indent}    `, ipSets));
        lines.push(`${indent}  }`);
      }
      lines.push(`${indent}}`);
      break;

    case "NotStatement":
      lines.push(`${indent}not_statement {`);
      lines.push(`${indent}  statement {`);
      lines.push(convertStatementToTerraform(statement.statement, `${indent}    `, ipSets));
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;

    default:
      lines.push(`${indent}# Unsupported statement type: ${statement.type}`);
  }

  return lines.join("\n");
}

/**
 * Convert FieldToMatch to Terraform format
 */
function convertFieldToMatchToTerraform(field: FieldToMatch, indent: string): string {
  const lines: string[] = [];

  switch (field.type) {
    case "URI_PATH":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  uri_path {}`);
      lines.push(`${indent}}`);
      break;
    case "QUERY_STRING":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  query_string {}`);
      lines.push(`${indent}}`);
      break;
    case "BODY":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  body {`);
      lines.push(`${indent}    oversize_handling = "${(field.oversizeHandling || "CONTINUE")}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    case "METHOD":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  method {}`);
      lines.push(`${indent}}`);
      break;
    case "SINGLE_HEADER":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  single_header {`);
      lines.push(`${indent}    name = "${field.name}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    case "ALL_QUERY_ARGUMENTS":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  all_query_arguments {}`);
      lines.push(`${indent}}`);
      break;
    case "SINGLE_QUERY_ARGUMENT":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  single_query_argument {`);
      lines.push(`${indent}    name = "${field.name}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    case "ALL_HEADERS":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  headers {`);
      lines.push(`${indent}    match_pattern {`);
      lines.push(`${indent}      all {}`);
      lines.push(`${indent}    }`);
      lines.push(`${indent}    match_scope       = "${field.matchScope || "ALL"}"`);
      lines.push(`${indent}    oversize_handling = "${field.oversizeHandling || "CONTINUE"}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    case "COOKIES":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  cookies {`);
      lines.push(`${indent}    match_pattern {`);
      lines.push(`${indent}      all {}`);
      lines.push(`${indent}    }`);
      lines.push(`${indent}    match_scope       = "${field.matchScope || "ALL"}"`);
      lines.push(`${indent}    oversize_handling = "${field.oversizeHandling || "CONTINUE"}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    case "JSON_BODY":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  json_body {`);
      lines.push(`${indent}    match_pattern {`);
      lines.push(`${indent}      all {}`);
      lines.push(`${indent}    }`);
      lines.push(`${indent}    match_scope                = "${field.jsonMatchScope || "VALUE"}"`);
      lines.push(`${indent}    invalid_fallback_behavior = "${field.invalidFallback || "EVALUATE_AS_STRING"}"`);
      lines.push(`${indent}    oversize_handling          = "${field.oversizeHandling || "CONTINUE"}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    case "JA3_FINGERPRINT":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  ja3_fingerprint {`);
      lines.push(`${indent}    fallback_behavior = "${field.fallbackBehavior || "MATCH"}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    case "HEADER_ORDER":
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  header_order {`);
      lines.push(`${indent}    oversize_handling = "${field.oversizeHandling || "CONTINUE"}"`);
      lines.push(`${indent}  }`);
      lines.push(`${indent}}`);
      break;
    default:
      lines.push(`${indent}field_to_match {`);
      lines.push(`${indent}  # Field type: ${field.type}`);
      lines.push(`${indent}}`);
  }

  return lines.join("\n");
}

/**
 * Sanitize name for Terraform resource
 */
function sanitizeTerraformName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, "_").toLowerCase();
}

/**
 * Escape string for Terraform
 */
function escapeTerraformString(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}
