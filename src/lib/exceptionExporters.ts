// WAFSim v3 rc.9.3 — Multi-format exporter for a single exception rule.
//
// A developer shipping this exception will deploy via one of:
//   - Console (raw JSON copy/paste)
//   - CloudFormation (AWS::WAFv2::WebACL > Rules)
//   - Terraform (aws_wafv2_web_acl > rule block)
//   - AWS CLI (update-web-acl with rules file)
//
// This module produces each format from the same engine-generated Rule.
// The outputs are valid for drop-in use into the respective deployment
// path. None of these are hand-written; they're derived from the same
// source Rule object.

import type { Rule, Statement } from "./types";

export type ExceptionExportFormat = "json" | "cloudformation" | "terraform" | "cli";

// ---------- JSON (raw) ----------

export function toJson(rule: Rule): string {
  return JSON.stringify(rule, null, 2);
}

// ---------- CloudFormation YAML ----------
//
// We produce the YAML fragment for a single rule inside a
// AWS::WAFv2::WebACL Rules array. User pastes this into their stack.

export function toCloudFormation(rule: Rule): string {
  const action = cfAction(rule.action);
  const lines: string[] = [
    `- Name: ${rule.name}`,
    `  Priority: ${rule.priority}`,
    `  Action:`,
    ...indent(action, 4),
    `  Statement:`,
    ...indent(cfStatement(rule.statement), 4),
    `  VisibilityConfig:`,
    `    SampledRequestsEnabled: ${rule.visibilityConfig?.sampledRequestsEnabled ?? true}`,
    `    CloudWatchMetricsEnabled: ${rule.visibilityConfig?.cloudWatchMetricsEnabled ?? true}`,
    `    MetricName: ${rule.visibilityConfig?.metricName ?? rule.name}`,
  ];
  return lines.join("\n");
}

function cfAction(action: string): string[] {
  switch (action) {
    case "ALLOW": return ["Allow: {}"];
    case "BLOCK": return ["Block: {}"];
    case "COUNT": return ["Count: {}"];
    case "CAPTCHA": return ["Captcha: {}"];
    case "CHALLENGE": return ["Challenge: {}"];
    default: return ["Allow: {}"];
  }
}

function cfStatement(stmt: Statement): string[] {
  // We render a minimal subset of statements — enough for the common
  // exception rules our engine generates (AND, LabelMatch, ByteMatch,
  // IPSetReference, ManagedRuleGroup with ExcludedRules).
  const s = stmt as Statement & Record<string, unknown>;
  switch (s.type) {
    case "AndStatement": {
      const children = ((s.statements as Statement[]) ?? []).map((sub) =>
        indent(cfStatement(sub), 4).join("\n")
      );
      return [
        "AndStatement:",
        "  Statements:",
        ...children.map((c) => `    - ${c.trimStart()}`),
      ];
    }
    case "OrStatement": {
      const children = ((s.statements as Statement[]) ?? []).map((sub) =>
        indent(cfStatement(sub), 4).join("\n")
      );
      return [
        "OrStatement:",
        "  Statements:",
        ...children.map((c) => `    - ${c.trimStart()}`),
      ];
    }
    case "NotStatement": {
      const inner = cfStatement(s.statement as Statement);
      return ["NotStatement:", "  Statement:", ...indent(inner, 4)];
    }
    case "LabelMatchStatement": {
      return [
        "LabelMatchStatement:",
        `  Scope: ${s.scope ?? "LABEL"}`,
        `  Key: ${s.key}`,
      ];
    }
    case "ByteMatchStatement": {
      const fim = s.fieldToMatch as { type: string } | undefined;
      const fieldKey = fieldKeyForCF(fim?.type ?? "URI_PATH");
      return [
        "ByteMatchStatement:",
        `  SearchString: "${(s.searchString as string) ?? ""}"`,
        `  FieldToMatch:`,
        `    ${fieldKey}: {}`,
        `  TextTransformations:`,
        `    - Priority: 0`,
        `      Type: NONE`,
        `  PositionalConstraint: ${s.positionalConstraint ?? "EXACTLY"}`,
      ];
    }
    case "IPSetReferenceStatement": {
      return ["IPSetReferenceStatement:", `  Arn: "${s.arn}"`];
    }
    case "ManagedRuleGroupStatement": {
      const excluded = ((s.excludedRules as string[]) ?? []).map((r) => `    - Name: ${r}`);
      return [
        "ManagedRuleGroupStatement:",
        `  VendorName: ${s.vendorName ?? "AWS"}`,
        `  Name: ${s.name}`,
        "  ExcludedRules:",
        ...(excluded.length > 0 ? excluded : ["    []"]),
      ];
    }
    case "GeoMatchStatement": {
      const countries = ((s.countryCodes as string[]) ?? []).map((c) => `    - ${c}`);
      return ["GeoMatchStatement:", "  CountryCodes:", ...countries];
    }
    case "RateBasedStatement": {
      return [
        "RateBasedStatement:",
        `  Limit: ${s.rateLimit ?? s.limit ?? 100}`,
        `  AggregateKeyType: ${s.aggregateKeyType ?? "IP"}`,
      ];
    }
    default: {
      return [`${s.type}: {}`];
    }
  }
}

function fieldKeyForCF(type: string): string {
  switch (type) {
    case "URI_PATH": return "UriPath";
    case "QUERY_STRING": return "QueryString";
    case "BODY": return "Body";
    case "METHOD": return "Method";
    case "ALL_QUERY_ARGUMENTS": return "AllQueryArguments";
    default: return type;
  }
}

// ---------- Terraform HCL ----------

export function toTerraform(rule: Rule): string {
  const lines: string[] = [
    `rule {`,
    `  name     = "${rule.name}"`,
    `  priority = ${rule.priority}`,
    ``,
    `  action {`,
    `    ${tfActionBlock(rule.action)}`,
    `  }`,
    ``,
    `  statement {`,
    ...indent(tfStatement(rule.statement), 4),
    `  }`,
    ``,
    `  visibility_config {`,
    `    sampled_requests_enabled   = ${rule.visibilityConfig?.sampledRequestsEnabled ?? true}`,
    `    cloudwatch_metrics_enabled = ${rule.visibilityConfig?.cloudWatchMetricsEnabled ?? true}`,
    `    metric_name                = "${rule.visibilityConfig?.metricName ?? rule.name}"`,
    `  }`,
    `}`,
  ];
  return lines.join("\n");
}

function tfActionBlock(action: string): string {
  switch (action) {
    case "ALLOW": return "allow {}";
    case "BLOCK": return "block {}";
    case "COUNT": return "count {}";
    case "CAPTCHA": return "captcha {}";
    case "CHALLENGE": return "challenge {}";
    default: return "allow {}";
  }
}

function tfStatement(stmt: Statement): string[] {
  const s = stmt as Statement & Record<string, unknown>;
  switch (s.type) {
    case "AndStatement": {
      const subs = ((s.statements as Statement[]) ?? []).map((sub) => {
        return [`statement {`, ...indent(tfStatement(sub), 2), `}`];
      });
      return [
        "and_statement {",
        ...subs.flat().map((l) => "  " + l),
        "}",
      ];
    }
    case "OrStatement": {
      const subs = ((s.statements as Statement[]) ?? []).map((sub) => {
        return [`statement {`, ...indent(tfStatement(sub), 2), `}`];
      });
      return [
        "or_statement {",
        ...subs.flat().map((l) => "  " + l),
        "}",
      ];
    }
    case "NotStatement": {
      return [
        "not_statement {",
        "  statement {",
        ...indent(tfStatement(s.statement as Statement), 4),
        "  }",
        "}",
      ];
    }
    case "LabelMatchStatement": {
      return [
        "label_match_statement {",
        `  scope = "${s.scope ?? "LABEL"}"`,
        `  key   = "${s.key}"`,
        "}",
      ];
    }
    case "ByteMatchStatement": {
      const fim = s.fieldToMatch as { type: string } | undefined;
      const fieldBlock = tfFieldToMatch(fim?.type ?? "URI_PATH");
      return [
        "byte_match_statement {",
        `  search_string         = "${(s.searchString as string) ?? ""}"`,
        `  positional_constraint = "${s.positionalConstraint ?? "EXACTLY"}"`,
        `  field_to_match {`,
        `    ${fieldBlock}`,
        `  }`,
        `  text_transformation {`,
        `    priority = 0`,
        `    type     = "NONE"`,
        `  }`,
        "}",
      ];
    }
    case "IPSetReferenceStatement": {
      return [
        "ip_set_reference_statement {",
        `  arn = "${s.arn}"`,
        "}",
      ];
    }
    case "ManagedRuleGroupStatement": {
      const excluded = ((s.excludedRules as string[]) ?? [])
        .map((r) => `  rule_action_override {\n    name = "${r}"\n    action_to_use {\n      count {}\n    }\n  }`);
      return [
        "managed_rule_group_statement {",
        `  vendor_name = "${s.vendorName ?? "AWS"}"`,
        `  name        = "${s.name}"`,
        ...excluded,
        "}",
      ];
    }
    case "GeoMatchStatement": {
      const codes = ((s.countryCodes as string[]) ?? []).map((c) => `"${c}"`).join(", ");
      return [
        "geo_match_statement {",
        `  country_codes = [${codes}]`,
        "}",
      ];
    }
    case "RateBasedStatement": {
      return [
        "rate_based_statement {",
        `  limit              = ${s.rateLimit ?? s.limit ?? 100}`,
        `  aggregate_key_type = "${s.aggregateKeyType ?? "IP"}"`,
        "}",
      ];
    }
    default: {
      return [`# Unsupported statement type: ${s.type}`];
    }
  }
}

function tfFieldToMatch(type: string): string {
  switch (type) {
    case "URI_PATH": return "uri_path {}";
    case "QUERY_STRING": return "query_string {}";
    case "BODY": return "body {}";
    case "METHOD": return "method {}";
    case "ALL_QUERY_ARGUMENTS": return "all_query_arguments {}";
    default: return `${type.toLowerCase()} {}`;
  }
}

// ---------- AWS CLI ----------
//
// update-web-acl requires the full rules list — can't add a single rule.
// We produce a one-liner template the user can paste a file path into.

export function toCli(rule: Rule, webAclName: string = "MyWebACL", scope: string = "REGIONAL"): string {
  const ruleFile = `./${rule.name}.json`;
  return `# 1. Save the rule to a file:
cat > ${ruleFile} << 'EOF'
${JSON.stringify(rule, null, 2)}
EOF

# 2. Get the current WebACL, append the rule, and push back:
aws wafv2 get-web-acl \\
  --name ${webAclName} \\
  --scope ${scope} \\
  --id <WEB_ACL_ID> > current-webacl.json

# 3. Edit current-webacl.json to add the new rule into .WebACL.Rules,
#    then call update-web-acl with the merged rules array:
aws wafv2 update-web-acl \\
  --name ${webAclName} \\
  --scope ${scope} \\
  --id <WEB_ACL_ID> \\
  --lock-token <LOCK_TOKEN_FROM_GET> \\
  --default-action Allow={} \\
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=${webAclName} \\
  --rules file://merged-rules.json`;
}

// ---------- helper ----------

function indent(lines: string[], spaces: number): string[] {
  const pad = " ".repeat(spaces);
  return lines.map((l) => pad + l);
}

// ---------- dispatch ----------

export function exportException(rule: Rule, format: ExceptionExportFormat, webAclName?: string, scope?: string): string {
  switch (format) {
    case "json": return toJson(rule);
    case "cloudformation": return toCloudFormation(rule);
    case "terraform": return toTerraform(rule);
    case "cli": return toCli(rule, webAclName, scope);
  }
}
