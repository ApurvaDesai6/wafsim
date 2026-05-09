// WAFSim v3 — Exception rule generator
//
// Given a parsed WAF log of a false-positive block, generates a structured
// WAF Rule that would have allowed that request. Three strategies, ordered
// from most-recommended (narrowest + preserves protection) to least:
//
//   1. LABEL_MATCH_EXCEPTION (preferred per AWS Developer Guide):
//        Set the managed rule's action to COUNT (so it still labels but
//        doesn't block), then add a high-priority custom rule that looks
//        for the managed rule's label AND NOT (the scope-down predicate
//        that identifies legit traffic). When the scope-down matches
//        legit traffic, the combined rule doesn't match, so no block.
//        Actual attacks that match the label also match the scope-down
//        NOT condition → rule matches → action BLOCK.
//
//   2. MANAGED_GROUP_EXCLUSION:
//        Add the specific offending sub-rule to the managed group's
//        ExcludedRules (acts as rule-level override to COUNT). Blunt — it
//        disables that sub-rule globally across the entire web ACL. Use
//        only when label-based isn't feasible.
//
//   3. CUSTOM_ALLOW_BYPASS:
//        High-priority custom ALLOW rule that matches the exact request
//        pattern (e.g. URI + method + client IP in allowlist). Simple but
//        carries security risk: if the allowlist is just IP, an attacker
//        from that IP bypasses all rules. Include IP allowlist scope-down
//        by default.
//
// Scope levels control how narrow/wide the exception is:
//
//   - EXACT:        match only the exact URI + method + query string.
//   - SAME_PATH:    match the same path, any method, any query string.
//   - SAME_ENDPOINT: match a broader path prefix (e.g. first two URL segments).
//
// References:
//   https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-label-match.html
//   https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing-phases.html
//   AWS WAF Developer Guide — label-based exceptions for managed rule groups

import type { Rule, Statement, VisibilityConfig, WebACL } from "@/lib/types";
import type { ParsedWafLog } from "@/lib/wafLogParser";

export type ExceptionStrategy =
  | "LABEL_MATCH_EXCEPTION"
  | "MANAGED_GROUP_EXCLUSION"
  | "CUSTOM_ALLOW_BYPASS";

export type ExceptionScope = "EXACT" | "SAME_PATH" | "SAME_ENDPOINT";

export interface ExceptionGeneratorInput {
  log: ParsedWafLog;
  /** Existing WebACL — informs priority assignment and existing-label checks. */
  webACL: WebACL;
  strategy: ExceptionStrategy;
  scope: ExceptionScope;
  /** Optional IP allowlist ARN (for CUSTOM_ALLOW_BYPASS). */
  ipAllowlistArn?: string;
  /** Optional rule-name override; otherwise auto-generated. */
  ruleName?: string;
}

export interface Caveat {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  text: string;
}

export interface GeneratedException {
  /** The rule to insert into the WebACL. For LABEL_MATCH_EXCEPTION / CUSTOM_ALLOW_BYPASS this is a new rule to prepend. For MANAGED_GROUP_EXCLUSION it's the updated managed-rule-group rule. */
  rule: Rule | null;
  /** If MANAGED_GROUP_EXCLUSION, the ExcludedRules array update to apply to the existing managed-group rule. */
  excludedRulesUpdate?: {
    targetRuleName: string; // name of the managed-group rule in the WebACL
    excludedRules: string[]; // sub-rules to exclude (rule names within the group)
  };
  /** Human-readable explanation to show in the UI. */
  explanation: string;
  /** Caveats — things the user needs to know/do before this works. */
  caveats: Caveat[];
  /** Suggested priority for insertion. */
  suggestedPriority: number;
}

export interface GenerateExceptionResult {
  ok: boolean;
  exception?: GeneratedException;
  error?: string;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function generateException(input: ExceptionGeneratorInput): GenerateExceptionResult {
  const { log, strategy } = input;

  if (!log.terminatingRuleId) {
    return {
      ok: false,
      error:
        "The WAF log does not include a terminatingRuleId. Cannot target an exception without knowing which rule blocked.",
    };
  }

  switch (strategy) {
    case "LABEL_MATCH_EXCEPTION":
      return buildLabelMatchException(input);
    case "MANAGED_GROUP_EXCLUSION":
      return buildManagedGroupExclusion(input);
    case "CUSTOM_ALLOW_BYPASS":
      return buildCustomAllowBypass(input);
    default:
      return { ok: false, error: `Unknown strategy: ${strategy}` };
  }
}

// ---------------------------------------------------------------------------
// Strategy 1: Label-match exception (PREFERRED)
// ---------------------------------------------------------------------------

function buildLabelMatchException(
  input: ExceptionGeneratorInput
): GenerateExceptionResult {
  const { log, webACL, scope, ruleName } = input;

  // Derive the label that the terminating rule emits. For AWS-managed rule
  // groups we can reconstruct it deterministically; otherwise we fall back
  // to using labels actually present in the log.
  const label = deriveLabelForTerminatingRule(log);
  if (!label) {
    return {
      ok: false,
      error:
        "Couldn't determine a label for the terminating rule. Use MANAGED_GROUP_EXCLUSION or CUSTOM_ALLOW_BYPASS instead.",
    };
  }

  const suggestedPriority = computeInsertionPriority(webACL, label, null);
  const scopeDown = buildScopeDownStatement(log, scope);
  const name = ruleName ?? (webACL.defaultAction === "ALLOW"
    ? safeName(`Block_nonLegit_${shortLabel(label)}_${scope}`)
    : safeName(`Allow_${shortLabel(label)}_${scope}`));

  // AWS-recommended label-match pattern — choose pattern based on WebACL default:
  //
  // - WebACL default ALLOW (most common) → emit BLOCK rule with
  //     AND(LabelMatch, NOT scope-down). Attacks (label matched, not
  //     legit shape) hit BLOCK and terminate. Legit traffic (label
  //     matched AND legit shape) doesn't match this rule, so it falls
  //     through to the default ALLOW. Self-contained — no downstream
  //     block rule required.
  //
  // - WebACL default BLOCK → emit ALLOW rule with
  //     AND(LabelMatch, scope-down). Legit traffic is explicitly allowed.
  //     Attacks fall through to default BLOCK.
  //
  // Both require the labeling rule (managed group sub-rule) in COUNT
  // mode so the label propagates to this rule (checked as a prerequisite
  // in the UI; see checkPrerequisites in ExceptionGeneratorPanel).
  //
  // Previous versions of this engine only emitted the ALLOW+AND variant
  // regardless of default action. That pattern is UNSAFE when default is
  // ALLOW because labeled-but-not-legit requests (actual attacks) fell
  // through to the default ALLOW. This implementation uses the
  // documented SSRF exception procedure exactly.
  const useBlockNotPattern = webACL.defaultAction === "ALLOW";

  // Rule structure (corrected): to ALLOW legit traffic that would
  // otherwise be blocked by a labeling rule, match traffic that:
  //   (a) has the managed rule's label applied, AND
  //   (b) matches the scope-down signature of legitimate traffic.
  // When both conditions hold, ALLOW terminates evaluation.
  //
  // Attacks that trigger the same label but don't match the scope-down
  // signature (e.g. different URI / query string) fall through to the
  // next rule in priority order, which should be a custom or managed
  // rule that blocks actual attacks.
  //
  // NOTE: this strategy assumes the labeling rule is in COUNT mode (or
  // a managed sub-rule override to COUNT) so that the label is applied
  // without terminating. The `caveats` array surfaces this requirement.
  // Build the statement based on pattern choice.
  //   BLOCK+NOT pattern (default-ALLOW WebACLs):
  //     AndStatement(LabelMatch, NotStatement(scopeDown))  →  BLOCK
  //   ALLOW+AND pattern (default-BLOCK WebACLs):
  //     AndStatement(LabelMatch, scopeDown)                →  ALLOW
  const labelMatch: Statement = {
    type: "LabelMatchStatement",
    scope: "LABEL",
    key: label,
  } as Statement;

  const scopeBranch: Statement = useBlockNotPattern
    ? ({
        type: "NotStatement",
        statement: scopeDown,
      } as Statement)
    : scopeDown;

  const statement: Statement = {
    type: "AndStatement",
    statements: [labelMatch, scopeBranch],
  } as Statement;

  const rule: Rule = {
    name,
    priority: suggestedPriority,
    action: useBlockNotPattern ? "BLOCK" : "ALLOW",
    statement,
    visibilityConfig: defaultVisibilityConfig(name),
    ruleLabels: [],
  };

  const caveats: Array<{ severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"; text: string }> = [];

  if (useBlockNotPattern) {
    caveats.push({
      severity: "HIGH",
      text:
        "Requires the managed rule group that emits this label to be in COUNT mode (override action: COUNT). Otherwise the managed rule blocks before the label can propagate to this rule.",
    });
    caveats.push({
      severity: "LOW",
      text:
        "Pattern: AND(label, NOT legit-shape) → BLOCK. Legit requests (label + legit shape) pass through to the WebACL's default ALLOW action. Attacks (label + non-legit shape) are blocked by this rule.",
    });
  } else {
    caveats.push({
      severity: "HIGH",
      text:
        "Requires the managed rule group to be in COUNT mode so labels propagate without blocking.",
    });
    caveats.push({
      severity: "MEDIUM",
      text:
        "Pattern: AND(label, legit-shape) → ALLOW. Safe only because WebACL default is BLOCK — attacks without matching legit shape fall through to the default BLOCK. Do not change default to ALLOW without also adding an explicit block rule for unmatched labeled traffic.",
    });
  }

  if (scope === "SAME_ENDPOINT") {
    caveats.push({
      severity: "MEDIUM",
      text: "SAME_ENDPOINT scope uses the first two URI segments — verify the prefix in the rule preview.",
    });
  }
  if (scope === "EXACT") {
    caveats.push({
      severity: "LOW",
      text: "EXACT scope includes the full query string. Requests to the same path with different query params don't match.",
    });
  }

  return {
    ok: true,
    exception: {
      rule,
      explanation: buildLabelExplanation(label, scope, log),
      suggestedPriority,
      strategy: "LABEL_MATCH_EXCEPTION",
      caveats,
    },
  };
}

function buildLabelExplanation(label: string, scope: ExceptionScope, log: ParsedWafLog): string {
  const scopeHuman = {
    EXACT: "the exact URI + method of the false-positive request",
    SAME_PATH: "the same URI path (any method / any query)",
    SAME_ENDPOINT: "the same endpoint prefix (first two URL segments)",
  }[scope];
  return `When a request (a) has the label ${label} applied by a managed rule group, AND (b) matches ${scopeHuman}, this rule ALLOWS the request. Legitimate traffic to this endpoint is allowed through. Actual attacks that hit the managed rule but do NOT match the scope-down predicate still get blocked.`;
}

// ---------------------------------------------------------------------------
// Strategy 2: Managed group exclusion
// ---------------------------------------------------------------------------

function buildManagedGroupExclusion(
  input: ExceptionGeneratorInput
): GenerateExceptionResult {
  const { log, webACL } = input;

  if (!log.terminatingRuleId) {
    return {
      ok: false,
      error: "No terminating rule ID in the log.",
    };
  }

  // Find the managed rule group rule in the WebACL that owns the terminating sub-rule.
  // Logs encode ruleGroupId as "{Vendor}#{GroupName}" (e.g. "AWS#AWSManagedRulesCommonRuleSet"),
  // so strip the vendor prefix before matching the statement's `name`.
  const normalizedGroupName = log.terminatingRuleGroupName
    ? log.terminatingRuleGroupName.includes("#")
      ? log.terminatingRuleGroupName.split("#").pop()
      : log.terminatingRuleGroupName
    : undefined;

  const targetRule = webACL.rules.find(
    (r) =>
      r.statement.type === "ManagedRuleGroupStatement" &&
      (normalizedGroupName
        ? (r.statement as { name?: string }).name === normalizedGroupName
        : true)
  );

  if (!targetRule) {
    return {
      ok: false,
      error:
        "Could not find a matching managed rule group in the current WebACL. Either the log came from a different WebACL, or the group isn't attached here.",
    };
  }

  const existingExcludedRules =
    (targetRule.statement as { excludedRules?: string[] }).excludedRules ?? [];
  const newExcludedRules = Array.from(
    new Set([...existingExcludedRules, log.terminatingRuleId])
  );

  const explanation = `Adds '${log.terminatingRuleId}' to the ExcludedRules of the '${targetRule.name}' managed rule group. AWS WAF will still evaluate this sub-rule and emit its label, but the action is overridden to COUNT — so it never blocks. This disables the sub-rule globally across the entire WebACL.`;

  const caveats: Caveat[] = [
    {
      severity: "HIGH",
      text: "This disables the sub-rule for ALL traffic, not just the specific URI/path. Consider LABEL_MATCH_EXCEPTION for a narrower fix.",
    },
    {
      severity: "LOW",
      text: "Labels are still applied, so downstream rules that depend on this label continue to work.",
    },
  ];

  return {
    ok: true,
    exception: {
      rule: null,
      excludedRulesUpdate: {
        targetRuleName: targetRule.name,
        excludedRules: newExcludedRules,
      },
      explanation,
      suggestedPriority: targetRule.priority,
      strategy: "MANAGED_GROUP_EXCLUSION",
      caveats,
    },
  };
}

// ---------------------------------------------------------------------------
// Strategy 3: Custom ALLOW bypass
// ---------------------------------------------------------------------------

function buildCustomAllowBypass(
  input: ExceptionGeneratorInput
): GenerateExceptionResult {
  const { log, webACL, scope, ruleName, ipAllowlistArn } = input;

  // Custom ALLOW bypass runs BEFORE all other rules (it's a bypass, not a
  // label-based exception). Priority = min(existing) - 1 so it wins.
  const suggestedPriority =
    webACL.rules.length === 0
      ? 0
      : Math.max(0, Math.min(...webACL.rules.map((r) => r.priority)) - 1);

  const scopeStatement = buildScopeDownStatement(log, scope);

  // If an IP allowlist is provided, AND it with the URI match. This is
  // the right move per label-match convention: never ship a bare URI-based
  // ALLOW without at least an IP constraint, or you hand attackers a
  // get-out-of-jail-free card.
  const statement: Statement = ipAllowlistArn
    ? ({
        type: "AndStatement",
        statements: [
          scopeStatement,
          {
            type: "IPSetReferenceStatement",
            arn: ipAllowlistArn,
            ipSetReference: { arn: ipAllowlistArn },
          } as Statement,
        ],
      } as Statement)
    : scopeStatement;

  const name = ruleName ?? safeName(`AllowBypass_${scope}`);

  const rule: Rule = {
    name,
    priority: suggestedPriority,
    action: "ALLOW",
    statement,
    visibilityConfig: defaultVisibilityConfig(name),
    ruleLabels: [],
  };

  const caveats: Caveat[] = [];
  if (!ipAllowlistArn) {
    caveats.push({
      severity: "CRITICAL",
      text: "No IP allowlist was supplied. This rule will ALLOW the matching URI pattern from ANY source IP, including attackers. Add an IP allowlist or use LABEL_MATCH_EXCEPTION instead.",
    });
  }
  caveats.push({
    severity: "MEDIUM",
    text: `This rule runs at priority ${suggestedPriority} — before any managed rule groups. Traffic matching it exits evaluation immediately with ALLOW.`,
  });

  return {
    ok: true,
    exception: {
      rule,
      explanation: `Prepends a high-priority ALLOW rule matching ${scopeHuman(scope)}${
        ipAllowlistArn ? " AND the IP is in the allowlist" : ""
      }. This rule runs before any managed rule group, so matching traffic bypasses all downstream rules entirely.`,
      suggestedPriority,
      strategy: "CUSTOM_ALLOW_BYPASS",
      caveats,
    },
  };
}

// ---------------------------------------------------------------------------
// Scope-down statement construction
// ---------------------------------------------------------------------------

function buildScopeDownStatement(log: ParsedWafLog, scope: ExceptionScope): Statement {
  const uri = log.request.uri;
  const path = uri.split("?")[0];
  const queryString = uri.includes("?") ? uri.split("?").slice(1).join("?") : "";

  switch (scope) {
    case "EXACT": {
      // AWS WAF's URI_PATH field only contains the path (not the query).
      // So an EXACT match needs both URI_PATH EXACTLY and QUERY_STRING EXACTLY
      // joined with AND. If there's no query, a single URI_PATH match suffices.
      const pathMatch: Statement = {
        type: "ByteMatchStatement",
        searchString: path,
        fieldToMatch: { type: "URI_PATH" },
        textTransformations: [{ type: "NONE", priority: 0 }],
        positionalConstraint: "EXACTLY",
      } as Statement;
      if (!queryString) return pathMatch;
      const queryMatch: Statement = {
        type: "ByteMatchStatement",
        searchString: queryString,
        fieldToMatch: { type: "QUERY_STRING" },
        textTransformations: [{ type: "NONE", priority: 0 }],
        positionalConstraint: "EXACTLY",
      } as Statement;
      return {
        type: "AndStatement",
        statements: [pathMatch, queryMatch],
      } as Statement;
    }
    case "SAME_PATH": {
      // Match the path portion only (any query string).
      return {
        type: "ByteMatchStatement",
        searchString: path,
        fieldToMatch: { type: "URI_PATH" },
        textTransformations: [{ type: "NONE", priority: 0 }],
        positionalConstraint: "EXACTLY",
      } as Statement;
    }
    case "SAME_ENDPOINT": {
      // First two URL segments.
      const segments = path.split("/").filter(Boolean);
      const prefix = "/" + segments.slice(0, 2).join("/");
      return {
        type: "ByteMatchStatement",
        searchString: prefix,
        fieldToMatch: { type: "URI_PATH" },
        textTransformations: [{ type: "NONE", priority: 0 }],
        positionalConstraint: "STARTS_WITH",
      } as Statement;
    }
  }
}

function scopeHuman(scope: ExceptionScope): string {
  return {
    EXACT: "the exact URI from the false-positive log",
    SAME_PATH: "the same URI path (any query)",
    SAME_ENDPOINT: "the same endpoint prefix",
  }[scope];
}

// ---------------------------------------------------------------------------
// Label derivation
// ---------------------------------------------------------------------------

function deriveLabelForTerminatingRule(log: ParsedWafLog): string | null {
  // If a fully-qualified managed label is already in the log's labels array
  // and it matches the terminating rule name, prefer that.
  const matchedLabel = log.labels.find((l) =>
    log.terminatingRuleId ? l.toLowerCase().includes(log.terminatingRuleId.toLowerCase()) : false
  );
  if (matchedLabel) return matchedLabel;

  // AWS-managed label format:
  //   awswaf:managed:aws:{rule-group-suffix}:{rule-name}
  // e.g. awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH
  if (log.terminatingRuleGroupName && log.terminatingRuleId) {
    const suffix = managedGroupLabelSuffix(log.terminatingRuleGroupName);
    if (suffix) {
      return `awswaf:managed:aws:${suffix}:${log.terminatingRuleId}`;
    }
  }
  // Last resort: use whatever label the log surfaced
  return log.labels[0] ?? null;
}

function managedGroupLabelSuffix(ruleGroupName: string): string | null {
  const map: Record<string, string> = {
    AWSManagedRulesCommonRuleSet: "core-rule-set",
    AWSManagedRulesKnownBadInputsRuleSet: "known-bad-inputs",
    AWSManagedRulesSQLiRuleSet: "sqli",
    AWSManagedRulesLinuxRuleSet: "linux-rule-set",
    AWSManagedRulesUnixRuleSet: "unix-rule-set",
    AWSManagedRulesWindowsRuleSet: "windows-rule-set",
    AWSManagedRulesPHPRuleSet: "php-rule-set",
    AWSManagedRulesWordPressRuleSet: "wordpress-rule-set",
    AWSManagedRulesAdminProtectionRuleSet: "admin-protection",
    AWSManagedRulesAmazonIpReputationList: "amazon-ip-list",
    AWSManagedRulesAnonymousIpList: "anonymous-ip-list",
    AWSManagedRulesBotControlRuleSet: "bot-control",
    AWSManagedRulesATPRuleSet: "atp",
    AWSManagedRulesACFPRuleSet: "acfp",
  };
  return map[ruleGroupName] ?? null;
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

function computeInsertionPriority(
  webACL: WebACL,
  label: string | null,
  targetRuleName: string | null
): number {
  // The exception rule must run AFTER the rule that emits the label
  // (otherwise the LabelMatchStatement would never see the label as applied).
  // Find the label-emitting rule by checking ruleLabels or the managed
  // rule group rule that owns the terminating sub-rule.
  let emitterPriority: number | null = null;

  if (targetRuleName) {
    const rule = webACL.rules.find((r) => r.name === targetRuleName);
    if (rule) emitterPriority = rule.priority;
  }
  if (emitterPriority === null && label) {
    // Scan rules whose ruleLabels contains the label (custom rule emitting).
    const rule = webACL.rules.find((r) => (r.ruleLabels ?? []).includes(label));
    if (rule) emitterPriority = rule.priority;
  }
  if (emitterPriority === null && label) {
    // Managed rule group rule — its sub-rules emit labels in the awswaf:managed:aws:{group}:{rule} namespace
    // Find a managed group whose label namespace matches our label's prefix.
    const rule = webACL.rules.find((r) => {
      if (r.statement.type !== "ManagedRuleGroupStatement") return false;
      const name = (r.statement as { name?: string }).name ?? "";
      const suffix = managedGroupLabelSuffix(name);
      return suffix && label.includes(`:aws:${suffix}:`);
    });
    if (rule) emitterPriority = rule.priority;
  }

  // If we found the emitter, insert just after it. Find the next available
  // integer priority (AWS requires unique priorities in the WebACL).
  if (emitterPriority !== null) {
    const used = new Set(webACL.rules.map((r) => r.priority));
    let candidate = emitterPriority + 1;
    while (used.has(candidate)) candidate++;
    return candidate;
  }

  // No emitter found — fall back to the end of the rule list so it at least
  // runs after any existing rules (label propagation would require a rule
  // earlier in the list to have emitted the label).
  if (webACL.rules.length === 0) return 0;
  const max = Math.max(...webACL.rules.map((r) => r.priority));
  return max + 1;
}

function defaultVisibilityConfig(name: string): VisibilityConfig {
  return {
    sampledRequestsEnabled: true,
    cloudWatchMetricsEnabled: true,
    metricName: name.replace(/[^A-Za-z0-9]/g, ""),
  };
}

function shortLabel(label: string): string {
  // awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH → GenericRFI_URIPATH
  const last = label.split(":").pop() ?? label;
  return last.replace(/[^A-Za-z0-9]/g, "");
}

function safeName(raw: string): string {
  return raw.replace(/[^A-Za-z0-9_]/g, "_").slice(0, 128);
}
