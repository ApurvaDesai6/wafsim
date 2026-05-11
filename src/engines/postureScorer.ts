// WAFSim v3 — WebACL security posture scorer
//
// Scores a WebACL across 5 dimensions (20 points each, 100 total):
//   1. Coverage         — breadth of protection (managed groups, attack types)
//   2. Defense          — what actually blocks vs counts
//   3. Rate limiting    — DoS + brute force protection
//   4. Visibility       — observability (sampling, labels, metric names)
//   5. Hygiene          — config correctness (priorities, WCU, scope match)
//
// Each dimension returns findings (issue + severity + recommendation) so the
// UI can surface actionable guidance, not just a number.
//
// This is opinionated and deliberately lenient: a score of 0 means "no WAF",
// 50+ means "basic protection", 80+ means "production-appropriate for most
// apps", 95+ means "defense-in-depth with strong observability".
//
// Design inspired by the 5-category rubric in
// https://github.com/vijaygupta18/system-design-simulator, adapted for WAF.

import type { WebACL, Rule, Statement } from "@/lib/types";
import { MANAGED_RULE_GROUPS } from "@/lib/managedRuleGroups";
import { calculateWebACLUWCU, MAX_WCU, BASE_TIER_WCU } from "./wcuCalculator";

export type PostureCategory =
  | "Coverage"
  | "Defense"
  | "RateLimiting"
  | "Visibility"
  | "Hygiene";

export type FindingSeverity = "info" | "warning" | "error";

export interface PostureFinding {
  category: PostureCategory;
  severity: FindingSeverity;
  title: string;
  detail: string;
  recommendation?: string;
}

export interface CategoryScore {
  category: PostureCategory;
  score: number;           // 0–20
  max: number;             // always 20
  findings: PostureFinding[];
}

export interface PostureReport {
  totalScore: number;      // 0–100
  maxScore: number;        // always 100
  verdict: PostureVerdict;
  categories: CategoryScore[];
  findings: PostureFinding[];   // flattened, sorted by severity desc
  summary: string;
}

export type PostureVerdict =
  | "No Protection"
  | "Minimal"
  | "Basic"
  | "Solid"
  | "Strong"
  | "Defense in Depth";

const VERDICT_BANDS: Array<{ min: number; verdict: PostureVerdict }> = [
  { min: 0,  verdict: "No Protection" },
  { min: 20, verdict: "Minimal" },
  { min: 40, verdict: "Basic" },
  { min: 60, verdict: "Solid" },
  { min: 80, verdict: "Strong" },
  { min: 95, verdict: "Defense in Depth" },
];

function verdictFor(score: number): PostureVerdict {
  let v: PostureVerdict = "No Protection";
  for (const band of VERDICT_BANDS) if (score >= band.min) v = band.verdict;
  return v;
}

// ---------------------------------------------------------------------------
// Category 1 — Coverage
// Does the WebACL protect against common attack categories?
// Awards points for: managed rule group presence, SQLi coverage, XSS coverage,
// known-bad-inputs coverage, IP reputation coverage.
// ---------------------------------------------------------------------------

function scoreCoverage(webACL: WebACL): CategoryScore {
  const findings: PostureFinding[] = [];
  let score = 0;
  const max = 20;

  const managedGroups = webACL.rules
    .map((r) => r.statement)
    .filter((s): s is Statement & { type: "ManagedRuleGroupStatement"; name: string } =>
      s.type === "ManagedRuleGroupStatement"
    );
  const managedNames = new Set(managedGroups.map((s) => s.name));

  // +5 if any managed rule group at all
  if (managedGroups.length > 0) {
    score += 5;
  } else {
    findings.push({
      category: "Coverage",
      severity: "warning",
      title: "No AWS Managed Rule Groups configured",
      detail:
        "Managed Rule Groups (CRS, Known Bad Inputs, SQLi, etc.) provide baseline protection against OWASP Top 10 and known exploits.",
      recommendation:
        "Add AWSManagedRulesCommonRuleSet as a starting point — it costs 700 WCU and protects against the most common vulnerabilities.",
    });
  }

  // +5 if Core Rule Set (CRS) is present
  if (managedNames.has("AWSManagedRulesCommonRuleSet")) {
    score += 5;
  } else if (managedGroups.length > 0) {
    findings.push({
      category: "Coverage",
      severity: "info",
      title: "AWSManagedRulesCommonRuleSet not attached",
      detail:
        "The Core Rule Set (CRS) covers OWASP Top 10 classes including RFI, size restrictions, bad user-agents, and malformed requests.",
      recommendation:
        "Add AWSManagedRulesCommonRuleSet unless you have a specific reason to build equivalent custom rules.",
    });
  }

  // +3 if SQLi coverage — either AWSManagedRulesSQLiRuleSet or a custom SqliMatch rule
  const hasSQLiManaged = managedNames.has("AWSManagedRulesSQLiRuleSet");
  const hasSQLiCustom = webACL.rules.some(
    (r) => containsStatementType(r.statement, "SqliMatchStatement")
  );
  if (hasSQLiManaged || hasSQLiCustom) {
    score += 3;
  } else {
    findings.push({
      category: "Coverage",
      severity: "warning",
      title: "No SQLi protection",
      detail:
        "No AWSManagedRulesSQLiRuleSet or custom SqliMatchStatement rule was found.",
      recommendation:
        "Add AWSManagedRulesSQLiRuleSet (200 WCU) or a custom rule with SqliMatchStatement inspecting BODY and QUERY_STRING.",
    });
  }

  // +3 if XSS coverage
  const hasXSSCustom = webACL.rules.some(
    (r) => containsStatementType(r.statement, "XssMatchStatement")
  );
  // CRS and Known Bad Inputs also have XSS coverage (GenericXSS labels)
  const hasXSSManaged =
    managedNames.has("AWSManagedRulesCommonRuleSet") ||
    managedNames.has("AWSManagedRulesKnownBadInputsRuleSet");
  if (hasXSSCustom || hasXSSManaged) {
    score += 3;
  } else {
    findings.push({
      category: "Coverage",
      severity: "warning",
      title: "No XSS protection",
      detail:
        "No custom XssMatchStatement rule and no managed rule group that covers XSS (Common Rule Set, Known Bad Inputs) was found.",
      recommendation: "Add AWSManagedRulesKnownBadInputsRuleSet (200 WCU) or a custom XssMatchStatement rule.",
    });
  }

  // +2 for known-bad-inputs coverage (Log4Shell and similar)
  if (managedNames.has("AWSManagedRulesKnownBadInputsRuleSet")) {
    score += 2;
  } else {
    findings.push({
      category: "Coverage",
      severity: "info",
      title: "AWSManagedRulesKnownBadInputsRuleSet not attached",
      detail:
        "Known Bad Inputs covers Log4Shell (JNDI) and other signatures that aren't fully covered by CRS.",
      recommendation: "Add AWSManagedRulesKnownBadInputsRuleSet (200 WCU) for defense-in-depth.",
    });
  }

  // +2 for IP reputation
  if (
    managedNames.has("AWSManagedRulesAmazonIpReputationList") ||
    managedNames.has("AWSManagedRulesAnonymousIpList")
  ) {
    score += 2;
  } else {
    findings.push({
      category: "Coverage",
      severity: "info",
      title: "No IP reputation rule groups",
      detail:
        "AmazonIpReputationList (25 WCU) and AnonymousIpList (50 WCU) block known bad IPs, Tor exit nodes, and hosting IPs.",
      recommendation: "Add one or both — they are cheap (low WCU) and effective.",
    });
  }

  return { category: "Coverage", score, max, findings };
}

// ---------------------------------------------------------------------------
// Category 2 — Defense
// Are rules actually BLOCKING (not just COUNTING)?
// Awards points for: terminating actions on critical rules, default-action
// being BLOCK (fail-closed) OR ALLOW with comprehensive rules.
// ---------------------------------------------------------------------------

function scoreDefense(webACL: WebACL): CategoryScore {
  const findings: PostureFinding[] = [];
  let score = 0;
  const max = 20;

  const totalRules = webACL.rules.length;
  if (totalRules === 0) {
    findings.push({
      category: "Defense",
      severity: "error",
      title: "WebACL has no rules",
      detail: "Only the default action applies, which means the WAF provides no inspection.",
      recommendation: "Add at least one managed rule group or custom rule.",
    });
    return { category: "Defense", score: 0, max, findings };
  }

  const countRules = webACL.rules.filter((r) => r.action === "COUNT");
  const blockRules = webACL.rules.filter((r) => r.action === "BLOCK");
  const allowRules = webACL.rules.filter((r) => r.action === "ALLOW");

  // +8 if there's at least one BLOCK rule
  if (blockRules.length > 0) {
    score += 8;
  } else {
    findings.push({
      category: "Defense",
      severity: "error",
      title: "No BLOCK rules — WAF is monitor-only",
      detail:
        "All rules are set to COUNT, ALLOW, CAPTCHA, or CHALLENGE. This is fine for a tuning phase but provides no active blocking.",
      recommendation:
        "After tuning, switch at least the high-confidence rules (e.g. SQLi on query string) to BLOCK.",
    });
  }

  // +4 if most rules (> 50%) are terminating (not COUNT)
  const terminatingRatio =
    totalRules === 0 ? 0 : (totalRules - countRules.length) / totalRules;
  if (terminatingRatio >= 0.5) {
    score += 4;
  } else {
    findings.push({
      category: "Defense",
      severity: "warning",
      title: `${countRules.length} of ${totalRules} rules are in COUNT mode`,
      detail: "COUNT rules do not terminate evaluation and do not block traffic.",
      recommendation: "Move rules to BLOCK/CAPTCHA/CHALLENGE once tuned.",
    });
  }

  // +4 if ALLOW rules are scoped-down (have AND with non-IP conditions)
  // Bare IP-only ALLOW rules at high priority are risky — an attacker from an
  // allowlisted IP gets unchecked access. +4 if allows are scoped.
  const bareIpAllows = allowRules.filter((r) => r.statement.type === "IPSetReferenceStatement");
  if (allowRules.length === 0 || bareIpAllows.length === 0) {
    score += 4;
  } else {
    findings.push({
      category: "Defense",
      severity: "warning",
      title: `${bareIpAllows.length} bare IP-only ALLOW rule(s)`,
      detail:
        "ALLOW rules that only check IP bypass all subsequent rules for allowlisted sources. An attacker from a trusted IP is unchecked.",
      recommendation:
        "Combine IP allowlists with AndStatement against specific URI paths or request patterns, or use them with caution.",
    });
  }

  // +4 for sensible default action
  // Best practice: default ALLOW means your rules enumerate what's blocked.
  // default BLOCK means you enumerate what's allowed (stricter, less common).
  // Either is valid — award points for intentional choice (not neutral).
  if (webACL.defaultAction === "ALLOW" || webACL.defaultAction === "BLOCK") {
    score += 4;
  }

  return { category: "Defense", score, max, findings };
}

// ---------------------------------------------------------------------------
// Category 3 — Rate Limiting
// DoS / brute-force protection via rate-based rules.
// ---------------------------------------------------------------------------

function scoreRateLimiting(webACL: WebACL): CategoryScore {
  const findings: PostureFinding[] = [];
  let score = 0;
  const max = 20;

  const rateRules = webACL.rules.filter(
    (r) => r.statement.type === "RateBasedStatement"
  );

  if (rateRules.length === 0) {
    findings.push({
      category: "RateLimiting",
      severity: "warning",
      title: "No rate-based rules",
      detail: "Rate-based rules protect against credential stuffing, scrapers, and application-layer DoS.",
      recommendation:
        "Add at least one rate-based rule. Start broad (e.g. 2000 req / 5 min per IP on /) and tighter on sensitive endpoints (e.g. 100 req / 5 min on /login).",
    });
    return { category: "RateLimiting", score, max, findings };
  }

  // +10 for at least one rate rule
  score += 10;

  // +5 for rate rule with scope-down statement (targeted limits on sensitive endpoints)
  const scopedRateRules = rateRules.filter(
    (r) =>
      r.statement.type === "RateBasedStatement" &&
      (r.statement as { scopeDownStatement?: unknown }).scopeDownStatement
  );
  if (scopedRateRules.length > 0) {
    score += 5;
  } else {
    findings.push({
      category: "RateLimiting",
      severity: "info",
      title: "No rate-based rule with scope-down statement",
      detail:
        "Global per-IP rate limits protect against floods but may be too blunt for shared IPs (corporate NAT, mobile carriers).",
      recommendation:
        "Add a rate-based rule with a ScopeDownStatement targeting sensitive paths (e.g. /login, /api/v1/payments).",
    });
  }

  // +5 for reasonable limit values (100–10,000 per 5 min = not too low, not too high)
  const anyReasonableLimit = rateRules.some((r) => {
    if (r.statement.type !== "RateBasedStatement") return false;
    // Canonical field name is rateLimit per src/lib/types.ts
    const limit = (r.statement as { rateLimit?: number }).rateLimit;
    return typeof limit === "number" && limit >= 100 && limit <= 10_000;
  });
  if (anyReasonableLimit) {
    score += 5;
  } else {
    findings.push({
      category: "RateLimiting",
      severity: "info",
      title: "Rate-based rule limits are outside typical range (100–10,000 per 5 min)",
      detail:
        "Very low limits (< 100) block legitimate users behind shared IPs. Very high limits (> 10,000) provide minimal protection against sustained floods.",
      recommendation: "Tune rate limits by measuring baseline traffic in CloudWatch first.",
    });
  }

  return { category: "RateLimiting", score, max, findings };
}

// ---------------------------------------------------------------------------
// Category 4 — Visibility
// Can you actually see what the WAF is doing?
// ---------------------------------------------------------------------------

function scoreVisibility(webACL: WebACL): CategoryScore {
  const findings: PostureFinding[] = [];
  let score = 0;
  const max = 20;

  if (webACL.rules.length === 0) {
    return { category: "Visibility", score: 0, max, findings };
  }

  // +6 if all rules have sampledRequestsEnabled
  const ruleSampled = webACL.rules.filter(
    (r) => r.visibilityConfig?.sampledRequestsEnabled
  );
  if (ruleSampled.length === webACL.rules.length) {
    score += 6;
  } else {
    findings.push({
      category: "Visibility",
      severity: "warning",
      title: `${webACL.rules.length - ruleSampled.length} rule(s) have sampledRequestsEnabled=false`,
      detail:
        "Without sampling, you cannot replay matched requests from the WAF console — limiting false-positive triage.",
      recommendation: "Enable sampledRequestsEnabled on all rules.",
    });
  }

  // +6 if all rules have cloudWatchMetricsEnabled
  const ruleMetrics = webACL.rules.filter(
    (r) => r.visibilityConfig?.cloudWatchMetricsEnabled
  );
  if (ruleMetrics.length === webACL.rules.length) {
    score += 6;
  } else {
    findings.push({
      category: "Visibility",
      severity: "warning",
      title: `${webACL.rules.length - ruleMetrics.length} rule(s) have cloudWatchMetricsEnabled=false`,
      detail: "Without per-rule CloudWatch metrics you cannot alarm on specific rule match rates.",
      recommendation: "Enable cloudWatchMetricsEnabled on all rules.",
    });
  }

  // +4 if at least one rule emits a label (enables downstream exception rules + filtering)
  const rulesWithLabels = webACL.rules.filter(
    (r) => r.ruleLabels && r.ruleLabels.length > 0
  );
  if (rulesWithLabels.length > 0) {
    score += 4;
  } else {
    findings.push({
      category: "Visibility",
      severity: "info",
      title: "No rules emit custom labels",
      detail:
        "Labels let you filter WAF logs and build exception rules for false positives without disabling managed rule groups.",
      recommendation:
        "Add ruleLabels to custom rules so operators can identify why a request matched in logs.",
    });
  }

  // +4 if all metricName values are non-empty and unique
  const metricNames = webACL.rules.map((r) => r.visibilityConfig?.metricName).filter(Boolean);
  const uniqueMetricNames = new Set(metricNames);
  if (metricNames.length === webACL.rules.length && uniqueMetricNames.size === metricNames.length) {
    score += 4;
  } else if (metricNames.length < webACL.rules.length) {
    findings.push({
      category: "Visibility",
      severity: "warning",
      title: "Some rules are missing metricName",
      detail: "AWS requires metricName on every rule's VisibilityConfig.",
      recommendation: "Assign a unique metricName per rule (alphanumeric only).",
    });
  } else if (uniqueMetricNames.size < metricNames.length) {
    findings.push({
      category: "Visibility",
      severity: "warning",
      title: "Duplicate metricName values across rules",
      detail: "CloudWatch metrics are keyed by metricName — duplicates collapse rule visibility.",
      recommendation: "Use a unique metricName per rule.",
    });
  }

  return { category: "Visibility", score, max, findings };
}

// ---------------------------------------------------------------------------
// Category 5 — Hygiene
// Config correctness: priorities, WCU, scope match, managed rule group
// scope matching the WebACL scope.
// ---------------------------------------------------------------------------

function scoreHygiene(webACL: WebACL): CategoryScore {
  const findings: PostureFinding[] = [];
  let score = 0;
  const max = 20;

  // +5 for no duplicate priorities
  const priorities = webACL.rules.map((r) => r.priority);
  const uniquePriorities = new Set(priorities);
  if (uniquePriorities.size === priorities.length) {
    score += 5;
  } else {
    findings.push({
      category: "Hygiene",
      severity: "error",
      title: "Duplicate rule priorities",
      detail:
        "AWS WAF requires unique priorities across rules in a WebACL. Duplicates cause deployment errors.",
      recommendation: "Renumber priorities so each is unique.",
    });
  }

  // +5 for no duplicate rule names
  const names = webACL.rules.map((r) => r.name);
  const uniqueNames = new Set(names);
  if (uniqueNames.size === names.length) {
    score += 5;
  } else {
    findings.push({
      category: "Hygiene",
      severity: "error",
      title: "Duplicate rule names",
      detail: "Rule names must be unique within a WebACL.",
      recommendation: "Rename any duplicates.",
    });
  }

  // +5 for WCU within reasonable budget
  const totalWCU = calculateWebACLUWCU(webACL.rules).total;
  if (totalWCU === 0) {
    // no rules — skip awarding or deducting
  } else if (totalWCU <= BASE_TIER_WCU) {
    score += 5;
  } else if (totalWCU <= MAX_WCU) {
    score += 2;
    findings.push({
      category: "Hygiene",
      severity: "info",
      title: `WCU (${totalWCU}) exceeds base tier (${BASE_TIER_WCU})`,
      detail:
        "AWS charges tiered fees above the base 1500 WCU. This is fine for heavy workloads but worth knowing.",
      recommendation: "If cost-sensitive, audit rules for unused transformations or consolidate.",
    });
  } else {
    findings.push({
      category: "Hygiene",
      severity: "error",
      title: `WCU (${totalWCU}) exceeds maximum (${MAX_WCU})`,
      detail: "AWS will reject a WebACL that exceeds 5000 WCUs.",
      recommendation: "Remove or simplify rules until WCU is under 5000.",
    });
  }

  // +5 for managed rule group scope matching WebACL scope
  // AWS CLOUDFRONT_ONLY groups can't be used in REGIONAL, and vice versa.
  const scopeMismatches = webACL.rules
    .map((r) => r.statement)
    .filter((s): s is Statement & { type: "ManagedRuleGroupStatement"; name: string } =>
      s.type === "ManagedRuleGroupStatement"
    )
    .map((s) => ({ stmt: s, model: MANAGED_RULE_GROUPS[s.name] }))
    .filter(({ model }) => {
      if (!model) return false;
      if (model.scope === "BOTH") return false;
      if (model.scope === "CLOUDFRONT_ONLY" && webACL.scope !== "CLOUDFRONT") return true;
      if (model.scope === "REGIONAL_ONLY" && webACL.scope !== "REGIONAL") return true;
      return false;
    });

  if (scopeMismatches.length === 0) {
    score += 5;
  } else {
    for (const { stmt, model } of scopeMismatches) {
      findings.push({
        category: "Hygiene",
        severity: "error",
        title: `${stmt.name} scope mismatch`,
        detail: `This managed rule group is ${model.scope} but the WebACL is ${webACL.scope}.`,
        recommendation:
          model.scope === "CLOUDFRONT_ONLY"
            ? "Attach this WebACL to a CloudFront distribution, or remove the rule."
            : "Attach this WebACL to a REGIONAL resource (ALB, API GW, etc.), or remove the rule.",
      });
    }
  }

  return { category: "Hygiene", score, max, findings };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function containsStatementType(statement: Statement, type: Statement["type"]): boolean {
  if (statement.type === type) return true;
  if (statement.type === "AndStatement" || statement.type === "OrStatement") {
    const inner = (statement as { statements?: Statement[] }).statements ?? [];
    return inner.some((s) => containsStatementType(s, type));
  }
  if (statement.type === "NotStatement") {
    const inner = (statement as { statement?: Statement }).statement;
    return inner ? containsStatementType(inner, type) : false;
  }
  if (statement.type === "RateBasedStatement") {
    const sd = (statement as { scopeDownStatement?: Statement }).scopeDownStatement;
    return sd ? containsStatementType(sd, type) : false;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Public: score a WebACL
// ---------------------------------------------------------------------------

export function scoreWebACL(webACL: WebACL): PostureReport {
  const categories: CategoryScore[] = [
    scoreCoverage(webACL),
    scoreDefense(webACL),
    scoreRateLimiting(webACL),
    scoreVisibility(webACL),
    scoreHygiene(webACL),
  ];

  const totalScore = categories.reduce((a, c) => a + c.score, 0);
  const maxScore = categories.reduce((a, c) => a + c.max, 0);
  const verdict = verdictFor(totalScore);

  // Flatten + sort findings: error > warning > info
  const severityOrder: Record<FindingSeverity, number> = { error: 0, warning: 1, info: 2 };
  const findings = categories
    .flatMap((c) => c.findings)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const summary = generateSummary(totalScore, verdict, categories, findings);

  return { totalScore, maxScore, verdict, categories, findings, summary };
}

function generateSummary(
  totalScore: number,
  verdict: PostureVerdict,
  categories: CategoryScore[],
  findings: PostureFinding[]
): string {
  const weakest = [...categories].sort((a, b) => a.score - b.score)[0];
  const errorCount = findings.filter((f) => f.severity === "error").length;
  const warningCount = findings.filter((f) => f.severity === "warning").length;

  const parts = [`WebACL posture: ${verdict} (${totalScore}/100).`];
  if (errorCount > 0) parts.push(`${errorCount} error${errorCount === 1 ? "" : "s"} to address.`);
  if (warningCount > 0) parts.push(`${warningCount} warning${warningCount === 1 ? "" : "s"}.`);
  if (weakest.score < 10) parts.push(`Weakest area: ${weakest.category} (${weakest.score}/20).`);

  return parts.join(" ");
}

// ============================================================================
// Fleet-level scoring (rc.9) — overall posture across all WebACLs in a
// topology, plus findings that only make sense at fleet scope (unprotected
// resources, inconsistent protection, default-action drift).
//
// Rationale: a topology with 3 WAFs at 70/70/70 is meaningfully different
// from 3 at 95/95/20. Per-WebACL scoring can't surface the weakest-link.
// The fleet view does.
// ============================================================================

export interface FleetWebACLEntry {
  id: string;
  name: string;
  scope: "CLOUDFRONT" | "REGIONAL";
  /** Resource IDs this WebACL is currently attached to in the topology. */
  attachedResourceIds: string[];
  /** Resource kinds for prettier display ("ALB", "CloudFront", etc.) */
  attachedResourceKinds: string[];
  report: PostureReport;
}

export interface FleetPostureReport {
  overallScore: number;         // 0-100 (average of per-WebACL scores)
  overallVerdict: PostureVerdict;
  webAclCount: number;
  /** Count of WAF-attachable resources in the topology that have no WebACL. */
  unprotectedResourceCount: number;
  /** Per-WebACL breakdown. */
  perWebAcl: FleetWebACLEntry[];
  /** Findings that apply across the fleet (not specific to one WebACL). */
  fleetFindings: PostureFinding[];
  /** Consolidated findings from individual WebACLs, deduped by title. */
  consolidatedFindings: PostureFinding[];
  summary: string;
}

/**
 * Fleet-level attachment data so the scorer can reason about topology-level
 * properties like coverage gaps. The caller is responsible for passing the
 * topology data in; the scorer doesn't care about node shapes, just the
 * mapping from WebACL → attached resources.
 */
export interface FleetScopingInput {
  /** All WebACLs in the workspace. */
  webACLs: WebACL[];
  /** Per-WebACL: what resources is it attached to? */
  attachments: Map<string, Array<{ resourceId: string; resourceKind: string }>>;
  /** WAF-attachable resources across the topology (for coverage-gap detection). */
  attachableResources: Array<{ resourceId: string; resourceKind: string }>;
}

export function scoreWebACLFleet(input: FleetScopingInput): FleetPostureReport {
  const { webACLs, attachments, attachableResources } = input;

  // --- Per-WebACL entries ---
  const perWebAcl: FleetWebACLEntry[] = webACLs.map((webACL) => {
    const attached = attachments.get(webACL.id) ?? [];
    return {
      id: webACL.id,
      name: webACL.name,
      scope: webACL.scope,
      attachedResourceIds: attached.map((a) => a.resourceId),
      attachedResourceKinds: attached.map((a) => a.resourceKind),
      report: scoreWebACL(webACL),
    };
  });

  // --- Overall score: simple average. Future: weight by traffic volume. ---
  const overallScore =
    perWebAcl.length === 0
      ? 0
      : Math.round(
          perWebAcl.reduce((acc, e) => acc + e.report.totalScore, 0) /
            perWebAcl.length
        );
  const overallVerdict = verdictFor(overallScore);

  // --- Fleet-only findings ---
  const fleetFindings: PostureFinding[] = [];

  // 1. Coverage gap: attachable resources without any WebACL attached
  const protectedResourceIds = new Set<string>();
  for (const entry of perWebAcl) {
    for (const id of entry.attachedResourceIds) protectedResourceIds.add(id);
  }
  const unprotected = attachableResources.filter(
    (r) => !protectedResourceIds.has(r.resourceId)
  );
  if (unprotected.length > 0) {
    fleetFindings.push({
      category: "Coverage",
      severity: "error",
      title: `${unprotected.length} unprotected resource${unprotected.length > 1 ? "s" : ""}`,
      detail: unprotected
        .map((r) => `${r.resourceKind} ${r.resourceId}`)
        .join(", "),
      recommendation: "Attach a WebACL to each.",
    });
  }

  // 2. IP reputation / anonymous IP coverage drift
  const reputationGroups = ["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList"];
  if (perWebAcl.length > 1) {
    const withReputation = perWebAcl.filter((e) =>
      hasAnyOfTheseManagedGroups(webACLsById(webACLs, e.id), reputationGroups)
    );
    if (withReputation.length > 0 && withReputation.length < perWebAcl.length) {
      const withoutNames = perWebAcl
        .filter((e) => !withReputation.includes(e))
        .map((e) => e.name);
      fleetFindings.push({
        category: "Coverage",
        severity: "warning",
        title: `IP reputation missing on ${withoutNames.length} of ${perWebAcl.length} WebACL${perWebAcl.length > 1 ? "s" : ""}`,
        detail: withoutNames.join(", "),
        recommendation: "Add AWSManagedRulesAmazonIpReputationList.",
      });
    }
  }

  // 3. Default-action drift
  if (perWebAcl.length > 1) {
    const defaults = new Map<string, string[]>();
    for (const e of perWebAcl) {
      const waf = webACLsById(webACLs, e.id);
      if (!waf) continue;
      const arr = defaults.get(waf.defaultAction) ?? [];
      arr.push(e.name);
      defaults.set(waf.defaultAction, arr);
    }
    if (defaults.size > 1) {
      const summary = [...defaults.entries()]
        .map(([action, names]) => `${action}: ${names.join(", ")}`)
        .join("  |  ");
      fleetFindings.push({
        category: "Hygiene",
        severity: "warning",
        title: "Default action differs across WebACLs",
        detail: summary,
        recommendation: "Align unless intentional.",
      });
    }
  }

  // 4. Managed rule group override drift
  if (perWebAcl.length > 1) {
    const groupOverrides = new Map<string, Map<string, string[]>>();
    for (const e of perWebAcl) {
      const waf = webACLsById(webACLs, e.id);
      if (!waf) continue;
      for (const rule of waf.rules) {
        if (rule.statement.type !== "ManagedRuleGroupStatement") continue;
        const stmt = rule.statement as { name?: string };
        const groupName = stmt.name ?? "(unknown)";
        const mode = rule.overrideAction ?? "NONE";
        if (!groupOverrides.has(groupName)) groupOverrides.set(groupName, new Map());
        const modeMap = groupOverrides.get(groupName)!;
        const arr = modeMap.get(mode) ?? [];
        arr.push(e.name);
        modeMap.set(mode, arr);
      }
    }
    for (const [groupName, modeMap] of groupOverrides.entries()) {
      if (modeMap.size > 1) {
        const modeSummary = [...modeMap.entries()]
          .map(([mode, names]) => `${mode}: ${names.join(", ")}`)
          .join("  |  ");
        // Short group name for display
        const shortGroup = groupName.replace(/^AWSManagedRules/, "");
        fleetFindings.push({
          category: "Defense",
          severity: "info",
          title: `${shortGroup} override mode differs`,
          detail: modeSummary,
          recommendation: "Usually means a rollout is mid-flight.",
        });
      }
    }
  }

  // 5. Rate-based rules entirely absent from fleet (new in rc.9.1)
  const fleetHasAnyRateRule = perWebAcl.some((e) => {
    const waf = webACLsById(webACLs, e.id);
    if (!waf) return false;
    return waf.rules.some((r) => r.statement.type === "RateBasedStatement");
  });
  if (!fleetHasAnyRateRule && perWebAcl.length > 0) {
    fleetFindings.push({
      category: "RateLimiting",
      severity: "warning",
      title: "No rate-based rules anywhere in the fleet",
      detail: "Volumetric attacks (credential stuffing, scraping) will not be rate-limited.",
      recommendation: "Add at least one rate-based rule per internet-facing WebACL.",
    });
  }

  // --- Consolidate per-WebACL findings (dedup by title, keep highest severity) ---
  const consolidatedMap = new Map<string, PostureFinding>();
  for (const entry of perWebAcl) {
    for (const f of entry.report.findings) {
      const existing = consolidatedMap.get(f.title);
      if (!existing) {
        consolidatedMap.set(f.title, f);
      } else {
        const severityRank = { error: 0, warning: 1, info: 2 } as const;
        if (severityRank[f.severity] < severityRank[existing.severity]) {
          consolidatedMap.set(f.title, f);
        }
      }
    }
  }
  const severityOrder: Record<FindingSeverity, number> = { error: 0, warning: 1, info: 2 };
  const consolidatedFindings = [...consolidatedMap.values()].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  // --- Summary ---
  const summaryParts: string[] = [
    `Fleet posture: ${overallVerdict} (${overallScore}/100) across ${perWebAcl.length} WebACL${perWebAcl.length === 1 ? "" : "s"}.`,
  ];
  if (unprotected.length > 0) {
    summaryParts.push(`${unprotected.length} unprotected resource${unprotected.length === 1 ? "" : "s"}.`);
  }
  if (fleetFindings.filter((f) => f.severity === "error").length > 0) {
    summaryParts.push("Fix fleet-level errors first.");
  }

  return {
    overallScore,
    overallVerdict,
    webAclCount: perWebAcl.length,
    unprotectedResourceCount: unprotected.length,
    perWebAcl,
    fleetFindings,
    consolidatedFindings,
    summary: summaryParts.join(" "),
  };
}

function webACLsById(webACLs: WebACL[], id: string): WebACL | undefined {
  return webACLs.find((w) => w.id === id);
}

function hasAnyOfTheseManagedGroups(webACL: WebACL | undefined, groupNames: string[]): boolean {
  if (!webACL) return false;
  for (const rule of webACL.rules) {
    if (rule.statement.type !== "ManagedRuleGroupStatement") continue;
    const stmt = rule.statement as { name?: string };
    if (stmt.name && groupNames.includes(stmt.name)) return true;
  }
  return false;
}
