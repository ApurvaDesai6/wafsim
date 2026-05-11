"use client";

// WAFSim v3 rc.9.2 — False-positive exception generator, wizard edition.
//
// Replaces the rc.9.1 form-dump layout with a 5-step progressive wizard:
//
//   1. Paste & parse the log
//   2. Review what was blocked (visual summary, not raw JSON)
//   3. Pick strategy + scope (with automatic recommendations and
//      prerequisite checks for the WAF the user is targeting)
//   4. Preview the generated exception (visual rule card + caveats,
//      raw JSON behind an Advanced disclosure)
//   5. Verify via simulation (original request + canned attack variant,
//      both evaluated before/after) and apply
//
// Principles for this rewrite, per Apurva's feedback that the first
// version was "very bad" and needed 4-5 reworks:
//   - Wizard-style with clear ordering; can't skip steps.
//   - Visual summaries over raw JSON (JSON available on demand).
//   - Automatic intelligence: recommend strategy, detect missing
//     prerequisites (e.g. LABEL_MATCH needs labeler rule in COUNT mode).
//   - Verification runs the original blocked request AND an attack
//     variant, so the user sees "legit request now allowed, attack
//     still blocked" as a single answer, not two separate buttons.
//   - Copy-for-CloudFormation for IaC users.
//   - Undo snapshot after insert (stored in panel state; one click
//     to revert).

import React, { useState, useMemo, useEffect } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Code,
  Play,
  Plus,
  FileJson,
  ArrowRight,
  ArrowLeft,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Undo2,
  ChevronDown,
  ChevronRight,
  Target,
  Zap,
  History,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useWAFSimStore } from "@/store/wafsimStore";
import { parseWafLog, type ParsedWafLog } from "@/lib/wafLogParser";
import {
  generateException,
  type ExceptionStrategy,
  type ExceptionScope,
  type GeneratedException,
} from "@/engines/exceptionGenerator";
import { evaluateWebACL } from "@/engines/wafEngine";
import type { WebACL, Rule } from "@/lib/types";
import { toast } from "sonner";
import { exportException, type ExceptionExportFormat } from "@/lib/exceptionExporters";
import { MANAGED_RULE_GROUPS } from "@/lib/managedRuleGroups";

// ---------- Sample log used by the "Load sample" affordance ----------

const SAMPLE_LOG = `{
  "timestamp": 1730000000000,
  "formatVersion": 1,
  "webaclId": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/abc",
  "terminatingRuleId": "GenericRFI_URIPATH",
  "terminatingRuleType": "MANAGED_RULE_GROUP",
  "action": "BLOCK",
  "httpRequest": {
    "clientIp": "203.0.113.42",
    "country": "US",
    "uri": "/api/v1/import",
    "args": "source=https://example.com/legit-source",
    "httpVersion": "HTTP/1.1",
    "httpMethod": "POST",
    "headers": [
      {"name": "User-Agent", "value": "Mozilla/5.0"},
      {"name": "Content-Type", "value": "application/json"}
    ]
  },
  "ruleGroupList": [{
    "ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet",
    "terminatingRule": {
      "ruleId": "GenericRFI_URIPATH",
      "action": "BLOCK"
    }
  }],
  "labels": [
    {"name": "awswaf:managed:aws:core-rule-set:GenericRFI_URIPATH"}
  ]
}`;

// ---------- Strategy metadata ----------

const STRATEGY_META: Record<ExceptionStrategy, {
  label: string;
  description: string;
  recommendedWhen: string;
  tradeoff: string;
}> = {
  LABEL_MATCH_EXCEPTION: {
    label: "Label match",
    description: "Allow requests labeled by the blocking rule AND matching a specific signature.",
    recommendedWhen: "The blocking rule comes from a managed group that emits labels.",
    tradeoff: "The labeling rule must be in COUNT mode, otherwise it blocks before the label match can consume it.",
  },
  MANAGED_GROUP_EXCLUSION: {
    label: "Exclude sub-rule",
    description: "Add the offending sub-rule to the managed group's ExcludedRules list (COUNT-only).",
    recommendedWhen: "A single managed sub-rule is clearly over-firing and you can't scope it down.",
    tradeoff: "Disables that sub-rule globally across all requests, not just the false positive pattern. Less surgical.",
  },
  CUSTOM_ALLOW_BYPASS: {
    label: "Custom allow bypass",
    description: "Prepend an explicit high-priority ALLOW rule scoped to URI pattern + (optional) IP allowlist.",
    recommendedWhen: "No labels available, or you need a quick win for a specific internal tool.",
    tradeoff: "Bypasses ALL downstream rules — highest risk. Always pair with IP allowlist.",
  },
  SCOPE_DOWN_STATEMENT: {
    label: "Scope-down statement",
    description: "Edit the managed rule's scope-down to skip the rule when the request matches your legit pattern.",
    recommendedWhen: "You want the simplest possible change — no new rule, just an edit to the existing managed rule.",
    tradeoff: "Applies to the entire managed group, not a specific sub-rule. Less surgical than LABEL_MATCH_EXCEPTION.",
  },
};

const SCOPE_META: Record<ExceptionScope, { label: string; description: string; risk: string }> = {
  EXACT: {
    label: "Exact URI + query",
    description: "Allow only this precise URL, including the exact query string.",
    risk: "Narrowest. Safest. Fragile if the query varies.",
  },
  SAME_PATH: {
    label: "Same path, any query",
    description: "Allow any request to this URL path regardless of query string.",
    risk: "Balanced. Recommended for most cases.",
  },
  SAME_ENDPOINT: {
    label: "Endpoint prefix",
    description: "Allow any request starting with the first two URL segments (e.g. /api/v1/*).",
    risk: "Broadest. Use only if you fully control the endpoint.",
  },
};

// ---------- Intelligence: recommend a strategy for a given log ----------

function recommendStrategy(log: ParsedWafLog): ExceptionStrategy {
  // If the terminating rule was in a managed group and emitted a label,
  // the label-match exception is the AWS-recommended pattern (per AWS WAF label-match pattern).
  if (log.labels.length > 0 && log.terminatingRuleGroupName) {
    return "LABEL_MATCH_EXCEPTION";
  }
  // If managed group but no label, exclude the sub-rule.
  if (log.terminatingRuleGroupName) {
    return "MANAGED_GROUP_EXCLUSION";
  }
  // No managed group — custom bypass is the only option.
  return "CUSTOM_ALLOW_BYPASS";
}

function recommendScope(log: ParsedWafLog): ExceptionScope {
  // If URI has a query string, EXACT is too fragile; recommend SAME_PATH.
  // If path has 3+ segments, SAME_ENDPOINT is probably too broad.
  return "SAME_PATH";
}

// ---------- Prerequisite detection ----------

interface Prerequisite {
  met: boolean;
  message: string;
  fix?: string;
  /**
   * rc.9.5 — optional auto-fix descriptor. When present, the UI offers a
   * one-click button to apply the remediation. Currently supports:
   *   - type: 'SET_MANAGED_GROUP_COUNT'
   *     Sets the overrideAction of the managed rule to COUNT so labels
   *     propagate without blocking.
   */
  autoFix?: {
    type: "SET_MANAGED_GROUP_COUNT";
    targetRuleName: string;
    buttonLabel: string;
  };
}

function checkPrerequisites(
  log: ParsedWafLog,
  webACL: WebACL,
  strategy: ExceptionStrategy
): Prerequisite[] {
  const out: Prerequisite[] = [];

  if (strategy === "LABEL_MATCH_EXCEPTION") {
    // Is the labeling rule (the managed group that emitted the label) in the WebACL at all?
    const shortGroupName = log.terminatingRuleGroupName?.split("#").pop() ?? "";
    const labelerRule = webACL.rules.find((r) => {
      if (r.statement.type !== "ManagedRuleGroupStatement") return false;
      const name = (r.statement as { name?: string }).name ?? "";
      return name === shortGroupName;
    });

    if (!labelerRule) {
      out.push({
        met: false,
        message: `Managed group "${shortGroupName}" is not attached to this WebACL.`,
        fix: "Attach it first, or switch to Custom allow bypass.",
      });
      return out;
    }

    // Is it in COUNT mode (override action)? If in BLOCK mode the label-match
    // exception can never run because the managed rule already terminated.
    const isCount = labelerRule.overrideAction === "COUNT" ||
      (labelerRule.statement as { ruleActionOverrides?: unknown }).ruleActionOverrides !== undefined;
    if (!isCount) {
      out.push({
        met: false,
        message: `"${shortGroupName}" is not in COUNT mode, so it blocks before the label-match exception can fire.`,
        fix: "Override the group to COUNT so labels propagate to this rule.",
        autoFix: {
          type: "SET_MANAGED_GROUP_COUNT",
          targetRuleName: labelerRule.name,
          buttonLabel: `Set ${shortGroupName} to COUNT`,
        },
      });
    } else {
      out.push({
        met: true,
        message: `"${shortGroupName}" is in COUNT mode — label will propagate to the exception rule.`,
      });
    }
  }

  if (strategy === "CUSTOM_ALLOW_BYPASS") {
    out.push({
      met: false,
      message: "Custom allow bypass skips ALL downstream rules including other attack checks.",
      fix: "Add an IP allowlist in Advanced to reduce blast radius.",
    });
  }

  if (strategy === "MANAGED_GROUP_EXCLUSION") {
    out.push({
      met: true,
      message: "This will set the offending sub-rule to COUNT globally. Other sub-rules in the group keep blocking.",
    });
  }

  return out;
}

// ---------- Attack variant generator for verification ----------

function makeAttackVariant(log: ParsedWafLog): { uri: string; reason: string } {
  const ruleId = log.terminatingRuleId ?? "";
  const path = log.request.uri.split("?")[0];

  if (ruleId.toUpperCase().includes("SQLI")) {
    return { uri: `${path}?id=1' OR '1'='1`, reason: "SQLi attempt at the same path" };
  }
  if (ruleId.toUpperCase().includes("XSS") || ruleId.toUpperCase().includes("CROSSSITE")) {
    return { uri: `${path}?q=<script>alert(1)</script>`, reason: "XSS attempt at the same path" };
  }
  if (ruleId.toUpperCase().includes("RFI") || ruleId.toUpperCase().includes("LFI")) {
    return { uri: `${path}?path=../../etc/passwd`, reason: "Path traversal at the same path" };
  }
  // Generic: try a SQLi attempt which the CommonRuleSet will catch for most apps.
  return { uri: `${path}?id=' UNION SELECT NULL--`, reason: "Generic attack probe at the same path" };
}

// ---------- Step wrapper ----------

type StepId = 1 | 2 | 3 | 4 | 5;
const STEP_LABELS: Record<StepId, string> = {
  1: "Paste log",
  2: "Review",
  3: "Configure",
  4: "Preview",
  5: "Verify & apply",
};

function StepIndicator({ current, max }: { current: StepId; max: StepId }) {
  return (
    <div className="flex items-center gap-1 px-3 py-2 border-b border-gray-800 text-[11px]">
      {([1, 2, 3, 4, 5] as StepId[]).map((n) => {
        const reached = n <= max;
        const isCurrent = n === current;
        return (
          <React.Fragment key={n}>
            <div
              className={cn(
                "flex items-center gap-1.5 px-2 py-1 rounded transition-colors",
                isCurrent && "bg-blue-500/20 text-blue-300",
                !isCurrent && reached && "text-gray-400",
                !reached && "text-gray-600"
              )}
            >
              <span
                className={cn(
                  "w-4 h-4 rounded-full flex items-center justify-center text-[10px] font-bold",
                  isCurrent && "bg-blue-500 text-white",
                  !isCurrent && reached && "bg-gray-700 text-gray-300",
                  !reached && "bg-gray-800 text-gray-600"
                )}
              >
                {n}
              </span>
              <span className="font-medium">{STEP_LABELS[n]}</span>
            </div>
            {n < 5 && <ChevronRight className="w-3 h-3 text-gray-700" />}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ---------- Main component ----------

export function ExceptionGeneratorPanel() {
  const { wafs, selectedWAFId, addRuleToWAF, updateWAF, exceptionHistory, addExceptionHistory, removeExceptionHistory } = useWAFSimStore();

  const [step, setStep] = useState<StepId>(1);
  const [furthestStep, setFurthestStep] = useState<StepId>(1);
  const [rawLog, setRawLog] = useState("");
  const [strategy, setStrategy] = useState<ExceptionStrategy>("LABEL_MATCH_EXCEPTION");
  const [scope, setScope] = useState<ExceptionScope>("SAME_PATH");
  const [targetWafId, setTargetWafId] = useState<string | null>(null);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [insertedSnapshot, setInsertedSnapshot] = useState<WebACL | null>(null);
  // rc.9.3 additions
  const [showHistory, setShowHistory] = useState(false);
  const [exportFormat, setExportFormat] = useState<ExceptionExportFormat>("json");

  const effectiveWafId = targetWafId ?? selectedWAFId ?? (wafs.length > 0 ? wafs[0].id : null);
  const targetWAF = wafs.find((w) => w.id === effectiveWafId) ?? null;

  const parseResult = useMemo(() => {
    if (!rawLog.trim()) return { ok: false as const, log: null, error: null };
    return parseWafLog(rawLog);
  }, [rawLog]);

  const parsedLog: ParsedWafLog | null = parseResult.ok ? (parseResult.log ?? null) : null;

  // Auto-recommend strategy + scope when a valid log is parsed
  useEffect(() => {
    if (parsedLog) {
      setStrategy(recommendStrategy(parsedLog));
      setScope(recommendScope(parsedLog));
    }
  }, [parsedLog]);

  const prereqs = useMemo(() => {
    if (!parsedLog || !targetWAF) return [];
    return checkPrerequisites(parsedLog, targetWAF, strategy);
  }, [parsedLog, targetWAF, strategy]);

  const genResult = useMemo(() => {
    if (!parsedLog || !targetWAF) return null;
    return generateException({ log: parsedLog, webACL: targetWAF, strategy, scope });
  }, [parsedLog, targetWAF, strategy, scope]);

  const generated: GeneratedException | null =
    genResult?.ok && genResult.exception ? genResult.exception : null;

  // Verification: original request + attack variant, before+after
  const verification = useMemo(() => {
    if (!parsedLog || !targetWAF || !generated?.rule) return null;

    const patchedWAF: WebACL = {
      ...targetWAF,
      rules: [...targetWAF.rules, generated.rule],
    };
    const originalBefore = evaluateWebACL(parsedLog.request, targetWAF);
    const originalAfter = evaluateWebACL(parsedLog.request, patchedWAF);

    const variant = makeAttackVariant(parsedLog);
    const attackRequest = {
      ...parsedLog.request,
      uri: variant.uri,
      queryParams: {},
    };
    const attackBefore = evaluateWebACL(attackRequest, targetWAF);
    const attackAfter = evaluateWebACL(attackRequest, patchedWAF);

    const originalNowAllowed = originalAfter.finalAction === "ALLOW";
    const attackStillBlocked = attackAfter.finalAction === "BLOCK";
    const allPassed = originalNowAllowed && attackStillBlocked;

    return {
      variant,
      originalBefore: originalBefore.finalAction,
      originalAfter: originalAfter.finalAction,
      attackBefore: attackBefore.finalAction,
      attackAfter: attackAfter.finalAction,
      originalNowAllowed,
      attackStillBlocked,
      allPassed,
    };
  }, [parsedLog, targetWAF, generated]);

  // Step gating: which steps are reachable
  const canAdvanceTo = (s: StepId): boolean => {
    if (s === 1) return true;
    if (s === 2) return !!parsedLog;
    if (s === 3) return !!parsedLog && !!targetWAF;
    if (s === 4) return !!generated;
    if (s === 5) return !!verification;
    return false;
  };

  const gotoStep = (s: StepId) => {
    if (!canAdvanceTo(s)) return;
    setStep(s);
    if (s > furthestStep) setFurthestStep(s);
  };

  const handleInsert = () => {
    if (!targetWAF || !generated) return;
    // Snapshot for undo
    setInsertedSnapshot(targetWAF);

    if (generated.rule) {
      const existingPriorities = new Set(targetWAF.rules.map((r) => r.priority));
      let priority = generated.suggestedPriority;
      while (existingPriorities.has(priority)) priority++;
      addRuleToWAF(targetWAF.id, { ...generated.rule, priority });
    } else if (generated.excludedRulesUpdate) {
      const shortGroupName = generated.excludedRulesUpdate.targetRuleName.split("#").pop() ?? "";
      const updatedRules = targetWAF.rules.map((r) => {
        if (
          r.statement.type === "ManagedRuleGroupStatement" &&
          (r.statement as { name?: string }).name === shortGroupName
        ) {
          return {
            ...r,
            statement: {
              ...r.statement,
              excludedRules: generated.excludedRulesUpdate!.excludedRules,
            } as typeof r.statement,
          };
        }
        return r;
      });
      updateWAF(targetWAF.id, { rules: updatedRules });
    } else if (generated.scopeDownUpdate) {
      // rc.9.5: scope-down statement strategy — patch the managed rule's
      // scope-down field in place.
      const updatedRules = targetWAF.rules.map((r) => {
        if (r.name === generated.scopeDownUpdate!.targetRuleName) {
          return {
            ...r,
            statement: {
              ...r.statement,
              scopeDownStatement: generated.scopeDownUpdate!.scopeDownStatement,
            } as typeof r.statement,
          };
        }
        return r;
      });
      updateWAF(targetWAF.id, { rules: updatedRules });
    }

    toast.success(`Exception rule inserted into "${targetWAF.name}"`, {
      description: "Ran verification before insert. Click the WAF to inspect.",
    });

    // rc.9.3: log to history
    if (parsedLog && generated.rule) {
      addExceptionHistory({
        wafId: targetWAF.id,
        wafName: targetWAF.name,
        strategy,
        scope,
        triggerUri: parsedLog.request.uri,
        triggerMethod: parsedLog.request.method,
        terminatingRuleId: parsedLog.terminatingRuleId ?? null,
        ruleJson: JSON.stringify(generated.rule),
        inserted: true,
        verificationPassed: verification?.allPassed ?? null,
      });
    }
  };

  const handleUndo = () => {
    if (!insertedSnapshot) return;
    updateWAF(insertedSnapshot.id, { rules: insertedSnapshot.rules });
    setInsertedSnapshot(null);
    toast.success("Reverted exception insert");
  };

  const handleCopyJson = () => {
    if (!generated?.rule) return;
    const json = JSON.stringify(generated.rule, null, 2);
    navigator.clipboard?.writeText(json);
    toast.success("Rule JSON copied");
  };

  // ---------- Render ----------

  if (wafs.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-gray-500">
        Add a WebACL to the topology before generating exceptions.
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col text-white text-xs overflow-hidden">
      <div className="flex items-center border-b border-gray-800">
        <div className="flex-1"><StepIndicator current={step} max={furthestStep} /></div>
        <button
          onClick={() => setShowHistory(!showHistory)}
          className={cn(
            "px-3 py-2 text-[11px] flex items-center gap-1.5 border-l border-gray-800 transition-colors",
            showHistory ? "bg-gray-800 text-gray-100" : "text-gray-400 hover:text-gray-200"
          )}
        >
          <History className="w-3 h-3" />
          History
          {exceptionHistory.length > 0 && (
            <Badge variant="outline" className="text-[9px] px-1 py-0 ml-0.5">
              {exceptionHistory.length}
            </Badge>
          )}
        </button>
      </div>

      {showHistory && (
        <div className="flex-1 overflow-auto p-4">
          <div className="max-w-3xl mx-auto space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold text-gray-200">Exception history</div>
                <div className="text-[11px] text-gray-500">
                  {exceptionHistory.length} past exception
                  {exceptionHistory.length === 1 ? "" : "s"} generated in this workspace
                </div>
              </div>
              <Button
                onClick={() => setShowHistory(false)}
                size="sm"
                variant="outline"
                className="h-7 text-xs"
              >
                Close
              </Button>
            </div>
            {exceptionHistory.length === 0 ? (
              <div className="rounded border border-gray-800 bg-gray-900/50 p-6 text-center text-[11px] text-gray-500">
                No history yet. Generate an exception via the wizard and it will appear here.
              </div>
            ) : (
              <div className="space-y-1.5">
                {exceptionHistory.map((rec) => (
                  <div
                    key={rec.id}
                    className="rounded border border-gray-800 bg-gray-900/50 p-2.5 flex items-start gap-3"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge
                          className={cn(
                            "text-[9px] py-0",
                            rec.inserted ? "bg-green-700" : "bg-gray-700"
                          )}
                        >
                          {rec.inserted ? "applied" : "drafted"}
                        </Badge>
                        <span className="text-[11px] font-medium text-gray-200">
                          {STRATEGY_META[rec.strategy].label}
                        </span>
                        <span className="text-[10px] text-gray-500">
                          · {SCOPE_META[rec.scope].label}
                        </span>
                        <span className="text-[10px] text-gray-500 ml-auto">
                          {new Date(rec.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div className="text-[10px] text-gray-400 font-mono mt-1 truncate">
                        {rec.triggerMethod} {rec.triggerUri}
                      </div>
                      <div className="text-[10px] text-gray-500 mt-0.5">
                        Blocked by{" "}
                        <span className="text-gray-400 font-mono">
                          {rec.terminatingRuleId ?? "(unknown rule)"}
                        </span>
                        {" · "}
                        Target: <span className="text-gray-400">{rec.wafName}</span>
                        {rec.verificationPassed !== null && (
                          <>
                            {" · "}
                            {rec.verificationPassed ? (
                              <span className="text-green-400">verified ✓</span>
                            ) : (
                              <span className="text-red-400">verification failed</span>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                    <button
                      onClick={() => {
                        const json = rec.ruleJson;
                        navigator.clipboard?.writeText(json);
                        toast.success("Rule JSON copied");
                      }}
                      className="text-[10px] text-blue-400 hover:text-blue-300 shrink-0"
                      title="Copy rule JSON"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                    <button
                      onClick={() => removeExceptionHistory(rec.id)}
                      className="text-[10px] text-red-400 hover:text-red-300 shrink-0"
                      title="Remove from history"
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {!showHistory && (<>
      <div className="flex-1 overflow-auto p-4">
        {/* ---------- STEP 1: paste log ---------- */}
        {step === 1 && (
          <div className="max-w-3xl mx-auto space-y-3">
            <div>
              <div className="text-sm font-semibold text-gray-200 mb-1">
                Paste a WAF log for a blocked request you want to allow
              </div>
              <div className="text-[11px] text-gray-500">
                Supported formats: sampled request JSON from the WAF console, full
                Kinesis Firehose log, or S3 log delivery. The parser detects automatically.
              </div>
            </div>

            <Textarea
              value={rawLog}
              onChange={(e) => setRawLog(e.target.value)}
              placeholder='Paste the full JSON of the WAF log here — or click "Load sample" below to try with a realistic example'
              className="bg-gray-900 border-gray-700 font-mono text-[10px] h-80"
            />

            <div className="flex items-center justify-between">
              <button
                onClick={() => setRawLog(SAMPLE_LOG)}
                className="text-[11px] text-blue-400 hover:text-blue-300 underline"
              >
                Load sample log (SSRF false positive)
              </button>
              {parseResult.error && rawLog.trim() && (
                <span className="text-[11px] text-red-400">
                  {parseResult.error}
                </span>
              )}
              {parsedLog && (
                <Button
                  onClick={() => gotoStep(2)}
                  size="sm"
                  className="h-8 bg-blue-600 hover:bg-blue-700 text-xs"
                >
                  Continue <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              )}
            </div>
          </div>
        )}

        {/* ---------- STEP 2: review ---------- */}
        {step === 2 && parsedLog && (
          <div className="max-w-3xl mx-auto space-y-3">
            <div className="flex items-start gap-3 p-4 rounded-lg border border-red-500/30 bg-red-500/5">
              <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-red-300">
                  {parsedLog.action}{" "}
                  <span className="text-gray-400 font-normal">by</span>{" "}
                  <span className="text-red-300">{parsedLog.terminatingRuleId ?? "unknown rule"}</span>
                </div>
                {parsedLog.terminatingRuleGroupName && (
                  <div className="text-[11px] text-gray-400 mt-0.5 font-mono">
                    in {parsedLog.terminatingRuleGroupName}
                  </div>
                )}
                {/* rc.9.5: rule context from managed rule groups catalog */}
                {(() => {
                  const shortGroupName = parsedLog.terminatingRuleGroupName?.split("#").pop() ?? "";
                  const groupInfo = MANAGED_RULE_GROUPS[shortGroupName];
                  const subRuleInfo = groupInfo?.rules?.find(
                    (r) => r.name === parsedLog.terminatingRuleId
                  );
                  if (!subRuleInfo) return null;
                  const docsUrl = `https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html`;
                  return (
                    <div className="mt-2 text-[11px] text-gray-300 leading-relaxed">
                      <span className="text-gray-500">What this rule does: </span>
                      {subRuleInfo.description}
                      {" · "}
                      <a
                        href={docsUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue-400 hover:text-blue-300 underline"
                      >
                        AWS docs
                      </a>
                    </div>
                  );
                })()}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Field label="Request">
                <div className="font-mono text-gray-200">
                  {parsedLog.request.method} {parsedLog.request.uri}
                </div>
              </Field>
              <Field label="From">
                <div className="font-mono text-gray-200">
                  {parsedLog.request.sourceIP} ({parsedLog.request.country})
                </div>
              </Field>
              {parsedLog.labels.length > 0 && (
                <Field label="Labels applied" className="col-span-2">
                  <div className="flex flex-wrap gap-1">
                    {parsedLog.labels.map((l) => (
                      <Badge key={l} variant="outline" className="font-mono text-[10px]">
                        {l}
                      </Badge>
                    ))}
                  </div>
                </Field>
              )}
              {parsedLog.matchReason && (
                <Field label="Match reason" className="col-span-2">
                  <div className="font-mono text-gray-400">{parsedLog.matchReason}</div>
                </Field>
              )}
            </div>

            <div className="flex items-center justify-between pt-2">
              <Button onClick={() => gotoStep(1)} size="sm" variant="outline" className="h-8 text-xs">
                <ArrowLeft className="w-3 h-3 mr-1" /> Back
              </Button>
              <Button
                onClick={() => gotoStep(3)}
                size="sm"
                className="h-8 bg-blue-600 hover:bg-blue-700 text-xs"
              >
                Configure exception <ArrowRight className="w-3 h-3 ml-1" />
              </Button>
            </div>
          </div>
        )}

        {/* ---------- STEP 3: configure ---------- */}
        {step === 3 && parsedLog && (
          <div className="max-w-3xl mx-auto space-y-3">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-blue-400" />
              <span className="text-[11px] text-blue-400">
                Recommended based on this log: {STRATEGY_META[recommendStrategy(parsedLog)].label} · {SCOPE_META[recommendScope(parsedLog)].label}
              </span>
            </div>

            {/* Target WebACL */}
            <div>
              <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                Target WebACL
              </Label>
              <Select value={effectiveWafId ?? ""} onValueChange={setTargetWafId}>
                <SelectTrigger className="bg-gray-900 border-gray-700 h-8 text-xs">
                  <SelectValue placeholder="Pick a WAF" />
                </SelectTrigger>
                <SelectContent>
                  {wafs.map((w) => (
                    <SelectItem key={w.id} value={w.id}>
                      {w.name} ({w.scope}) · {w.rules.length} rule{w.rules.length === 1 ? "" : "s"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Strategy picker */}
            <div>
              <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                Strategy
              </Label>
              <div className="grid grid-cols-1 gap-2 mt-1">
                {(Object.keys(STRATEGY_META) as ExceptionStrategy[]).map((s) => {
                  const meta = STRATEGY_META[s];
                  const isRecommended = s === recommendStrategy(parsedLog);
                  const isSelected = strategy === s;
                  return (
                    <button
                      key={s}
                      onClick={() => setStrategy(s)}
                      className={cn(
                        "text-left p-2.5 rounded-lg border transition-colors",
                        isSelected
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-gray-700 hover:border-gray-600 bg-gray-900/50"
                      )}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-[12px] font-medium text-gray-200">{meta.label}</span>
                        {isRecommended && (
                          <Badge className="bg-blue-600 text-[9px] py-0 px-1.5">
                            Recommended
                          </Badge>
                        )}
                      </div>
                      <div className="text-[11px] text-gray-400 mt-1">{meta.description}</div>
                      <div className="text-[10px] text-yellow-500 mt-1">
                        <span className="font-semibold">Tradeoff:</span> {meta.tradeoff}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Scope picker */}
            <div>
              <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                Scope
              </Label>
              <div className="grid grid-cols-3 gap-2 mt-1">
                {(Object.keys(SCOPE_META) as ExceptionScope[]).map((sc) => {
                  const meta = SCOPE_META[sc];
                  const isSelected = scope === sc;
                  return (
                    <button
                      key={sc}
                      onClick={() => setScope(sc)}
                      className={cn(
                        "text-left p-2 rounded border transition-colors",
                        isSelected
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-gray-700 hover:border-gray-600 bg-gray-900/50"
                      )}
                    >
                      <div className="text-[11px] font-medium text-gray-200">{meta.label}</div>
                      <div className="text-[10px] text-gray-400 mt-0.5">{meta.description}</div>
                      <div className="text-[9px] text-yellow-500 mt-1">{meta.risk}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Prerequisite checks */}
            {prereqs.length > 0 && (
              <div className="space-y-1.5">
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                  Prerequisite checks
                </Label>
                {prereqs.map((p, i) => (
                  <div
                    key={i}
                    className={cn(
                      "p-2 rounded border flex items-start gap-2 text-[11px]",
                      p.met
                        ? "border-green-500/30 bg-green-500/5"
                        : "border-yellow-500/30 bg-yellow-500/5"
                    )}
                  >
                    {p.met ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0 mt-0.5" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <div className="text-gray-200">{p.message}</div>
                      {p.fix && (
                        <div className="text-gray-400 mt-0.5 italic">{p.fix}</div>
                      )}
                      {p.autoFix && targetWAF && !p.met && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-6 text-[10px] mt-2 border-yellow-500 bg-yellow-500/10 text-yellow-200 hover:bg-yellow-500/20"
                          onClick={() => {
                            if (p.autoFix!.type === "SET_MANAGED_GROUP_COUNT") {
                              const updatedRules = targetWAF.rules.map((r) => {
                                if (r.name === p.autoFix!.targetRuleName) {
                                  return { ...r, overrideAction: "COUNT" as const };
                                }
                                return r;
                              });
                              updateWAF(targetWAF.id, { rules: updatedRules });
                              toast.success(`Set ${p.autoFix!.targetRuleName} to COUNT mode`);
                            }
                          }}
                        >
                          <Zap className="w-3 h-3 mr-1" />
                          {p.autoFix.buttonLabel}
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              <Button onClick={() => gotoStep(2)} size="sm" variant="outline" className="h-8 text-xs">
                <ArrowLeft className="w-3 h-3 mr-1" /> Back
              </Button>
              <Button
                onClick={() => gotoStep(4)}
                disabled={!generated}
                size="sm"
                className="h-8 bg-blue-600 hover:bg-blue-700 text-xs"
              >
                Preview rule <ArrowRight className="w-3 h-3 ml-1" />
              </Button>
            </div>
          </div>
        )}

        {/* ---------- STEP 4: preview ---------- */}
        {step === 4 && generated && (
          <div className="max-w-3xl mx-auto space-y-3">
            {/* Visual rule card */}
            <div className="rounded-lg border border-blue-500/40 bg-blue-500/5 p-3">
              <div className="flex items-center gap-2 mb-2">
                <Code className="w-4 h-4 text-blue-400" />
                <span className="text-sm font-semibold">Generated rule</span>
                <Badge className="text-[9px] py-0 bg-blue-600">{STRATEGY_META[strategy].label}</Badge>
                <Badge variant="outline" className="text-[9px] py-0">
                  priority {generated.suggestedPriority}
                </Badge>
                {generated.rule && (
                  <Badge
                    className={cn(
                      "text-[9px] py-0",
                      generated.rule.action === "ALLOW" && "bg-green-600",
                      generated.rule.action === "BLOCK" && "bg-red-600"
                    )}
                  >
                    {generated.rule.action}
                  </Badge>
                )}
              </div>
              <div className="text-[11px] text-gray-300 leading-relaxed">
                {generated.explanation}
              </div>
            </div>

            {/* Caveats as severity-colored chips */}
            {generated.caveats.length > 0 && (
              <div>
                <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                  Caveats
                </Label>
                <div className="space-y-1.5 mt-1">
                  {generated.caveats.map((c, i) => (
                    <div
                      key={i}
                      className={cn(
                        "p-2 rounded border flex items-start gap-2 text-[11px]",
                        c.severity === "CRITICAL" && "border-red-500/40 bg-red-500/5",
                        c.severity === "HIGH" && "border-orange-500/40 bg-orange-500/5",
                        c.severity === "MEDIUM" && "border-yellow-500/40 bg-yellow-500/5",
                        c.severity === "LOW" && "border-gray-700 bg-gray-900/50"
                      )}
                    >
                      <Badge
                        className={cn(
                          "text-[9px] py-0 shrink-0",
                          c.severity === "CRITICAL" && "bg-red-600",
                          c.severity === "HIGH" && "bg-orange-600",
                          c.severity === "MEDIUM" && "bg-yellow-600",
                          c.severity === "LOW" && "bg-gray-600"
                        )}
                      >
                        {c.severity}
                      </Badge>
                      <span className="text-gray-200 flex-1">{c.text}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Advanced: multi-format export */}
            <div>
              <button
                onClick={() => setAdvancedOpen(!advancedOpen)}
                className="flex items-center gap-1.5 text-[11px] text-gray-400 hover:text-gray-200"
              >
                {advancedOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                Export — AWS JSON, CloudFormation, Terraform, CLI
              </button>
              {advancedOpen && generated.rule && (
                <div className="mt-2 rounded border border-gray-700 bg-gray-950 overflow-hidden">
                  {/* Format tabs */}
                  <div className="flex items-center border-b border-gray-800 text-[10px]">
                    {(["json", "cloudformation", "terraform", "cli"] as const).map((f) => (
                      <button
                        key={f}
                        onClick={() => setExportFormat(f)}
                        className={cn(
                          "px-3 py-1.5 font-medium transition-colors",
                          exportFormat === f
                            ? "text-blue-300 border-b-2 border-blue-500 bg-blue-500/5"
                            : "text-gray-500 hover:text-gray-300"
                        )}
                      >
                        {f === "json" && "AWS JSON"}
                        {f === "cloudformation" && "CloudFormation"}
                        {f === "terraform" && "Terraform"}
                        {f === "cli" && "AWS CLI"}
                      </button>
                    ))}
                    <button
                      onClick={() => {
                        const text = exportException(
                          generated.rule!,
                          exportFormat,
                          targetWAF?.name,
                          targetWAF?.scope
                        );
                        navigator.clipboard?.writeText(text);
                        toast.success(`Copied ${exportFormat.toUpperCase()}`);
                      }}
                      className="ml-auto px-3 py-1.5 text-[10px] text-blue-400 hover:text-blue-300 flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  </div>
                  {/* Format body */}
                  <pre className="text-[10px] font-mono text-gray-300 overflow-auto max-h-72 p-3">
{exportException(generated.rule, exportFormat, targetWAF?.name, targetWAF?.scope)}
                  </pre>
                </div>
              )}
              {advancedOpen && generated.excludedRulesUpdate && !generated.rule && (
                <div className="mt-2 rounded border border-gray-700 bg-gray-950 p-2">
                  <div className="text-[10px] text-gray-500 mb-1">
                    Update to managed group: {generated.excludedRulesUpdate.targetRuleName}
                  </div>
                  <pre className="text-[10px] font-mono text-gray-300">
{JSON.stringify(generated.excludedRulesUpdate.excludedRules, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-2">
              <Button onClick={() => gotoStep(3)} size="sm" variant="outline" className="h-8 text-xs">
                <ArrowLeft className="w-3 h-3 mr-1" /> Back
              </Button>
              <Button
                onClick={() => gotoStep(5)}
                disabled={!verification}
                size="sm"
                className="h-8 bg-blue-600 hover:bg-blue-700 text-xs"
              >
                Verify & apply <ArrowRight className="w-3 h-3 ml-1" />
              </Button>
            </div>
          </div>
        )}

        {/* ---------- STEP 5: verify & apply ---------- */}
        {step === 5 && verification && targetWAF && generated && (
          <div className="max-w-3xl mx-auto space-y-3">
            <div
              className={cn(
                "p-3 rounded-lg border",
                verification.allPassed
                  ? "border-green-500/40 bg-green-500/5"
                  : "border-red-500/40 bg-red-500/5"
              )}
            >
              <div className="flex items-center gap-2 mb-2">
                {verification.allPassed ? (
                  <ShieldCheck className="w-5 h-5 text-green-400" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                )}
                <span className="text-sm font-semibold">
                  {verification.allPassed
                    ? "Verification passed — safe to apply"
                    : "Verification failed — review before applying"}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <VerifyCell
                  label="Original request"
                  detail={`${parsedLog!.request.method} ${parsedLog!.request.uri}`}
                  before={verification.originalBefore}
                  after={verification.originalAfter}
                  desired="ALLOW"
                  pass={verification.originalNowAllowed}
                />
                <VerifyCell
                  label={`Attack variant — ${verification.variant.reason}`}
                  detail={verification.variant.uri}
                  before={verification.attackBefore}
                  after={verification.attackAfter}
                  desired="BLOCK"
                  pass={verification.attackStillBlocked}
                />
              </div>

              {!verification.allPassed && (
                <div className="mt-3 p-2 rounded bg-gray-900/50 border border-gray-700 text-[11px] text-gray-300">
                  {!verification.originalNowAllowed && (
                    <div>
                      The exception did not let the original request through.
                      Try a broader <span className="text-yellow-400">scope</span> (e.g. SAME_PATH →
                      SAME_ENDPOINT) or a different strategy.
                    </div>
                  )}
                  {!verification.attackStillBlocked && (
                    <div>
                      The exception also let an attack variant through. The scope is too broad
                      — try narrowing it (e.g. SAME_ENDPOINT → SAME_PATH → EXACT).
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-2">
              <Button onClick={() => gotoStep(4)} size="sm" variant="outline" className="h-8 text-xs">
                <ArrowLeft className="w-3 h-3 mr-1" /> Back
              </Button>
              <div className="flex items-center gap-2">
                {insertedSnapshot && (
                  <Button
                    onClick={handleUndo}
                    size="sm"
                    variant="outline"
                    className="h-8 text-xs border-gray-600"
                  >
                    <Undo2 className="w-3 h-3 mr-1" /> Undo
                  </Button>
                )}
                <Button
                  onClick={handleInsert}
                  disabled={!verification.allPassed || !!insertedSnapshot}
                  size="sm"
                  className="h-8 bg-green-600 hover:bg-green-700 text-xs"
                >
                  <Plus className="w-3 h-3 mr-1" />
                  {insertedSnapshot ? "Applied" : `Apply to ${targetWAF.name}`}
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
      </>)}
    </div>
  );
}

// ---------- Little helpers ----------

function Field({
  label,
  children,
  className = "",
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("p-2 rounded border border-gray-700 bg-gray-900/50", className)}>
      <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">{label}</div>
      <div className="text-[11px]">{children}</div>
    </div>
  );
}

function VerifyCell({
  label,
  detail,
  before,
  after,
  desired,
  pass,
}: {
  label: string;
  detail: string;
  before: string;
  after: string;
  desired: "ALLOW" | "BLOCK";
  pass: boolean;
}) {
  const actionColor = (a: string) => {
    if (a === "ALLOW") return "text-green-400";
    if (a === "BLOCK") return "text-red-400";
    if (a === "COUNT") return "text-yellow-400";
    return "text-gray-400";
  };
  return (
    <div
      className={cn(
        "p-2 rounded border",
        pass ? "border-green-500/30 bg-green-500/5" : "border-red-500/30 bg-red-500/5"
      )}
    >
      <div className="flex items-center gap-1.5 mb-1">
        {pass ? (
          <CheckCircle2 className="w-3 h-3 text-green-400" />
        ) : (
          <AlertTriangle className="w-3 h-3 text-red-400" />
        )}
        <Target className="w-3 h-3 text-gray-500" />
        <span className="text-[10px] text-gray-300">{label}</span>
      </div>
      <div className="font-mono text-[10px] text-gray-400 truncate mb-1.5">{detail}</div>
      <div className="flex items-center gap-1.5">
        <span className={cn("font-mono text-[10px]", actionColor(before))}>{before}</span>
        <ArrowRight className="w-3 h-3 text-gray-600" />
        <span className={cn("font-mono text-[10px] font-bold", actionColor(after))}>{after}</span>
        <span className="text-[9px] text-gray-500 ml-auto">want {desired}</span>
      </div>
    </div>
  );
}
