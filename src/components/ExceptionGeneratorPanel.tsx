"use client";

// WAFSim v3 rc.9.1 — False-positive exception generator UI.
//
// Ships the engine that was created in rc.8 as a usable tool. User flow:
//   1. Paste a WAF log (sampled request JSON or full Kinesis log)
//   2. Pick a strategy (label-match / managed-group-exclusion / custom-allow)
//   3. Pick a scope (EXACT / SAME_PATH / SAME_ENDPOINT)
//   4. See the generated Rule JSON + caveats
//   5. Click "Simulate" to verify the original blocked request is now allowed
//   6. Click "Insert into WebACL" to patch the current WAF config
//
// Principles:
// - Never suggest something without a clear caveat (security tradeoff shown inline)
// - Simulate before insert — if the generated rule doesn't ALLOW the original
//   request, we say so instead of silently inserting a broken rule
// - Show the rule as valid AWS WAFv2 JSON so the user can copy it out for
//   CloudFormation / Terraform / console

import React, { useState, useMemo } from "react";
import { AlertTriangle, CheckCircle2, Code, Play, Plus, FileJson } from "lucide-react";
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

export function ExceptionGeneratorPanel() {
  const { wafs, selectedWAFId, addRuleToWAF, updateWAF } = useWAFSimStore();

  const [rawLog, setRawLog] = useState("");
  const [strategy, setStrategy] = useState<ExceptionStrategy>("LABEL_MATCH_EXCEPTION");
  const [scope, setScope] = useState<ExceptionScope>("SAME_PATH");
  const [targetWafId, setTargetWafId] = useState<string | null>(null);
  const [simResult, setSimResult] = useState<{ before: string; after: string } | null>(null);

  const effectiveWafId = targetWafId ?? selectedWAFId ?? (wafs.length > 0 ? wafs[0].id : null);
  const targetWAF = wafs.find((w) => w.id === effectiveWafId) ?? null;

  // Parse log on every change
  const parseResult = useMemo(() => {
    if (!rawLog.trim()) return { ok: false as const, log: null, error: null };
    return parseWafLog(rawLog);
  }, [rawLog]);

  const parsedLog: ParsedWafLog | null = parseResult.ok ? parseResult.log : null;

  // Generate exception whenever inputs change
  const genResult = useMemo(() => {
    if (!parsedLog || !targetWAF) return null;
    return generateException({
      log: parsedLog,
      webACL: targetWAF,
      strategy,
      scope,
    });
  }, [parsedLog, targetWAF, strategy, scope]);

  const generated: GeneratedException | null =
    genResult?.ok && genResult.exception ? genResult.exception : null;

  const verifyExceptionWorks = () => {
    if (!parsedLog || !targetWAF || !generated?.rule) return;

    // BEFORE: evaluate the original request against the current WAF — expect BLOCK
    const before = evaluateWebACL(parsedLog.request, targetWAF);

    // AFTER: evaluate against a modified copy of the WAF with the exception inserted
    const patched: WebACL = {
      ...targetWAF,
      rules: [...targetWAF.rules, generated.rule],
    };
    const after = evaluateWebACL(parsedLog.request, patched);

    setSimResult({ before: before.finalAction, after: after.finalAction });
  };

  const insertIntoWebACL = () => {
    if (!targetWAF || !generated?.rule) return;

    if (generated.rule) {
      // Direct rule — append to the WebACL with a unique priority
      const existingPriorities = new Set(targetWAF.rules.map((r) => r.priority));
      let priority = generated.suggestedPriority;
      while (existingPriorities.has(priority)) priority++;
      const toInsert: Rule = { ...generated.rule, priority };
      addRuleToWAF(targetWAF.id, toInsert);
    } else if (generated.excludedRulesUpdate) {
      // Managed-group exclusion — modify the existing rule
      const updatedRules = targetWAF.rules.map((r) => {
        if (
          r.statement.type === "ManagedRuleGroupStatement" &&
          (r.statement as { name?: string }).name ===
            generated.excludedRulesUpdate!.targetRuleName.split(":").pop()
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
    }
  };

  return (
    <div className="h-full flex flex-col text-white text-xs overflow-hidden">
      <div className="grid grid-cols-2 gap-3 p-3 overflow-auto flex-1 min-h-0">
        {/* LEFT COLUMN: input */}
        <div className="space-y-3 min-w-0">
          <div>
            <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
              WAF Log (Sampled Request or Kinesis format)
            </Label>
            <Textarea
              value={rawLog}
              onChange={(e) => setRawLog(e.target.value)}
              placeholder="Paste a WAF log JSON — from GetSampledRequests API, Kinesis Firehose, or S3 delivery"
              className="bg-gray-800 border-gray-700 font-mono text-[10px] h-64 mt-1"
            />
            <div className="flex justify-between items-center mt-1">
              <button
                onClick={() => setRawLog(SAMPLE_LOG)}
                className="text-[10px] text-blue-400 hover:text-blue-300 underline"
              >
                Load sample log
              </button>
              {rawLog.trim() && !parseResult.ok && (
                <span className="text-[10px] text-red-400">
                  {parseResult.error ?? "Invalid log format"}
                </span>
              )}
              {parsedLog && (
                <span className="text-[10px] text-green-400">
                  Parsed: {parsedLog.action} by {parsedLog.terminatingRuleId ?? "unknown rule"}
                </span>
              )}
            </div>
          </div>

          {parsedLog && (
            <div className="space-y-1.5 rounded border border-gray-700 bg-gray-900 p-2">
              <div className="text-[10px] text-gray-400">
                <span className="text-gray-500">Path:</span>{" "}
                <span className="font-mono text-gray-200">{parsedLog.request.uri}</span>
              </div>
              <div className="text-[10px] text-gray-400">
                <span className="text-gray-500">Method:</span>{" "}
                <span className="font-mono text-gray-200">{parsedLog.request.method}</span>
              </div>
              <div className="text-[10px] text-gray-400">
                <span className="text-gray-500">Source IP:</span>{" "}
                <span className="font-mono text-gray-200">{parsedLog.request.sourceIP}</span>
              </div>
              {parsedLog.labels.length > 0 && (
                <div className="text-[10px] text-gray-400">
                  <span className="text-gray-500">Labels:</span>{" "}
                  <span className="font-mono text-gray-200">{parsedLog.labels.join(", ")}</span>
                </div>
              )}
            </div>
          )}

          <div className="grid grid-cols-3 gap-2">
            <div>
              <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                Target WebACL
              </Label>
              <Select value={effectiveWafId ?? ""} onValueChange={setTargetWafId}>
                <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs">
                  <SelectValue placeholder="Pick a WAF" />
                </SelectTrigger>
                <SelectContent>
                  {wafs.map((w) => (
                    <SelectItem key={w.id} value={w.id}>
                      {w.name} ({w.scope})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                Strategy
              </Label>
              <Select value={strategy} onValueChange={(v) => setStrategy(v as ExceptionStrategy)}>
                <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="LABEL_MATCH_EXCEPTION">
                    Label-match (preferred)
                  </SelectItem>
                  <SelectItem value="MANAGED_GROUP_EXCLUSION">
                    Managed group exclude
                  </SelectItem>
                  <SelectItem value="CUSTOM_ALLOW_BYPASS">
                    Custom allow bypass
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-[10px] text-gray-500 uppercase tracking-wider">
                Scope
              </Label>
              <Select value={scope} onValueChange={(v) => setScope(v as ExceptionScope)}>
                <SelectTrigger className="bg-gray-800 border-gray-700 h-7 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="EXACT">
                    Exact (this URI + query)
                  </SelectItem>
                  <SelectItem value="SAME_PATH">
                    Same path (any query)
                  </SelectItem>
                  <SelectItem value="SAME_ENDPOINT">
                    Endpoint prefix (first 2 segments)
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="flex gap-2">
            <Button
              onClick={verifyExceptionWorks}
              disabled={!generated}
              size="sm"
              variant="outline"
              className="h-7 text-xs border-blue-600 text-blue-400 hover:bg-blue-900/20"
            >
              <Play className="w-3 h-3 mr-1" />
              Simulate
            </Button>
            <Button
              onClick={insertIntoWebACL}
              disabled={!generated || (simResult && simResult.after !== "ALLOW")}
              size="sm"
              className="h-7 text-xs bg-green-600 hover:bg-green-700"
            >
              <Plus className="w-3 h-3 mr-1" />
              Insert into WebACL
            </Button>
          </div>

          {simResult && (
            <div
              className={cn(
                "rounded border p-2 text-[10px]",
                simResult.after === "ALLOW"
                  ? "bg-green-500/10 border-green-500/30"
                  : "bg-red-500/10 border-red-500/30"
              )}
            >
              <div className="flex items-center gap-1.5 mb-1">
                {simResult.after === "ALLOW" ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                ) : (
                  <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                )}
                <span className="font-semibold">Simulation</span>
              </div>
              <div className="text-gray-300">
                Before: <span className="font-mono">{simResult.before}</span> →
                After: <span className="font-mono">{simResult.after}</span>
              </div>
              {simResult.after !== "ALLOW" && (
                <div className="text-red-300 mt-1 italic">
                  Exception did not let the blocked request through. This usually
                  means the scope is too narrow or another rule is still
                  blocking. Try a broader scope or a different strategy.
                </div>
              )}
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: generated rule preview */}
        <div className="space-y-2 min-w-0">
          {!parsedLog && (
            <div className="rounded border border-gray-800 bg-gray-900 p-4 text-[11px] text-gray-500 h-full flex flex-col items-center justify-center gap-2">
              <FileJson className="w-8 h-8 opacity-40" />
              <p>Paste a WAF log on the left to generate an exception</p>
              <p className="text-[10px]">
                Both console Sampled Request format and production Kinesis logs are supported
              </p>
            </div>
          )}

          {parsedLog && genResult && !genResult.ok && (
            <div className="rounded border border-yellow-500/30 bg-yellow-500/5 p-3 text-[11px]">
              <AlertTriangle className="w-4 h-4 text-yellow-400 inline mr-1" />
              {genResult.error}
            </div>
          )}

          {generated && (
            <>
              <div className="flex items-center gap-2">
                <Code className="w-3.5 h-3.5 text-blue-400" />
                <span className="text-[11px] font-semibold">Generated exception</span>
                <Badge className="text-[9px] py-0 bg-blue-600">{strategy}</Badge>
                <Badge variant="outline" className="text-[9px] py-0">
                  priority {generated.suggestedPriority}
                </Badge>
              </div>

              <div className="rounded border border-blue-500/30 bg-blue-500/5 p-2 text-[10px]">
                <div className="text-gray-300 leading-relaxed">{generated.explanation}</div>
              </div>

              {generated.caveats.length > 0 && (
                <div className="rounded border border-yellow-500/30 bg-yellow-500/5 p-2">
                  <div className="text-[10px] text-yellow-400 uppercase tracking-wider mb-1 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    Caveats ({generated.caveats.length})
                  </div>
                  <ul className="space-y-1 text-[10px]">
                    {generated.caveats.map((c, i) => (
                      <li
                        key={i}
                        className={cn(
                          "pl-2 border-l-2",
                          c.severity === "CRITICAL"
                            ? "border-red-500 text-red-300"
                            : c.severity === "HIGH"
                            ? "border-orange-500 text-orange-300"
                            : c.severity === "MEDIUM"
                            ? "border-yellow-500 text-yellow-300"
                            : "border-gray-500 text-gray-400"
                        )}
                      >
                        <span className="text-[9px] uppercase font-bold">{c.severity}</span>
                        {" — "}
                        {c.text}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {generated.rule && (
                <div className="rounded border border-gray-700 bg-gray-950 p-2">
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
                    AWS WAFv2 Rule JSON
                  </div>
                  <pre className="text-[10px] font-mono text-gray-300 overflow-auto max-h-72">
{JSON.stringify(generated.rule, null, 2)}
                  </pre>
                </div>
              )}

              {generated.excludedRulesUpdate && (
                <div className="rounded border border-gray-700 bg-gray-950 p-2">
                  <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
                    Managed Rule Group Update
                  </div>
                  <div className="text-[10px] font-mono text-gray-300">
                    Target group:{" "}
                    <span className="text-blue-300">
                      {generated.excludedRulesUpdate.targetRuleName}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-gray-300 mt-1">
                    Excluded rules:
                  </div>
                  <pre className="text-[10px] font-mono text-gray-400 ml-2">
{JSON.stringify(generated.excludedRulesUpdate.excludedRules, null, 2)}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
