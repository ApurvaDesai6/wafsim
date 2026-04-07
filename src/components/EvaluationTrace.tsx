"use client";

import React, { useState } from "react";
import { EvaluationResult, RuleTrace } from "@/lib/types";
import {
  Check,
  X,
  ChevronDown,
  ChevronRight,
  Shield,
  AlertTriangle,
  Clock,
  Tag,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

interface EvaluationTraceProps {
  result: EvaluationResult;
}

export const EvaluationTrace: React.FC<EvaluationTraceProps> = ({ result }) => {
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set());

  const toggleRule = (ruleName: string) => {
    const newExpanded = new Set(expandedRules);
    if (newExpanded.has(ruleName)) {
      newExpanded.delete(ruleName);
    } else {
      newExpanded.add(ruleName);
    }
    setExpandedRules(newExpanded);
  };

  const getActionIcon = (action: string) => {
    switch (action) {
      case "BLOCK":
        return <X className="w-4 h-4 text-red-400" />;
      case "ALLOW":
        return <Check className="w-4 h-4 text-green-400" />;
      case "COUNT":
        return <Clock className="w-4 h-4 text-yellow-400" />;
      case "CAPTCHA":
        return <Shield className="w-4 h-4 text-purple-400" />;
      case "CHALLENGE":
        return <Shield className="w-4 h-4 text-blue-400" />;
      default:
        return null;
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case "BLOCK":
        return "border-red-500 bg-red-500/10";
      case "ALLOW":
        return "border-green-500 bg-green-500/10";
      case "COUNT":
        return "border-yellow-500 bg-yellow-500/10";
      case "CAPTCHA":
        return "border-purple-500 bg-purple-500/10";
      case "CHALLENGE":
        return "border-blue-500 bg-blue-500/10";
      default:
        return "border-gray-500 bg-gray-500/10";
    }
  };

  // Calculate stats
  const matchedCount = result.ruleTrace.filter((r) => r.matched).length;
  const labelsCount = result.labelsApplied.length;

  return (
    <div className="h-full flex flex-col bg-gray-900 text-white text-xs">
      {/* Header */}
      <div className="px-3 py-2 border-b border-gray-700 shrink-0">
        {/* Final Result Banner */}
        <div
          className={cn(
            "p-2 rounded-lg border flex items-center justify-between",
            getActionColor(result.finalAction)
          )}
        >
          <div className="flex items-center gap-2">
            {getActionIcon(result.finalAction)}
            <span className="font-bold text-sm">{result.finalAction}</span>
            {result.terminatingRule && (
              <span className="text-[11px] text-gray-400">by {result.terminatingRule.rule.name}</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-[11px]">
            <span>{result.ruleTrace.length} evaluated</span>
            <span className="text-yellow-400">{matchedCount} matched</span>
            <span className="text-blue-400">{labelsCount} labels</span>
          </div>
        </div>

        {/* Approximation Warning */}
        {result.approximatedManagedRules && (
          <div className="mt-1.5 px-2 py-1 bg-yellow-500/10 border border-yellow-500/30 rounded flex items-center gap-1.5 text-[10px]">
            <AlertTriangle className="w-3 h-3 text-yellow-400 flex-shrink-0" />
            <span className="text-yellow-400">Managed rule behavior is approximated</span>
          </div>
        )}
      </div>

      {/* Rules Timeline */}
      <ScrollArea className="flex-1">
        <div className="p-2 space-y-1">
          {result.ruleTrace.map((trace, index) => {
            // v2.25: Calculate label propagation context
            const labelsAvailableBefore = result.ruleTrace
              .slice(0, index)
              .flatMap(t => t.labelsAdded);
            const consumedLabels = trace.reason?.includes("Label match:") 
              ? labelsAvailableBefore.filter(l => trace.reason.includes(l))
              : [];

            return (
            <Card
              key={trace.ruleName}
              className={cn(
                "bg-gray-800 border cursor-pointer transition-all",
                trace.matched ? "border-gray-600" : "border-gray-700",
                trace.terminates && "border-2"
              )}
              onClick={() => toggleRule(trace.ruleName)}
            >
              <CardHeader className="px-2.5 py-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      {trace.priority}
                    </Badge>
                    <span className="font-medium">{trace.ruleName}</span>
                    {trace.labelsAdded.length > 0 && (
                      <span className="text-[10px] text-blue-400">+{trace.labelsAdded.length} label{trace.labelsAdded.length > 1 ? "s" : ""}</span>
                    )}
                    {consumedLabels.length > 0 && (
                      <span className="text-[10px] text-purple-400">⟵ uses label</span>
                    )}
                    {expandedRules.has(trace.ruleName) ? (
                      <ChevronDown className="w-4 h-4 text-gray-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {trace.matched ? (
                      <Badge className="bg-green-500 text-white">
                        <Check className="w-3 h-3 mr-1" />
                        Matched
                      </Badge>
                    ) : (
                      <Badge variant="secondary" className="text-gray-400">
                        No Match
                      </Badge>
                    )}
                    {trace.terminates && (
                      <Badge className="bg-red-500 text-white">Terminated</Badge>
                    )}
                  </div>
                </div>
              </CardHeader>

              {expandedRules.has(trace.ruleName) && (
                <CardContent className="px-2.5 pb-2 pt-0 space-y-2">
                  {/* Label Propagation Context */}
                  {labelsAvailableBefore.length > 0 && (
                    <div>
                      <span className="text-sm text-gray-400">Labels available at this rule:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {labelsAvailableBefore.map((label) => (
                          <Badge key={label} variant="outline" className={cn("text-xs", consumedLabels.includes(label) ? "text-purple-400 border-purple-400" : "text-gray-500")}>
                            <Tag className="w-3 h-3 mr-1" />
                            {label}
                            {consumedLabels.includes(label) && " ✓"}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {/* Action */}
                  {trace.matched && trace.action !== "no-action" && (
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-gray-400">Action:</span>
                      <Badge
                        className={cn(
                          trace.action === "BLOCK" && "bg-red-500",
                          trace.action === "ALLOW" && "bg-green-500",
                          trace.action === "COUNT" && "bg-yellow-500"
                        )}
                      >
                        {trace.action}
                      </Badge>
                    </div>
                  )}

                  {/* Reason */}
                  <div className="text-sm bg-gray-700 p-2 rounded">
                    <span className="text-gray-400">Reason: </span>
                    {trace.reason}
                  </div>

                  {/* Labels Added */}
                  {trace.labelsAdded.length > 0 && (
                    <div>
                      <span className="text-sm text-gray-400">Labels Added:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {trace.labelsAdded.map((label) => (
                          <Badge key={label} variant="outline" className="text-xs text-blue-400">
                            <Tag className="w-3 h-3 mr-1" />
                            {label}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Matched Content & Transformation Chain */}
                  {trace.matchedContent && (
                    <div>
                      <span className="text-sm text-gray-400">Matched Content:</span>
                      <div className="mt-1 p-2 bg-gray-700 rounded font-mono text-xs overflow-x-auto">
                        {trace.matchedContent.substring(0, 200)}
                        {trace.matchedContent.length > 200 && "..."}
                      </div>
                    </div>
                  )}

                  {trace.transformedContent && trace.transformedContent !== trace.matchedContent && (
                    <div className="space-y-1">
                      <span className="text-sm text-gray-400">Transformation Chain:</span>
                      <div className="flex items-center gap-2 text-xs">
                        <div className="p-1.5 bg-gray-700 rounded font-mono overflow-x-auto max-w-[45%] truncate" title={trace.matchedContent || ""}>
                          {(trace.matchedContent || "").substring(0, 80)}
                        </div>
                        <span className="text-gray-500 shrink-0">→</span>
                        <div className="p-1.5 bg-green-900/30 border border-green-500/20 rounded font-mono overflow-x-auto max-w-[45%] truncate" title={trace.transformedContent}>
                          {trace.transformedContent.substring(0, 80)}
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              )}
            </Card>
          );
          })}
        </div>
      </ScrollArea>

      {/* Labels Applied */}
      {result.labelsApplied.length > 0 && (
        <div className="px-2.5 py-1.5 border-t border-gray-700 shrink-0">
          <div className="flex flex-wrap gap-1">
            <span className="text-[10px] text-gray-500 mr-1">Labels:</span>
            {result.labelsApplied.map((label) => (
              <Badge key={label} variant="outline" className="text-[9px] px-1 py-0">
                {label}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default EvaluationTrace;
