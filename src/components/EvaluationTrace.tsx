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
    <div className="h-full flex flex-col bg-gray-900 text-white">
      {/* Header */}
      <div className="p-4 border-b border-gray-700">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Zap className="w-5 h-5 text-yellow-400" />
          Evaluation Trace
        </h2>

        {/* Final Result Banner */}
        <div
          className={cn(
            "mt-3 p-3 rounded-lg border-2 flex items-center justify-between",
            getActionColor(result.finalAction)
          )}
        >
          <div className="flex items-center gap-2">
            {getActionIcon(result.finalAction)}
            <span className="font-bold text-lg">{result.finalAction}</span>
          </div>
          {result.terminatingRule && (
            <Badge variant="outline" className="text-xs">
              by: {result.terminatingRule.rule.name}
            </Badge>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-2 mt-3">
          <div className="text-center p-2 bg-gray-800 rounded">
            <div className="text-2xl font-bold">{result.ruleTrace.length}</div>
            <div className="text-xs text-gray-400">Evaluated</div>
          </div>
          <div className="text-center p-2 bg-gray-800 rounded">
            <div className="text-2xl font-bold text-yellow-400">{matchedCount}</div>
            <div className="text-xs text-gray-400">Matched</div>
          </div>
          <div className="text-center p-2 bg-gray-800 rounded">
            <div className="text-2xl font-bold text-blue-400">{labelsCount}</div>
            <div className="text-xs text-gray-400">Labels</div>
          </div>
        </div>

        {/* Approximation Warning */}
        {result.approximatedManagedRules && (
          <div className="mt-3 p-2 bg-yellow-500/10 border border-yellow-500/30 rounded flex items-center gap-2 text-sm">
            <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0" />
            <span className="text-yellow-400">
              Managed rule behavior is approximated based on documentation
            </span>
          </div>
        )}
      </div>

      {/* Rules Timeline */}
      <ScrollArea className="flex-1">
        <div className="p-4 space-y-2">
          {result.ruleTrace.map((trace, index) => (
            <Card
              key={trace.ruleName}
              className={cn(
                "bg-gray-800 border cursor-pointer transition-all",
                trace.matched ? "border-gray-600" : "border-gray-700",
                trace.terminates && "border-2"
              )}
              onClick={() => toggleRule(trace.ruleName)}
            >
              <CardHeader className="p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      {trace.priority}
                    </Badge>
                    <span className="font-medium">{trace.ruleName}</span>
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
                <CardContent className="px-3 pb-3 pt-0 space-y-3">
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

                  {/* Matched Content */}
                  {trace.matchedContent && (
                    <div>
                      <span className="text-sm text-gray-400">Matched Content:</span>
                      <div className="mt-1 p-2 bg-gray-700 rounded font-mono text-xs overflow-x-auto">
                        {trace.matchedContent.substring(0, 200)}
                        {trace.matchedContent.length > 200 && "..."}
                      </div>
                    </div>
                  )}

                  {/* Transformed Content */}
                  {trace.transformedContent && trace.transformedContent !== trace.matchedContent && (
                    <div>
                      <span className="text-sm text-gray-400">After Transformations:</span>
                      <div className="mt-1 p-2 bg-gray-700 rounded font-mono text-xs overflow-x-auto">
                        {trace.transformedContent.substring(0, 200)}
                        {trace.transformedContent.length > 200 && "..."}
                      </div>
                    </div>
                  )}
                </CardContent>
              )}
            </Card>
          ))}
        </div>
      </ScrollArea>

      {/* Labels Applied */}
      {result.labelsApplied.length > 0 && (
        <div className="p-4 border-t border-gray-700">
          <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
            <Tag className="w-4 h-4" />
            Labels Applied
          </h3>
          <div className="flex flex-wrap gap-1">
            {result.labelsApplied.map((label) => (
              <Badge key={label} variant="outline" className="text-xs">
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
