"use client";

import React from "react";
import { Rule } from "@/lib/types";
import { calculateWebACLUWCU, checkWCULimits, MAX_WCU, WARNING_WCU } from "@/engines/wcuCalculator";
import { AlertTriangle, Zap, CheckCircle } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from "@/components/ui/tooltip";

interface WCUBudgetMeterProps {
  rules: Rule[];
  showDetails?: boolean;
}

export const WCUBudgetMeter: React.FC<WCUBudgetMeterProps> = ({ rules, showDetails = false }) => {
  const { total, byRule } = calculateWebACLUWCU(rules);
  const status = checkWCULimits(total);

  const getProgressColor = () => {
    switch (status.status) {
      case "exceeded":
        return "bg-red-500";
      case "warning":
        return "bg-yellow-500";
      default:
        return "bg-green-500";
    }
  };

  const getStatusIcon = () => {
    switch (status.status) {
      case "exceeded":
        return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case "warning":
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      default:
        return <CheckCircle className="w-4 h-4 text-green-500" />;
    }
  };

  return (
    <TooltipProvider>
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-yellow-400 shrink-0" />
            <span className="font-medium">WCU</span>
          </div>
          <div className="flex items-center gap-1.5">
            {getStatusIcon()}
            <span
              className={`font-mono text-xs ${
                status.status === "exceeded"
                  ? "text-red-400"
                  : status.status === "warning"
                  ? "text-yellow-400"
                  : "text-green-400"
              }`}
            >
              {total}/{MAX_WCU}
            </span>
          </div>
        </div>

        <Tooltip>
          <TooltipTrigger asChild>
            <div className="relative">
              <Progress
                value={Math.min(status.percentage, 100)}
                className="h-2 bg-gray-700"
              />
              {/* Warning marker */}
              <div
                className="absolute top-0 h-2 w-0.5 bg-yellow-400/50"
                style={{ left: `${(WARNING_WCU / MAX_WCU) * 100}%` }}
              />
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <div className="text-sm">
              <div className="font-semibold mb-1">WCU Usage</div>
              <div>Used: {total} WCU</div>
              <div>Remaining: {status.remaining} WCU</div>
              <div>Percentage: {status.percentage.toFixed(1)}%</div>
              {status.status === "exceeded" && (
                <div className="text-red-400 mt-1">⚠ Exceeds maximum capacity!</div>
              )}
              {status.status === "warning" && (
                <div className="text-yellow-400 mt-1">⚠ Approaching limit</div>
              )}
            </div>
          </TooltipContent>
        </Tooltip>

        {showDetails && byRule.size > 0 && (
          <div className="mt-3 text-xs">
            <div className="text-gray-400 mb-1">Breakdown by Rule:</div>
            <div className="space-y-1 max-h-32 overflow-y-auto">
              {Array.from(byRule.entries()).map(([name, cost]) => (
                <div key={name} className="flex justify-between">
                  <span className="truncate flex-1">{name}</span>
                  <span className="text-gray-500 ml-2">{cost.total} WCU</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {status.status === "exceeded" && (
          <div className="flex items-center gap-2 text-xs text-red-400 bg-red-900/20 p-2 rounded">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>WCU exceeds maximum. Remove rules or optimize transformations.</span>
          </div>
        )}
      </div>
    </TooltipProvider>
  );
};

export default WCUBudgetMeter;
