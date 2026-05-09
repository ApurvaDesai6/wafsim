"use client";

// WAFSim v3 rc.9 — Aggregate fleet posture badge.
//
// Rendered in the right panel when no specific WAF is selected. Shows
// overall fleet security posture (average of per-WebACL scores), per-WebACL
// mini-cards, and fleet-level findings (unprotected resources, IP
// reputation drift, managed-rule override drift, default-action drift).
//
// Per Apurva's 2026-05-08 feedback: "the smart security score should take
// everything into account if they have multiple webACLs and assess overall
// sec posture, that's a very useful consumer value add feature".

import React from "react";
import { Shield, AlertTriangle, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { useWAFSimStore } from "@/store/wafsimStore";
import { scoreWebACLFleet, type FleetPostureReport, type FleetScopingInput } from "@/engines/postureScorer";

// WAF-attachable node kinds in WAFSim's topology model.
const WAF_ATTACHABLE_KINDS = new Set([
  "CloudFront",
  "ALB",
  "APIGateway",
  "AppSync",
  "CognitoUserPool",
  "AppRunner",
  "VerifiedAccess",
]);

interface AggregatePostureBadgeProps {
  className?: string;
}

function verdictColor(score: number): { bg: string; border: string; text: string } {
  if (score >= 95) return { bg: "bg-emerald-500/10", border: "border-emerald-500/30", text: "text-emerald-400" };
  if (score >= 80) return { bg: "bg-green-500/10", border: "border-green-500/30", text: "text-green-400" };
  if (score >= 60) return { bg: "bg-yellow-500/10", border: "border-yellow-500/30", text: "text-yellow-400" };
  if (score >= 40) return { bg: "bg-orange-500/10", border: "border-orange-500/30", text: "text-orange-400" };
  if (score >= 20) return { bg: "bg-red-500/10", border: "border-red-500/30", text: "text-red-400" };
  return { bg: "bg-gray-700/30", border: "border-gray-600", text: "text-gray-400" };
}

function computeFleetInput(
  wafs: ReturnType<typeof useWAFSimStore.getState>["wafs"],
  nodes: ReturnType<typeof useWAFSimStore.getState>["nodes"],
  edges: ReturnType<typeof useWAFSimStore.getState>["edges"]
): FleetScopingInput {
  // Build attachments map from topology edges where source is a WAF node.
  const wafNodesById = new Map<string, { wafId?: string }>();
  for (const n of nodes) {
    if (n.type === "WAF") wafNodesById.set(n.id, { wafId: n.wafId });
  }

  const attachments = new Map<string, Array<{ resourceId: string; resourceKind: string }>>();
  for (const edge of edges) {
    const wafNode = wafNodesById.get(edge.source);
    if (!wafNode?.wafId) continue;
    const target = nodes.find((n) => n.id === edge.target);
    if (!target) continue;
    const arr = attachments.get(wafNode.wafId) ?? [];
    arr.push({ resourceId: target.id, resourceKind: target.type });
    attachments.set(wafNode.wafId, arr);
  }

  // Attachable resources = any non-WAF node of a WAF-attachable kind.
  const attachableResources = nodes
    .filter((n) => n.type !== "WAF" && WAF_ATTACHABLE_KINDS.has(n.type))
    .map((n) => ({ resourceId: n.id, resourceKind: n.type }));

  return { webACLs: wafs, attachments, attachableResources };
}

export function AggregatePostureBadge({ className = "" }: AggregatePostureBadgeProps) {
  const { wafs, nodes, edges, selectWAF } = useWAFSimStore();

  if (wafs.length === 0) {
    return null; // page.tsx has its own "no WAF configured" empty state
  }

  const report: FleetPostureReport = scoreWebACLFleet(computeFleetInput(wafs, nodes, edges));
  const colors = verdictColor(report.overallScore);
  const errorCount = report.fleetFindings.filter((f) => f.severity === "error").length;
  const warningCount = report.fleetFindings.filter((f) => f.severity === "warning").length;

  return (
    <div className={cn("space-y-2", className)}>
      {/* Overall score card */}
      <div className={cn("p-3 rounded-lg border", colors.bg, colors.border)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className={cn("w-5 h-5", colors.text)} />
            <div>
              <div className={cn("text-xs uppercase tracking-wider", colors.text)}>
                Fleet Security Posture
              </div>
              <div className="text-[10px] text-gray-500">
                {report.webAclCount} WebACL{report.webAclCount === 1 ? "" : "s"}
                {report.unprotectedResourceCount > 0
                  ? ` · ${report.unprotectedResourceCount} unprotected`
                  : ""}
              </div>
            </div>
          </div>
          <div className="text-right">
            <div className={cn("text-2xl font-bold", colors.text)}>{report.overallScore}</div>
            <div className="text-[10px] text-gray-500">/ 100</div>
          </div>
        </div>
        <div className="mt-1.5 text-[11px] text-gray-300">{report.overallVerdict}</div>
      </div>

      {/* Fleet findings */}
      {report.fleetFindings.length > 0 && (
        <div className="space-y-1">
          <div className="text-[10px] text-gray-500 uppercase tracking-wider flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" />
            Fleet-level findings
            {errorCount > 0 && <span className="text-red-400 ml-1">({errorCount} error)</span>}
            {warningCount > 0 && <span className="text-yellow-400 ml-1">({warningCount} warning)</span>}
          </div>
          {report.fleetFindings.slice(0, 4).map((f, i) => (
            <div
              key={i}
              className={cn(
                "px-2 py-1.5 rounded border text-[10px]",
                f.severity === "error" && "bg-red-500/5 border-red-500/30",
                f.severity === "warning" && "bg-yellow-500/5 border-yellow-500/30",
                f.severity === "info" && "bg-blue-500/5 border-blue-500/30"
              )}
            >
              <div className="font-medium text-gray-200">{f.title}</div>
              <div className="text-gray-400 mt-0.5">{f.detail}</div>
              {f.recommendation && (
                <div className="text-gray-500 italic mt-1 text-[9px]">{f.recommendation}</div>
              )}
            </div>
          ))}
          {report.fleetFindings.length > 4 && (
            <div className="text-[9px] text-gray-500 pl-1">
              +{report.fleetFindings.length - 4} more finding
              {report.fleetFindings.length - 4 === 1 ? "" : "s"}
            </div>
          )}
        </div>
      )}

      {/* Per-WebACL mini-cards */}
      <div className="space-y-1">
        <div className="text-[10px] text-gray-500 uppercase tracking-wider">
          Per-WebACL scores
        </div>
        {report.perWebAcl.map((entry) => {
          const ecolors = verdictColor(entry.report.totalScore);
          return (
            <button
              key={entry.id}
              onClick={() => selectWAF(entry.id)}
              className={cn(
                "w-full px-2 py-1.5 rounded border text-left flex items-center justify-between hover:opacity-80 transition-opacity",
                ecolors.bg,
                ecolors.border
              )}
              title={`Click to inspect ${entry.name}`}
            >
              <div className="min-w-0 flex-1">
                <div className="text-[11px] font-medium truncate text-gray-200">
                  {entry.name}
                </div>
                <div className="text-[9px] text-gray-500 truncate">
                  {entry.scope}
                  {entry.attachedResourceKinds.length > 0 && (
                    <> · attached to {entry.attachedResourceKinds.join(", ")}</>
                  )}
                  {entry.attachedResourceKinds.length === 0 && " · not attached"}
                </div>
              </div>
              <div className="flex items-center gap-1.5 ml-2 shrink-0">
                <span className={cn("text-sm font-bold", ecolors.text)}>
                  {entry.report.totalScore}
                </span>
                <ChevronRight className="w-3 h-3 text-gray-600" />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
