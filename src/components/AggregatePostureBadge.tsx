"use client";

// WAFSim v3 rc.9.1 — Aggregate fleet posture (redesign).
//
// Apurva rc.9 feedback: "overall security score panel was bull and really
// bad, no actionable info, not clear just AI blubby mess and not
// re-retrievable, either make it valuable or don't include it be ruthless".
//
// This rewrite leads with metrics, kills every paragraph in favor of
// one-line findings, and makes each finding point at a specific WAF name
// the user can act on. No recommendations that say 'align unless
// intentional' or similar AI padding.

import React from "react";
import { Shield, AlertCircle, AlertTriangle, Info, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { useWAFSimStore } from "@/store/wafsimStore";
import { scoreWebACLFleet, type FleetPostureReport, type FleetScopingInput } from "@/engines/postureScorer";

const WAF_ATTACHABLE_KINDS = new Set([
  "CloudFront",
  "ALB",
  "APIGateway",
  "AppSync",
  "CognitoUserPool",
  "AppRunner",
  "VerifiedAccess",
]);

function verdictTone(score: number): { text: string; border: string; bg: string } {
  if (score >= 95) return { text: "text-emerald-400", border: "border-emerald-500/40", bg: "bg-emerald-500/10" };
  if (score >= 80) return { text: "text-green-400", border: "border-green-500/40", bg: "bg-green-500/10" };
  if (score >= 60) return { text: "text-yellow-400", border: "border-yellow-500/40", bg: "bg-yellow-500/10" };
  if (score >= 40) return { text: "text-orange-400", border: "border-orange-500/40", bg: "bg-orange-500/10" };
  if (score >= 20) return { text: "text-red-400", border: "border-red-500/40", bg: "bg-red-500/10" };
  return { text: "text-gray-400", border: "border-gray-600", bg: "bg-gray-800/50" };
}

function computeFleetInput(
  wafs: ReturnType<typeof useWAFSimStore.getState>["wafs"],
  nodes: ReturnType<typeof useWAFSimStore.getState>["nodes"],
  edges: ReturnType<typeof useWAFSimStore.getState>["edges"]
): FleetScopingInput {
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

  const attachableResources = nodes
    .filter((n) => n.type !== "WAF" && WAF_ATTACHABLE_KINDS.has(n.type))
    .map((n) => ({ resourceId: n.id, resourceKind: n.type }));

  return { webACLs: wafs, attachments, attachableResources };
}

export function AggregatePostureBadge({ className = "" }: { className?: string }) {
  const { wafs, nodes, edges, selectWAF } = useWAFSimStore();

  if (wafs.length === 0) return null;

  const report: FleetPostureReport = scoreWebACLFleet(computeFleetInput(wafs, nodes, edges));
  const tone = verdictTone(report.overallScore);

  const errorCount = report.fleetFindings.filter((f) => f.severity === "error").length;
  const warningCount = report.fleetFindings.filter((f) => f.severity === "warning").length;
  const infoCount = report.fleetFindings.filter((f) => f.severity === "info").length;

  // Total resources attachable vs protected
  const totalAttachable = wafs.length > 0
    ? [...nodes].filter((n) => n.type !== "WAF" && WAF_ATTACHABLE_KINDS.has(n.type)).length
    : 0;
  const protectedCount = totalAttachable - report.unprotectedResourceCount;

  return (
    <div className={cn("space-y-2", className)}>
      {/* Big score + 3-metric row */}
      <div className={cn("p-3 rounded-lg border", tone.bg, tone.border)}>
        <div className="flex items-baseline justify-between">
          <div className="flex items-center gap-2">
            <Shield className={cn("w-4 h-4", tone.text)} />
            <span className="text-[10px] uppercase tracking-wider text-gray-400">
              Fleet posture
            </span>
          </div>
          <div className="flex items-baseline gap-1">
            <span className={cn("text-3xl font-bold leading-none", tone.text)}>
              {report.overallScore}
            </span>
            <span className="text-[10px] text-gray-500">/100</span>
          </div>
        </div>
        <div className="mt-1">
          <span className={cn("text-xs font-medium", tone.text)}>
            {report.overallVerdict}
          </span>
        </div>

        {/* Three-up metric bar */}
        <div className="mt-3 grid grid-cols-3 gap-2 text-[10px]">
          <div className="border-r border-gray-700 pr-2">
            <div className="text-gray-500 uppercase tracking-wider">WebACLs</div>
            <div className="text-gray-100 font-mono mt-0.5">{report.webAclCount}</div>
          </div>
          <div className="border-r border-gray-700 pr-2">
            <div className="text-gray-500 uppercase tracking-wider">Coverage</div>
            <div className={cn(
              "font-mono mt-0.5",
              report.unprotectedResourceCount === 0 ? "text-green-400" : "text-red-400"
            )}>
              {protectedCount}/{totalAttachable}
            </div>
          </div>
          <div>
            <div className="text-gray-500 uppercase tracking-wider">Findings</div>
            <div className="font-mono mt-0.5 flex gap-1.5">
              {errorCount > 0 && <span className="text-red-400">{errorCount}E</span>}
              {warningCount > 0 && <span className="text-yellow-400">{warningCount}W</span>}
              {infoCount > 0 && <span className="text-blue-400">{infoCount}i</span>}
              {errorCount + warningCount + infoCount === 0 && <span className="text-green-400">0</span>}
            </div>
          </div>
        </div>
      </div>

      {/* Fleet findings — one line each, leading icon, terse */}
      {report.fleetFindings.length > 0 && (
        <div className="space-y-1">
          {report.fleetFindings.map((f, i) => {
            const Icon =
              f.severity === "error" ? AlertCircle :
              f.severity === "warning" ? AlertTriangle : Info;
            const toneClass =
              f.severity === "error" ? "text-red-400" :
              f.severity === "warning" ? "text-yellow-400" : "text-blue-400";
            return (
              <div key={i} className="px-2 py-1.5 rounded border border-gray-800 bg-gray-900/50 text-[10px]">
                <div className="flex items-start gap-1.5">
                  <Icon className={cn("w-3 h-3 mt-0.5 shrink-0", toneClass)} />
                  <div className="min-w-0 flex-1">
                    <div className="font-medium text-gray-200">{f.title}</div>
                    <div className="text-gray-400 font-mono mt-0.5 break-words">
                      {f.detail}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Per-WebACL list — each is clickable to drill in */}
      <div>
        <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
          Per WebACL
        </div>
        <div className="space-y-0.5">
          {report.perWebAcl
            .slice()
            .sort((a, b) => a.report.totalScore - b.report.totalScore)
            .map((entry) => {
              const etone = verdictTone(entry.report.totalScore);
              const findingCount = entry.report.findings.filter((f) => f.severity !== "info").length;
              return (
                <button
                  key={entry.id}
                  onClick={() => selectWAF(entry.id)}
                  className="w-full px-2 py-1.5 rounded border border-gray-800 bg-gray-900/50 hover:bg-gray-800/70 transition-colors text-left group"
                  title={`Click to open ${entry.name}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="text-[11px] font-medium text-gray-200 truncate">
                        {entry.name}
                      </div>
                      <div className="text-[9px] text-gray-500 truncate font-mono">
                        {entry.scope}
                        {entry.attachedResourceKinds.length > 0
                          ? ` · ${entry.attachedResourceKinds.join(", ")}`
                          : " · unattached"}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {findingCount > 0 && (
                        <span className="text-[9px] text-yellow-500">
                          {findingCount} issue{findingCount === 1 ? "" : "s"}
                        </span>
                      )}
                      <span className={cn("text-sm font-bold font-mono", etone.text)}>
                        {entry.report.totalScore}
                      </span>
                      <ChevronRight className="w-3 h-3 text-gray-600 group-hover:text-gray-400 transition-colors" />
                    </div>
                  </div>
                </button>
              );
            })}
        </div>
      </div>
    </div>
  );
}
