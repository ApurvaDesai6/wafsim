"use client";

import React, { useMemo, useState } from "react";
import { useWAFSimStore } from "@/store/wafsimStore";
import {
  validateTopology,
  type TopoNode,
  type TopoEdge,
  type FindingSeverity,
} from "@/engines/topologyValidator";
import { AlertCircle, AlertTriangle, Info, CheckCircle2, ChevronDown, ChevronUp } from "lucide-react";

const SEVERITY_ICONS: Record<FindingSeverity, React.ReactNode> = {
  error: <AlertCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />,
  warning: <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0 mt-0.5" />,
  info: <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />,
};

type WafScope = "CLOUDFRONT" | "REGIONAL";

/**
 * Reads the current topology + WAF configs from the store, runs the
 * topologyValidator engine, and displays any issues as a compact banner with
 * expandable findings. Silent + out-of-the-way when the topology is clean.
 */
export function TopologyIssuesBanner() {
  const nodes = useWAFSimStore((s) => s.nodes);
  const edges = useWAFSimStore((s) => s.edges);
  const wafs = useWAFSimStore((s) => s.wafs);
  const selectNode = useWAFSimStore((s) => s.selectNode);
  const [expanded, setExpanded] = useState(false);

  const report = useMemo(() => {
    // Convert WAFSim store types to topologyValidator input shape.
    // Each edge that has a wafId gets a synthetic WAF node inserted between
    // its endpoints so the validator sees WAF attachment as a node-on-edge
    // model (matches how the simulator evaluates traffic).
    const topoNodes: TopoNode[] = nodes.map((n) => ({
      id: n.id,
      kind: n.type as TopoNode["kind"],
      label: n.label,
    }));
    const topoEdges: TopoEdge[] = [];

    for (const edge of edges) {
      if (edge.wafId) {
        const waf = wafs.find((w) => w.id === edge.wafId);
        const scope: WafScope | undefined = waf?.scope as WafScope | undefined;
        topoNodes.push({
          id: `waf-${edge.wafId}`,
          kind: "WAF",
          label: waf?.name ?? "WAF",
          wafScope: scope,
        });
        topoEdges.push({ id: `${edge.id}-in`, source: edge.source, target: `waf-${edge.wafId}` });
        topoEdges.push({ id: `${edge.id}-out`, source: `waf-${edge.wafId}`, target: edge.target });
      } else {
        topoEdges.push({ id: edge.id, source: edge.source, target: edge.target });
      }
    }
    return validateTopology(topoNodes, topoEdges);
  }, [nodes, edges, wafs]);

  const issueCount = report.findings.length;
  const errorCount = report.findings.filter((f) => f.severity === "error").length;
  const warningCount = report.findings.filter((f) => f.severity === "warning").length;

  if (nodes.length === 0) return null;

  if (issueCount === 0) {
    return (
      <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-emerald-900/30 border border-emerald-800/60 text-emerald-300 text-[11px]">
        <CheckCircle2 className="w-3.5 h-3.5" />
        <span>Topology clean</span>
      </div>
    );
  }

  const bannerStyle = errorCount
    ? "bg-red-900/30 border-red-800/60 text-red-300"
    : warningCount
    ? "bg-yellow-900/30 border-yellow-800/60 text-yellow-200"
    : "bg-blue-900/30 border-blue-800/60 text-blue-200";

  return (
    <div className={`rounded-md border ${bannerStyle} text-[11px]`}>
      <button
        type="button"
        onClick={() => setExpanded((x) => !x)}
        className="w-full flex items-center gap-1.5 px-2 py-1 text-left"
        aria-expanded={expanded}
        aria-label="Toggle topology issues"
      >
        {errorCount > 0 ? (
          <AlertCircle className="w-3.5 h-3.5 text-red-400" />
        ) : warningCount > 0 ? (
          <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
        ) : (
          <Info className="w-3.5 h-3.5 text-blue-400" />
        )}
        <span className="font-medium">
          {issueCount} topology {issueCount === 1 ? "issue" : "issues"}
        </span>
        {errorCount > 0 && <span className="text-red-400">({errorCount} error)</span>}
        {warningCount > 0 && <span className="text-yellow-400">({warningCount} warning)</span>}
        <span className="ml-auto">
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </span>
      </button>
      {expanded && (
        <ul className="border-t border-white/10 px-2 py-1.5 space-y-1.5 max-h-48 overflow-auto">
          {report.findings.map((f, i) => (
            <li key={i} className="flex gap-1.5">
              {SEVERITY_ICONS[f.severity]}
              <span className="flex-1">
                <span className="font-medium text-gray-100">{f.message}</span>
                {f.recommendation && (
                  <span className="block text-gray-400 mt-0.5">{f.recommendation}</span>
                )}
                {f.nodeIds && f.nodeIds.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1">
                    {f.nodeIds
                      .filter((id) => !id.startsWith("waf-")) // synthetic WAF nodes
                      .map((id) => {
                        const node = nodes.find((n) => n.id === id);
                        if (!node) return null;
                        return (
                          <button
                            key={id}
                            onClick={(e) => {
                              e.stopPropagation();
                              selectNode(id);
                            }}
                            className="px-1.5 py-0.5 rounded bg-white/5 hover:bg-white/10 text-[10px] text-gray-200 border border-white/10"
                          >
                            {node.label ?? id}
                          </button>
                        );
                      })}
                  </div>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
